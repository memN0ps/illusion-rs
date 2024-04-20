//! This module provides functionalities for creating and managing hooks in a hypervisor environment.
//! It includes support for function hooks and page hooks, allowing manipulation and monitoring
//! of system behavior at a low level. The module is designed for use in scenarios requiring direct
//! interaction with system internals, such as in kernel and hypervisor development.
//! Credits to jessiep_ and Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/hook.rs
//!

use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            ept::{AccessType, Ept, Pt},
            hooks::inline::{InlineHook, InlineHookType},
            invept::invept_all_contexts,
            invvpid::invvpid_all_contexts,
            page::Page,
            vm::Vm,
        },
    },
    alloc::boxed::Box,
    core::intrinsics::copy_nonoverlapping,
    log::*,
    x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE},
};

/// Enum representing different types of hooks that can be applied.
#[derive(Debug, Clone, Copy)]
pub enum EptHookType {
    /// Hook for intercepting and possibly modifying function execution.
    /// Requires specifying the type of inline hook to use.
    Function(InlineHookType),

    /// Hook for hiding or monitoring access to a specific page.
    /// No inline hook type is required for page hooks.
    Page,
}

/// Manages the lifecycle and control of various hooks.
///
/// `EptHook` is a container for multiple hooks and provides an interface
/// to enable or disable these hooks as a group. It's primarily responsible for
/// modifying the Extended Page Tables (EPT) to facilitate the hooking mechanism.
pub struct EptHook {
    /// The Page Table (PT) for splitting the 2MB page into 4KB pages for the primary EPT (Pre-Allocated).
    pub primary_ept_pre_alloc_pt: Box<Pt>,

    /// Guest physical address of the function or page to be copied.
    pub guest_pa: PAddr,

    /// Guest virtual address of the function or page to be copied.
    pub guest_va: VAddr,

    /// Contents of the host shadow page where the hook is placed (Pre-Allocated).
    pub host_shadow_page: Box<Page>,

    /// Physical address of the host shadow page containing the hook.
    pub host_shadow_page_pa: PAddr,

    /// Physical address of the host shadow function containing the hook.
    pub host_shadow_function_pa: PAddr,

    /// Handler function to be called when the hook is triggered.
    pub hook_handler: *const (),

    /// The type of hook to be installed.
    pub hook_type: EptHookType,

    /// The inline hook configuration for the hook.
    pub inline_hook: Option<InlineHook>,
}

impl EptHook {
    /// Constructs a new `EptHook` with a given set of hooks.
    ///
    /// # Arguments
    ///
    /// * `host_shadow_page` - The pre-allocated host shadow page for the hook.
    /// * `primary_ept_pre_alloc_pt` - The pre-allocated Page Table (PT) for splitting the 2MB page into 4KB pages for the primary EPT.
    ///
    /// # Returns
    ///
    /// * `Box<Self>` - The new instance of `EptHook`.
    #[rustfmt::skip]
    pub fn new(host_shadow_page: Box<Page>, primary_ept_pre_alloc_pt: Box<Pt>) -> Box<Self> {
        let hooks = Self {
            primary_ept_pre_alloc_pt,
            guest_pa: PAddr::zero(),
            guest_va: VAddr::zero(),
            host_shadow_page,
            host_shadow_page_pa: PAddr::zero(),
            host_shadow_function_pa: PAddr::zero(),
            hook_handler: core::ptr::null(),
            hook_type: EptHookType::Function(InlineHookType::Int3),
            inline_hook: None,
        };
        Box::new(hooks)
    }

    /// Installs an EPT hook for a function.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine instance of the hypervisor.
    /// * guest_va - The virtual address of the function or page to be hooked.
    /// * hook_handler - The handler function to be called when the hooked function is executed.
    /// * ept_hook_type - The type of EPT hook to be installed.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    #[rustfmt::skip]
    pub fn ept_hook(vm: &mut Vm, guest_va: u64, hook_handler: *const (), ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        trace!("Creating EPT hook for function at VA: {:#x}", guest_va);

        // Ensure the index is within bounds
        if vm.hook_manager.current_hook_index >= vm.hook_manager.ept_hooks.len() {
            return Err(HypervisorError::OutOfHooks);
        }

        trace!("Accessing Hook Manager with hook index: {}", vm.hook_manager.current_hook_index);

        // Access the current hook based on `current_hook_index`
        let ept_hook = vm.hook_manager.ept_hooks.get_mut(vm.hook_manager.current_hook_index).ok_or(HypervisorError::FailedToGetCurrentHookIndex)?;

        match ept_hook_type {
            EptHookType::Function(inline_hook_type) => {
                ept_hook.hook_function(guest_va, hook_handler, inline_hook_type).ok_or(HypervisorError::HookError)?;
            }
            EptHookType::Page => {
                ept_hook.hook_page(guest_va, hook_handler, ept_hook_type).ok_or(HypervisorError::HookError)?;
            }
        }

        // Enable the hook by setting the necessary permissions on the primary EPTs.
        ept_hook.enable_hooks(&mut vm.primary_ept)?;

        // Increment the hook index for the next hook.
        vm.hook_manager.current_hook_index += 1;
        trace!("Hook Index Incremented: {}", vm.hook_manager.current_hook_index);

        trace!("EPT hook created successfully");

        Ok(())
    }

    /// Enables all the hooks managed by the `Hook`.
    ///
    /// It sets the necessary permissions on the primary Extended Page Tables (EPTs)
    /// to intercept execution and data access at specific memory locations. This function is
    /// particularly used to switch between primary EPTs when executing hooked functions.
    ///
    /// # Arguments
    ///
    /// * `primary_ept` - A mutable reference to the primary EPT, typically representing the normal memory view.
    ///
    /// # Returns
    ///
    /// * `Result<(), HypervisorError>` - The result of the operation, `Ok` if successful, otherwise a `HypervisorError`.
    #[rustfmt::skip]
    pub fn enable_hooks(&mut self, primary_ept: &mut Box<Ept>) -> Result<(), HypervisorError> {
        trace!("Enabling hooks");

        // Align the guest function or page address to the large page size.
        let guest_large_page_pa = self.guest_pa.align_down_to_large_page().as_u64();

        // Split the guest 2MB page into 4KB pages for the primary EPT.
        trace!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
        primary_ept.split_2mb_to_4kb(guest_large_page_pa, self.primary_ept_pre_alloc_pt.as_mut())?;

        // Align the guest function or page address to the base page size.
        let guest_page_pa = self.guest_pa.align_down_to_base_page().as_u64();

        // Modify the page permission in the primary EPT to ReadWrite for the guest page.
        trace!("Changing Primary EPT permissions for page to Read-Write (RW) only: {:#x}", guest_page_pa);
        primary_ept.modify_page_permissions(guest_page_pa, AccessType::READ_WRITE, self.primary_ept_pre_alloc_pt.as_mut())?;

        // Invalidate the EPT cache for all contexts.
        invept_all_contexts();

        // Invalidate the VPID cache for all contexts.
        invvpid_all_contexts();

        Ok(())
    }

    /// Creates a hook on a function by its name.
    ///
    /// This function sets up a hook on a specific memory function, allowing for monitoring or altering the function's content.
    ///
    /// # Arguments
    ///
    /// * `guest_function_va` - The virtual address of the function to be hooked.
    /// * `hook_handler` - The handler function to be called when the hooked function is executed.
    /// * `hook_type` - The type of inline hook to be installed.
    ///
    /// # Returns
    ///
    /// * `Option<()>` - Returns `Some(())` if the hook was successfully installed, otherwise `None`.
    #[rustfmt::skip]
    pub fn hook_function(&mut self, guest_function_va: u64, hook_handler: *const (), hook_type: InlineHookType) -> Option<()> {
        let guest_function_va = VAddr::from(guest_function_va);
        trace!("Guest Function VA: {:#x}", guest_function_va);
        trace!("Hook Handler: {:#x}", hook_handler as u64);

        // Convert the function guest virtual address to a physical address using Guest CR3.
        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va(guest_function_va.as_u64()));
        trace!("Guest Function PA: {:#x}", guest_function_pa.as_u64());

        // Align the guest function address to the base page size.
        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        trace!("Guest Page PA: {:#x}", guest_page_pa.as_u64());

        // Get the physical address of the pre-allocated host shadow page.
        let host_shadow_page_pa = PAddr::from(self.host_shadow_page.as_mut_slice().as_mut_ptr() as u64);
        trace!("Host Shadow Page PA: {:#x}", host_shadow_page_pa);

        // Copy the guest page to the pre-allocated host shadow page.
        Self::unsafe_copy_guest_to_shadow(guest_page_pa, host_shadow_page_pa);

        // Calculate the address of the function within the pre-allocated host shadow page.
        let host_shadow_function_pa = PAddr::from(Self::calculate_function_offset_in_host_shadow_page(host_shadow_page_pa, guest_function_pa));
        trace!("Host Shadow Function PA: {:#x}", host_shadow_function_pa);

        // Create a new inline hook configuration.
        let mut inline_hook = InlineHook::new(
            host_shadow_function_pa.as_u64() as _,
            guest_function_va.as_u64() as _,
            hook_handler as _,
            hook_type,
        );

        // Perform the actual hook
        trace!("Calling Detour64");
        inline_hook.detour64();

        // Set the hook properties.
        self.guest_va = guest_function_va;
        self.guest_pa = guest_function_pa;
        self.host_shadow_page_pa = host_shadow_page_pa;
        self.host_shadow_function_pa = host_shadow_function_pa;
        self.hook_handler = hook_handler;
        self.hook_type = EptHookType::Function(hook_type);
        self.inline_hook = Some(inline_hook);

        Some(())
    }

    /// Creates a hook on a specific page.
    ///
    /// This function sets up a hook on a specific memory page, allowing for monitoring or altering the page's content.
    ///
    /// # Arguments
    ///
    /// * `guest_page_va` - The virtual address of the page to be hooked.
    /// * `hook_handler` - The handler function to be called when the hooked page is accessed.
    /// * `ept_hook_type` - The type of EPT hook to be installed.
    ///
    /// # Returns
    ///
    /// * `Option<()>` - Returns `Some(())` if the hook was successfully installed, otherwise `None`.
    #[rustfmt::skip]
    pub fn hook_page(&mut self, guest_page_va: u64, hook_handler: *const (), ept_hook_type: EptHookType) -> Option<()> {
        let guest_page_va = VAddr::from(guest_page_va);
        trace!("Guest Page VA: {:#x}", guest_page_va);

        // Convert the page guest virtual address to a physical address using Guest CR3.
        let guest_page_pa = PAddr::from(PhysicalAddress::pa_from_va(guest_page_va.as_u64()));
        trace!("Guest Page PA: {:#x}", guest_page_pa.as_u64());

        let host_shadow_page_pa = PAddr::from(self.host_shadow_page.as_mut_slice().as_mut_ptr() as u64);
        trace!("Host Shadow Page PA: {:#x}", host_shadow_page_pa);

        // Copy the guest page to the pre-allocated host shadow page.
        Self::unsafe_copy_guest_to_shadow(guest_page_pa.align_down_to_base_page(), host_shadow_page_pa);

        // Set the hook properties.
        self.guest_va = guest_page_va;
        self.guest_pa = guest_page_pa;
        self.host_shadow_page_pa = host_shadow_page_pa;
        self.hook_handler = hook_handler;
        self.hook_type = ept_hook_type;

        Some(())
    }

    /// Copies the guest page to the pre-allocated host shadow page.
    ///
    /// # Arguments
    ///
    /// * `guest_page_pa` - The physical address of the guest page.
    /// * `host_shadow_page_pa` - The physical address of the host shadow page.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs a raw memory copy from the guest page to the shadow page.
    #[rustfmt::skip]
    pub fn unsafe_copy_guest_to_shadow(guest_page_pa: PAddr, host_shadow_page_pa: PAddr) {
        unsafe { copy_nonoverlapping(guest_page_pa.as_u64() as *mut u8, host_shadow_page_pa.as_u64() as *mut u8, BASE_PAGE_SIZE) };
    }

    /// Calculates the address of the function within the host shadow page.
    ///
    /// # Arguments
    ///
    /// * `host_shadow_page_pa` - The physical address of the host shadow page.
    /// * `guest_function_pa` - The physical address of the guest function.
    ///
    /// # Returns
    ///
    /// * `u64` - The adjusted address of the function within the new page.
    #[rustfmt::skip]
    fn calculate_function_offset_in_host_shadow_page(host_shadow_page_pa: PAddr, guest_function_pa: PAddr) -> u64 {
        host_shadow_page_pa.as_u64() + guest_function_pa.base_page_offset()
    }
}
