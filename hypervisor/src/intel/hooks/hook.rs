//! This module provides functionalities for creating and managing hooks in a hypervisor environment.
//! It includes support for function hooks and page hooks, allowing manipulation and monitoring
//! of system behavior at a low level. The module is designed for use in scenarios requiring direct
//! interaction with system internals, such as in kernel and hypervisor development.
//! Credits to jessiep_ and Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/hook.rs
//!

use {
    crate::intel::{
        addresses::PhysicalAddress,
        hooks::inline::{InlineHook, InlineHookType},
        page::Page,
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
#[derive(Debug, Clone)]
pub struct EptHook {
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
    ///
    /// # Returns
    ///
    /// * `Box<Self>` - The new instance of `EptHook`.
    pub fn new(host_shadow_page: Box<Page>) -> Box<Self> {
        let hooks = Self {
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
        let mut inline_hook = InlineHook::new(host_shadow_function_pa.as_u64() as _, guest_function_va.as_u64() as _, hook_handler as _, hook_type);

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
    fn calculate_function_offset_in_host_shadow_page(host_shadow_page_pa: PAddr, guest_function_pa: PAddr) -> u64 {
        host_shadow_page_pa.as_u64() + guest_function_pa.base_page_offset()
    }
}
