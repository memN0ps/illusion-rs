//! This module provides functionalities for creating and managing hooks in a hypervisor environment.
//! It includes support for function hooks and page hooks, allowing manipulation and monitoring
//! of system behavior at a low level. The module is designed for use in scenarios requiring direct
//! interaction with system internals, such as in kernel and hypervisor development.

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
pub enum HookType {
    /// Hook for intercepting and possibly modifying function execution.
    Function { inline_hook: InlineHook },

    /// Hook for hiding or monitoring access to a specific page.
    Page,
}

/// Manages the lifecycle and control of various hooks.
///
/// `EptHook` is a container for multiple hooks and provides an interface
/// to enable or disable these hooks as a group. It's primarily responsible for
/// modifying the Extended Page Tables (EPT) to facilitate the hooking mechanism.
pub struct EptHook {
    /// The Page Table (PT) for the hook (Pre-Allocated).
    pub pt: Box<Pt>,

    /// Original virtual address of the target function or page.
    pub original_function_va: VAddr,

    /// Original physical address of the target function or page.
    pub original_function_pa: PAddr,

    /// Virtual address where the hook is placed.
    pub original_page_va: VAddr,

    /// Physical address where the hook is placed.
    pub original_page_pa: PAddr,

    /// Virtual address where the hook is placed.
    pub shadow_function_va: VAddr,

    /// Physical address of the hook.
    pub shadow_function_pa: PAddr,

    /// Contents of the original page where the hook is placed (Pre-Allocated).
    pub shadow_page: Box<Page>,

    /// Virtual address of the page containing the hook.
    pub shadow_page_va: VAddr,

    /// Physical address of the page containing the hook.
    pub shadow_page_pa: PAddr,

    /// Type of the hook (Function or Page).
    pub hook_type: HookType,

    /// Handler function to be called when the hook is triggered.
    pub hook_handler: *const (),
}

impl EptHook {
    /// Constructs a new `Hook` with a given set of hooks.
    ///
    /// # Arguments
    ///
    /// * `hooks` - A vector of `Hook` instances to be managed.
    pub fn new(shadow_page: Box<Page>, pt: Box<Pt>) -> Box<Self> {
        let hooks = Self {
            pt,
            original_function_va: VAddr::zero(),
            original_function_pa: PAddr::zero(),
            original_page_va: VAddr::zero(),
            original_page_pa: PAddr::zero(),
            shadow_function_va: VAddr::zero(),
            shadow_function_pa: PAddr::zero(),
            shadow_page,
            shadow_page_va: VAddr::zero(),
            shadow_page_pa: PAddr::zero(),
            hook_type: HookType::Page,
            hook_handler: core::ptr::null(),
        };
        Box::new(hooks)
    }

    /// Installs an EPT hook for a function.
    ///
    /// # Arguments
    ///
    /// * original_va - The virtual address of the function to be hooked.
    /// * hook_handler - The handler function to be called when the hooked function is executed.
    /// * hook_type - The type of hook to be installed.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    pub fn ept_hook(
        vm: &mut Vm,
        original_va: u64,
        hook_handler: *const (),
        hook_type: InlineHookType,
    ) -> Result<(), HypervisorError> {
        trace!("Creating an EPT hook for function at {:#x}", original_va);

        // Get the shared data from the VM.
        let shared_data = unsafe { vm.shared_data.as_mut() };

        // Ensure the index is within bounds
        if shared_data.current_hook_index >= shared_data.hook_manager.len() {
            return Err(HypervisorError::OutOfHooks);
        }

        trace!(
            "Accessing Hook Manager with hook index: {}",
            shared_data.current_hook_index
        );

        // Access the current hook based on `current_hook_index`
        let hook = shared_data
            .hook_manager
            .get_mut(shared_data.current_hook_index)
            .ok_or(HypervisorError::FailedToGetCurrentHookIndex)?;

        // Increment the hook index for the next hook.
        shared_data.current_hook_index += 1;

        trace!("Hook Index Incremented: {}", shared_data.current_hook_index);

        // Setups the hook for the function.
        hook.setup_function_hook(original_va, hook_handler, hook_type)
            .ok_or(HypervisorError::HookError)?;

        // Get the primary and secondary EPTs.
        let primary_ept = &mut shared_data.primary_ept;
        let secondary_ept = &mut shared_data.secondary_ept;

        // Enable the hook by setting the necessary permissions on the primary and secondary EPTs.
        hook.enable_hooks(primary_ept, secondary_ept)?;

        trace!("EPT hook created successfully");

        Ok(())
    }

    /// Enables all the hooks managed by the `Hook`.
    ///
    /// It sets the necessary permissions on the primary and secondary Extended Page Tables (EPTs)
    /// to intercept execution and data access at specific memory locations. This function is
    /// particularly used to switch between primary and secondary EPTs when executing hooked functions.
    ///
    /// # Arguments
    ///
    /// * `primary_ept` - A mutable reference to the primary EPT, typically representing the normal memory view.
    /// * `secondary_ept` - A mutable reference to the secondary EPT, typically representing the altered memory view for hooks.
    ///
    /// # Returns
    ///
    /// * `Result<(), HypervisorError>` - The result of the operation, `Ok` if successful, otherwise a `HypervisorError`.
    pub fn enable_hooks(
        &mut self,
        primary_ept: &mut Box<Ept>,
        secondary_ept: &mut Box<Ept>,
    ) -> Result<(), HypervisorError> {
        trace!("Enabling hooks");

        // Align the original function address to the large page size.
        let original_large_page = self
            .original_function_pa
            .align_down_to_large_page()
            .as_u64();

        // Split the original page 2MB page into 4KB pages for the primary EPT.
        debug!(
            "Splitting 2MB page to 4KB pages for Primary EPT: {:#x}",
            original_large_page
        );
        primary_ept.split_2mb_to_4kb(original_large_page, self.pt.as_mut())?;

        // Split the original page 2MB page into 4KB pages for the secondary EPT.
        debug!(
            "Splitting 2MB page to 4KB pages for Secondary EPT: {:#x}",
            original_large_page
        );
        secondary_ept.split_2mb_to_4kb(original_large_page, self.pt.as_mut())?;

        // Align the original function address to the base page size.
        let original_page = self.original_function_pa.align_down_to_base_page().as_u64();

        // Align the shadow function address to the base page size.
        let shadow_page = self.shadow_function_pa.align_down_to_base_page().as_u64();

        // Modify the page permission in the primary EPT to ReadWrite for the original page.
        debug!(
            "Changing permissions for page to Read-Write (RW) only: {:#x}",
            original_page
        );
        primary_ept.modify_page_permissions(
            original_page,
            AccessType::READ_WRITE,
            self.pt.as_mut(),
        )?;

        // Modify the page permission in the secondary EPT to Execute-only for the original page.
        debug!(
            "Changing permissions for hook page to Execute (X) only: {:#x}",
            shadow_page
        );
        secondary_ept.modify_page_permissions(
            original_page,
            AccessType::EXECUTE,
            self.pt.as_mut(),
        )?;

        // Map the original page to the hooked shadow page in the secondary EPT.
        debug!("Mapping Guest Physical Address to Host Physical Address of the hooked page: {:#x} {:#x}", original_page, shadow_page);
        secondary_ept.remap_gpa_to_hpa(original_page, shadow_page, self.pt.as_mut())?;

        // Invalidate the EPT cache for all contexts.
        invept_all_contexts();

        // Invalidate the VPID cache for all contexts.
        invvpid_all_contexts();

        Ok(())
    }

    pub fn setup_function_hook(
        &mut self,
        original_function_va: u64,
        hook_handler: *const (),
        hook_type: InlineHookType,
    ) -> Option<()> {
        trace!("Hook Function Called");
        trace!("Hook Type: {:?}", hook_type);
        debug!("Hook Handler: {:#x}", hook_handler as u64);

        // Cast the original virtual address to a physical address using Guest CR3.
        let original_function_pa = PAddr::from(PhysicalAddress::pa_from_va(original_function_va));
        debug!("Original Function PA: {:#x}", original_function_pa.as_u64());

        // Align the original function address to the base page size.
        let original_page_pa = original_function_pa.align_down_to_base_page();
        trace!("Original Page PA: {:#x}", original_page_pa.as_u64());

        // Get the physical address of the shadow page.
        let shadow_page_ptr = self.shadow_page.as_mut_slice().as_mut_ptr();
        let shadow_page_pa = PAddr::from(shadow_page_ptr as u64);
        debug!("Shadow Page PA: {:#x}", shadow_page_pa);

        // Copy the original page to the pre-allocated shadow page.
        unsafe {
            copy_nonoverlapping(
                original_page_pa.as_u64() as *mut u8,
                shadow_page_pa.as_u64() as *mut u8,
                BASE_PAGE_SIZE,
            )
        };

        // Calculate the address of the function within the copied page.
        let shadow_function_pa =
            PAddr::from(shadow_page_pa + original_function_pa.base_page_offset());
        debug!("Shadow Function PA: {:#x}", shadow_function_pa);

        let mut inline_hook = InlineHook::new(shadow_function_pa.as_u64() as _, hook_type);

        // Perform the actual hook
        trace!("Calling Detour64");
        inline_hook.detour64();

        // Set the hook properties.
        self.original_function_pa = original_function_pa;
        self.original_page_pa = original_page_pa;
        self.shadow_page_pa = shadow_page_pa;
        self.shadow_function_pa = shadow_function_pa;
        self.hook_handler = hook_handler;
        self.hook_type = HookType::Function { inline_hook };

        Some(())
    }
}
