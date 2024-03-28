//! This module provides functionalities for creating and managing hooks in a hypervisor environment.
//! It includes support for function hooks and page hooks, allowing manipulation and monitoring
//! of system behavior at a low level. The module is designed for use in scenarios requiring direct
//! interaction with system internals, such as in kernel and hypervisor development.

use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::{AccessType, Ept, PT_INDEX_MAX},
            hooks::inline::{InlineHook, InlineHookType},
            page::Page,
        },
    },
    alloc::boxed::Box,
    core::intrinsics::copy_nonoverlapping,
    core::ptr::addr_of_mut,
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
/// `Hook` is a container for multiple hooks and provides an interface
/// to enable or disable these hooks as a group. It's primarily responsible for
/// modifying the Extended Page Tables (EPT) to facilitate the hooking mechanism.
pub struct Hook {
    /// The index of the page table entry in the EPT, to keep track of the hooks.
    pub pt_table_index: usize,

    /// Original virtual address of the target function or page.
    pub original_function_va: VAddr,

    /// Original physical address of the target function or page.
    pub original_function_pa: PAddr,

    /// Virtual address where the hook is placed.
    pub shadow_function_va: VAddr,

    /// Physical address of the hook.
    pub shadow_function_pa: PAddr,

    /// Contents of the original page where the hook is placed.
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

impl Hook {
    /// Constructs a new `Hook` with a given set of hooks.
    ///
    /// # Arguments
    ///
    /// * `hooks` - A vector of `Hook` instances to be managed.
    pub fn new(shadow_page: Box<Page>, pt_table_index: usize) -> Box<Self> {
        let hooks = Self {
            pt_table_index,
            original_function_va: VAddr::zero(),
            original_function_pa: PAddr::zero(),
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
        // Increment the page table index for each hook. Should not be 0 as it's reserved.
        self.pt_table_index += 1;

        // If the page table index exceeds the maximum allowed, return an error.
        if self.pt_table_index >= PT_INDEX_MAX {
            return Err(HypervisorError::EptPtTableIndexExhausted);
        }

        let original_page = self
            .original_function_pa
            .align_down_to_large_page()
            .as_u64();
        let hooked_copy_page = self.shadow_function_pa.align_down_to_large_page().as_u64();

        debug!(
            "Splitting 2MB page to 4KB pages for Primary EPT: {:#x}",
            original_page
        );
        primary_ept.split_2mb_to_4kb(original_page, self.pt_table_index)?;

        debug!(
            "Splitting 2MB page to 4KB pages for Secondary EPT: {:#x}",
            hooked_copy_page
        );
        secondary_ept.split_2mb_to_4kb(original_page, self.pt_table_index)?;

        // Align addresses to their base page sizes for accurate permission modification.
        let original_page = self.original_function_pa.align_down_to_base_page().as_u64();
        let hooked_copy_page = self.shadow_function_pa.align_down_to_base_page().as_u64();

        // Modify the page permission in the primary EPT to ReadWrite for the original page.
        debug!(
            "Changing permissions for page to Read-Write (RW) only: {:#x}",
            original_page
        );
        primary_ept.modify_page_permissions(
            original_page,
            AccessType::READ_WRITE,
            self.pt_table_index,
        )?;

        // Modify the page permission in the secondary EPT to Execute for the original page.
        debug!(
            "Changing permissions for hook page to Execute (X) only: {:#x}",
            hooked_copy_page
        );
        secondary_ept.modify_page_permissions(
            original_page,
            AccessType::EXECUTE,
            self.pt_table_index,
        )?;

        // Map the original page to the hooked page in the secondary EPT.
        debug!("Mapping Guest Physical Address to Host Physical Address of the hooked page: {:#x} {:#x}", original_page, hooked_copy_page);
        secondary_ept.remap_gpa_to_hpa(original_page, hooked_copy_page, self.pt_table_index)?;

        Ok(())
    }

    pub fn hook_function_uefi(
        &mut self,
        original_function_pa: u64,
        hook_handler: *const (),
        hook_type: InlineHookType,
    ) -> Option<()> {
        trace!("Hook Function Called");

        // Cast the original physical address to a PAddr.
        let original_function_pa = PAddr::from(original_function_pa);

        // Copy the original page to the pre-allocated shadow page.
        unsafe {
            copy_nonoverlapping(
                original_function_pa.as_u64() as *mut u64,
                addr_of_mut!(self.shadow_page) as *mut u64,
                BASE_PAGE_SIZE,
            )
        };

        // Get the physical address of the shadow page.
        let shadow_page_pa = PAddr::from(addr_of_mut!(self.shadow_page) as *mut u64 as u64);

        // Calculate the address of the function within the copied page.
        let shadow_function_pa =
            PAddr::from(shadow_page_pa + original_function_pa.base_page_offset());

        debug!("Original Function PA: {:#x}", original_function_pa.as_u64());
        debug!("Shadow Page PA: {:#x}", shadow_page_pa);
        debug!("Shadow Function PA: {:#x}", shadow_function_pa);
        debug!("Hook Handler: {:#x}", hook_handler as u64);

        let inline_hook = InlineHook::new(
            original_function_pa.as_u64() as _,
            shadow_function_pa.as_u64() as _,
            hook_handler as _,
            hook_type,
        );

        // Set the hook properties.
        self.original_function_pa = original_function_pa;
        self.shadow_page_pa = shadow_page_pa;
        self.shadow_function_pa = shadow_function_pa;
        self.hook_handler = hook_handler;
        self.hook_type = HookType::Function { inline_hook };

        Some(())
    }
}
