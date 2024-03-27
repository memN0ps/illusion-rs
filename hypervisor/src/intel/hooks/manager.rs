//! This module provides functionalities for creating and managing hooks in a hypervisor environment.
//! It includes support for function hooks and page hooks, allowing manipulation and monitoring
//! of system behavior at a low level. The module is designed for use in scenarios requiring direct
//! interaction with system internals, such as in kernel and hypervisor development.

use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::{AccessType, Ept, PT_INDEX_MAX},
            hooks::hook::{Hook, HookType},
        },
    },
    alloc::{boxed::Box, vec::Vec},
    log::*,
};

/// Manages the lifecycle and control of various hooks.
///
/// `HookManager` is a container for multiple hooks and provides an interface
/// to enable or disable these hooks as a group. It's primarily responsible for
/// modifying the Extended Page Tables (EPT) to facilitate the hooking mechanism.
pub struct HookManager {
    /// A collection of hooks managed by the HookManager.
    pub hooks: Vec<Hook>,

    /// The index of the page table entry in the EPT, to keep track of the hooks.
    pub pt_table_index: usize,
}

impl HookManager {
    /// Constructs a new `HookManager` with a given set of hooks.
    ///
    /// # Arguments
    ///
    /// * `hooks` - A vector of `Hook` instances to be managed.
    pub fn new(hooks: Vec<Hook>) -> Box<Self> {
        let hooks = Self {
            hooks,
            pt_table_index: 0,
        };

        Box::new(hooks)
    }

    /// Enables all the hooks managed by the `HookManager`.
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
        for hook in &mut self.hooks {
            // Increment the page table index for each hook. Should not be 0 as it's reserved.
            self.pt_table_index += 1;

            // If the page table index exceeds the maximum allowed, return an error.
            if self.pt_table_index >= PT_INDEX_MAX {
                return Err(HypervisorError::EptPtTableIndexExhausted);
            }

            if let HookType::Function { inline_hook } = &mut hook.hook_type {
                inline_hook.enable()?;
            }

            let original_page = hook.original_pa.align_down_to_large_page().as_u64();
            let hooked_copy_page = hook.shadow_pa.align_down_to_large_page().as_u64();

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
            let original_page = hook.original_pa.align_down_to_base_page().as_u64();
            let hooked_copy_page = hook.shadow_pa.align_down_to_base_page().as_u64();

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
        }

        Ok(())
    }
}
