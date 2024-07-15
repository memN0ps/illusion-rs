//! Module for managing memory allocations related to Extended Page Tables (EPT)
//! for a hypervisor. Provides memory resources for EPT hooks and management functionalities
//! to maintain and access these resources effectively.

use {
    crate::{
        error::HypervisorError,
        heap::box_zeroed,
        intel::{ept::Pt, hooks::hook_manager::EptHookType, page::Page},
    },
    alloc::{boxed::Box, collections::BTreeMap, vec::Vec},
    log::trace,
};

/// Represents the hook information for a specific guest virtual address and EPT hook type.
#[derive(Debug, Clone)]
pub struct HookInfo {
    /// Guest virtual address of the function to be hooked.
    pub guest_function_va: u64,
    /// Guest physical address of the function to be hooked.
    pub guest_function_pa: u64,
    /// Type of EPT hook to be applied.
    pub ept_hook_type: EptHookType,
    /// Hash of the function to be hooked.
    pub function_hash: u32,
}

/// Represents the mapping information for a guest page.
#[derive(Debug, Clone)]
pub struct HookMapping {
    /// The shadow page.
    pub shadow_page: Box<Page>,
    /// The list of hooks associated with this page.
    pub hooks: Vec<HookInfo>,
}

/// Represents a memory management system that manages page tables and shadow pages
/// for a hypervisor, allocating memory as needed at runtime.
#[derive(Debug, Clone)]
pub struct MemoryManager {
    /// Mappings of guest physical addresses to their respective hook mappings.
    guest_page_mappings: BTreeMap<u64, HookMapping>,
    /// Mappings of large guest physical addresses to their respective page tables.
    large_page_table_mappings: BTreeMap<u64, Box<Pt>>,
}

impl MemoryManager {
    /// Constructs a new `MemoryManager` instance.
    ///
    /// # Returns
    /// A new instance of `MemoryManager`.
    pub fn new() -> Self {
        trace!("Initializing memory manager");

        Self {
            guest_page_mappings: BTreeMap::new(),
            large_page_table_mappings: BTreeMap::new(),
        }
    }

    /// Checks if a guest page is already processed (split and copied).
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to check.
    ///
    /// # Returns
    /// `true` if the guest page is processed, otherwise `false`.
    pub fn is_guest_page_processed(&self, guest_page_pa: u64) -> bool {
        self.guest_page_mappings.contains_key(&guest_page_pa)
    }

    /// Maps a shadow page to a guest physical address and adds hook information, allocating memory as needed.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to map.
    /// * `guest_function_va` - The guest virtual address of the function.
    /// * `guest_function_pa` - The guest physical address of the function.
    /// * `ept_hook_type` - The type of EPT hook.
    /// * `function_hash` - The hash of the function.
    ///
    /// # Returns
    /// `Ok(())` if successful, or an error if no free pages are available or if already mapped.
    pub fn map_guest_to_shadow_page(
        &mut self,
        guest_page_pa: u64,
        guest_function_va: u64,
        guest_function_pa: u64,
        ept_hook_type: EptHookType,
        function_hash: u32,
    ) -> Result<(), HypervisorError> {
        trace!("Mapping guest page and shadow page for PA: {:#x}", guest_page_pa);

        let hook_info = HookInfo {
            guest_function_va,
            guest_function_pa,
            ept_hook_type,
            function_hash,
        };

        // Check if the guest page is already mapped
        if let Some(mapping) = self.guest_page_mappings.get_mut(&guest_page_pa) {
            trace!("Mapping already exists, adding hook info");

            // Check if the hook already exists for the given function PA
            if mapping.hooks.iter().any(|hook| hook.guest_function_pa == guest_function_pa) {
                trace!("Hook already exists for function PA: {:#x}", guest_function_pa);
            } else {
                mapping.hooks.push(hook_info); // Add new hook info
            }
        } else {
            trace!("Mapping does not exist, creating new mapping");
            // Allocate a new shadow page
            let shadow_page = unsafe { box_zeroed::<Page>() };
            let mut hooks = Vec::new();
            hooks.push(hook_info);

            // Insert new mapping into guest_page_mappings
            self.guest_page_mappings.insert(guest_page_pa, HookMapping { shadow_page, hooks });
            trace!("Guest page mapped to shadow page successfully");
        }

        Ok(())
    }

    /// Maps a free page table to a large guest physical address, allocating memory as needed.
    ///
    /// # Arguments
    /// * `guest_large_page_pa` - The large guest physical address to map.
    ///
    /// # Returns
    /// `Ok(())` if successful, or an error if no free page tables are available.
    pub fn map_large_page_to_pt(&mut self, guest_large_page_pa: u64) -> Result<(), HypervisorError> {
        // Check if the large page is already mapped
        if !self.large_page_table_mappings.contains_key(&guest_large_page_pa) {
            trace!("Large page not mapped to page table, mapping now");
            // Allocate a new page table
            let pt = unsafe { box_zeroed::<Pt>() };
            self.large_page_table_mappings.insert(guest_large_page_pa, pt);
            trace!("Large page mapped to page table successfully");
        } else {
            trace!("Large page PA: {:#x} is already mapped to a page table", guest_large_page_pa);
        }

        Ok(())
    }

    /// Retrieves a mutable reference to the page table associated with a large guest physical address.
    ///
    /// # Arguments
    /// * `guest_large_page_pa` - The large guest physical address.
    ///
    /// # Returns
    /// An `Option` containing a mutable reference to the `Pt` if found.
    pub fn get_page_table_as_mut(&mut self, guest_large_page_pa: u64) -> Option<&mut Pt> {
        self.large_page_table_mappings.get_mut(&guest_large_page_pa).map(|pt| &mut **pt)
    }

    /// Retrieves a pointer to the shadow page associated with a guest physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    ///
    /// # Returns
    /// An `Option` containing the memory address of the `Page` as a `u64` if found.
    pub fn get_shadow_page_as_ptr(&self, guest_page_pa: u64) -> Option<u64> {
        self.guest_page_mappings
            .get(&guest_page_pa)
            .map(|mapping| &*mapping.shadow_page as *const Page as u64)
    }

    /// Retrieves a reference to the `HookInfo` associated with a guest physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    ///
    /// # Returns
    /// An `Option` containing a reference to the `HookInfo` if found.
    pub fn get_hook_info(&self, guest_page_pa: u64) -> Option<&Vec<HookInfo>> {
        self.guest_page_mappings.get(&guest_page_pa).map(|mapping| &mapping.hooks)
    }

    /// Retrieves a reference to the `HookInfo` instance associated with a guest function physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    /// * `guest_function_pa` - The guest function physical address.
    ///
    /// # Returns
    /// An `Option` containing a reference to the `HookInfo` instance if found.
    pub fn get_hook_info_by_function_pa(&self, guest_page_pa: u64, guest_function_pa: u64) -> Option<&HookInfo> {
        self.guest_page_mappings
            .get(&guest_page_pa)?
            .hooks
            .iter()
            .find(|hook| hook.guest_function_pa == guest_function_pa)
    }

    /// Retrieves a reference to the `HookInfo` instance associated with a guest function virtual address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    /// * `guest_function_va` - The guest function virtual address.
    ///
    /// # Returns
    /// An `Option` containing a reference to the `HookInfo` instance if found.
    pub fn get_hook_info_by_function_va(&self, guest_page_pa: u64, guest_function_va: u64) -> Option<&HookInfo> {
        self.guest_page_mappings
            .get(&guest_page_pa)?
            .hooks
            .iter()
            .find(|hook| hook.guest_function_va == guest_function_va)
    }
}
