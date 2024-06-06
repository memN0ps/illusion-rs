//! Module for managing memory allocations related to Extended Page Tables (EPT)
//! for a hypervisor. Provides pre-allocated memory resources for EPT hooks and
//! management functionalities to maintain and access these resources effectively.

use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{ept::Pt, hooks::hook_manager::EptHookType, page::Page},
    },
    alloc::boxed::Box,
    heapless::{LinearMap, Vec},
    log::{error, trace},
};

/// The maximum number of hooks supported by the hypervisor. Change this value as needed.
const MAX_HOOK_ENTRIES: usize = 64;

/// The maximum number of hooks per page supported by the hypervisor. Change this value as needed.
const MAX_HOOKS_PER_PAGE: usize = 64;

/// Represents the hook information for a specific guest virtual address and EPT hook type.
#[derive(Debug, Clone)]
pub struct HookInfo {
    pub guest_function_va: u64,
    pub guest_function_pa: u64,
    pub ept_hook_type: EptHookType,
    pub function_hash: u32,
}

/// Represents the mapping information for a guest page.
#[derive(Debug, Clone)]
pub struct HookMapping {
    /// The shadow page.
    pub shadow_page: Box<Page>,

    /// The page table.
    pub page_table: Box<Pt>,

    /// The list of hooks associated with this page.
    pub hooks: Vec<HookInfo, MAX_HOOKS_PER_PAGE>,
}

/// Represents a memory management system that pre-allocates and manages page tables
/// and shadow pages for a hypervisor, using fixed-size arrays to avoid runtime allocation.
#[derive(Debug, Clone)]
pub struct MemoryManager {
    /// Active mappings of guest physical addresses to their respective hook mappings.
    active_mappings: LinearMap<u64, HookMapping, MAX_HOOK_ENTRIES>,

    /// Free slots for hook mappings.
    free_slots: Vec<usize, MAX_HOOK_ENTRIES>,
}

impl MemoryManager {
    /// Constructs a new `MemoryManager` instance, pre-allocating all necessary resources.
    ///
    /// # Returns
    /// A new instance of `MemoryManager` or an error if initial allocation fails.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing memory manager");

        let mut active_mappings = LinearMap::<u64, HookMapping, MAX_HOOK_ENTRIES>::new();
        let mut free_slots = Vec::<usize, MAX_HOOK_ENTRIES>::new();

        trace!("Pre-allocating page tables and shadow pages");

        // Pre-allocate shadow pages and page tables for hooks.
        for i in 0..MAX_HOOK_ENTRIES {
            let pt = unsafe { box_zeroed::<Pt>() };
            let sp = unsafe { box_zeroed::<Page>() };

            active_mappings
                .insert(
                    i as u64,
                    HookMapping {
                        shadow_page: sp,
                        page_table: pt,
                        hooks: Vec::<HookInfo, MAX_HOOKS_PER_PAGE>::new(),
                    },
                )
                .map_err(|_| HypervisorError::ActiveMappingError)?;
            free_slots.push(i).map_err(|_| HypervisorError::ActiveMappingError)?;
        }

        trace!("Memory manager initialized");

        Ok(Self { active_mappings, free_slots })
    }

    /// Checks if a guest page is already processed (split and copied).
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to check.
    ///
    /// # Returns
    /// `true` if the guest page is processed, otherwise `false`.
    pub fn is_guest_page_processed(&self, guest_page_pa: u64) -> bool {
        self.active_mappings.contains_key(&guest_page_pa)
    }

    /// Maps a free page table and shadow page to a guest physical address, removing them from the free pool.
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
    pub fn map_guest_page_and_shadow_page(
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

        if let Some(mapping) = self.active_mappings.get_mut(&guest_page_pa) {
            trace!("Mapping already exists, adding hook info");
            mapping.hooks.push(hook_info).map_err(|_| HypervisorError::TooManyHooks)?;
        } else {
            trace!("Mapping does not exist, creating new mapping");
            if let Some(free_slot) = self.free_slots.pop() {
                trace!("Found free slot at index: {}", free_slot);
                let key = free_slot as u64;
                let mut mapping = self.active_mappings.remove(&key).unwrap();
                mapping.hooks.push(hook_info).map_err(|_| HypervisorError::TooManyHooks)?;
                self.active_mappings
                    .insert(guest_page_pa, mapping)
                    .map_err(|_| HypervisorError::ActiveMappingError)?;
                trace!("Mapping added successfully");
            } else {
                error!("No free pages available for mapping");
                return Err(HypervisorError::OutOfMemory);
            }
        }

        Ok(())
    }

    /// Retrieves a mutable reference to the page table associated with a guest physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    ///
    /// # Returns
    /// An `Option` containing a mutable reference to the `Pt` if found.
    pub fn get_page_table_as_mut(&mut self, guest_page_pa: u64) -> Option<&mut Pt> {
        self.active_mappings.get_mut(&guest_page_pa).map(|mapping| &mut *mapping.page_table)
    }

    /// Retrieves a pointer to the shadow page associated with a guest physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    ///
    /// # Returns
    /// An `Option` containing the memory address of the `Page` as a `u64` if found.
    pub fn get_shadow_page_as_ptr(&self, guest_page_pa: u64) -> Option<u64> {
        self.active_mappings
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
    pub fn get_hook_info(&self, guest_page_pa: u64) -> Option<&Vec<HookInfo, MAX_HOOKS_PER_PAGE>> {
        self.active_mappings.get(&guest_page_pa).map(|mapping| &mapping.hooks)
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
        self.active_mappings
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
        self.active_mappings
            .get(&guest_page_pa)?
            .hooks
            .iter()
            .find(|hook| hook.guest_function_va == guest_function_va)
    }
}
