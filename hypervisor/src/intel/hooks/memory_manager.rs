//! Module for managing memory allocations related to Extended Page Tables (EPT)
//! for a hypervisor. Provides pre-allocated memory resources for EPT hooks and
//! management functionalities to maintain and access these resources effectively.

use {
    crate::{
        allocator::box_zeroed,
        error::HypervisorError,
        global_const::{MAX_HOOKS_PER_PAGE, MAX_HOOK_ENTRIES},
        intel::{ept::Pt, hooks::hook_manager::EptHookType, page::Page},
    },
    alloc::boxed::Box,
    heapless::{LinearMap, Vec},
    log::{error, trace},
};

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

    /// The list of hooks associated with this page.
    pub hooks: Vec<HookInfo, MAX_HOOKS_PER_PAGE>,
}

/// Represents a memory management system that pre-allocates and manages page tables
/// and shadow pages for a hypervisor, using fixed-size arrays to avoid runtime allocation.
#[derive(Debug, Clone)]
pub struct MemoryManager {
    /// Active mappings of guest physical addresses to their respective hook mappings.
    active_mappings: LinearMap<u64, HookMapping, MAX_HOOK_ENTRIES>,

    /// Mappings of large guest physical addresses to their respective page tables.
    large_pt_mappings: LinearMap<u64, Box<Pt>, MAX_HOOK_ENTRIES>,

    /// Free slots for hook mappings.
    free_slots_hm: Vec<usize, MAX_HOOK_ENTRIES>,

    /// Free slots for page tables.
    free_slots_pt: Vec<usize, MAX_HOOK_ENTRIES>,
}

impl MemoryManager {
    /// Constructs a new `MemoryManager` instance, pre-allocating all necessary resources.
    ///
    /// # Returns
    /// A new instance of `MemoryManager` or an error if initial allocation fails.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing memory manager");

        let mut active_mappings = LinearMap::<u64, HookMapping, MAX_HOOK_ENTRIES>::new();
        let mut large_pt_mappings = LinearMap::<u64, Box<Pt>, MAX_HOOK_ENTRIES>::new();
        let mut free_slots_hm = Vec::<usize, MAX_HOOK_ENTRIES>::new();
        let mut free_slots_pt = Vec::<usize, MAX_HOOK_ENTRIES>::new();

        trace!("Pre-allocating shadow pages and page tables");

        // Pre-allocate shadow pages for hooks and page tables for large pages.
        for i in 0..MAX_HOOK_ENTRIES {
            let sp = unsafe { box_zeroed::<Page>() };

            active_mappings
                .insert(
                    i as u64,
                    HookMapping {
                        shadow_page: sp,
                        hooks: Vec::<HookInfo, MAX_HOOKS_PER_PAGE>::new(),
                    },
                )
                .map_err(|_| HypervisorError::ActiveMappingError)?;

            let pt = unsafe { box_zeroed::<Pt>() };
            large_pt_mappings.insert(i as u64, pt).map_err(|_| HypervisorError::LargePtMappingError)?;

            free_slots_hm.push(i).map_err(|_| HypervisorError::ActiveMappingError)?;
            free_slots_pt.push(i).map_err(|_| HypervisorError::LargePtMappingError)?;
        }

        trace!("Memory manager initialized");

        Ok(Self {
            active_mappings,
            large_pt_mappings,
            free_slots_hm,
            free_slots_pt,
        })
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
    /// Maps the Large Page to the Page Table if not already mapped.
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

        if let Some(mapping) = self.active_mappings.get_mut(&guest_page_pa) {
            trace!("Mapping already exists, adding hook info");
            mapping.hooks.push(hook_info).map_err(|_| HypervisorError::TooManyHooks)?;
        } else {
            trace!("Mapping does not exist, creating new mapping");
            if let Some(free_slot) = self.free_slots_hm.pop() {
                trace!("Found free slot at index: {}", free_slot);
                let key = free_slot as u64;
                let mut mapping = self.active_mappings.remove(&key).unwrap();
                mapping.hooks.push(hook_info).map_err(|_| HypervisorError::TooManyHooks)?;
                self.active_mappings
                    .insert(guest_page_pa, mapping)
                    .map_err(|_| HypervisorError::ActiveMappingError)?;
                trace!("Guest page mapped to shadow page successfully");
            } else {
                error!("No free pages available for mapping");
                return Err(HypervisorError::OutOfMemory);
            }
        }

        Ok(())
    }

    /// Maps a free page table to a large guest physical address, removing it from the free pool.
    ///
    /// # Arguments
    ///
    /// * `guest_large_page_pa` - The large guest physical address to map.
    pub fn map_large_page_to_pt(&mut self, guest_large_page_pa: u64) -> Result<(), HypervisorError> {
        // Ensure the large page has a page table (Pt)
        if !self.large_pt_mappings.contains_key(&guest_large_page_pa) {
            trace!("Large page not mapped to page table, mapping now");
            if let Some(free_slot) = self.free_slots_pt.pop() {
                trace!("Found free slot for page table at index: {}", free_slot);
                let pt_key = free_slot as u64;
                let pt = self.large_pt_mappings.remove(&pt_key).unwrap();
                self.large_pt_mappings
                    .insert(guest_large_page_pa, pt)
                    .map_err(|_| HypervisorError::ActiveMappingError)?;
                trace!("Large page mapped to page table successfully");
            } else {
                error!("No free page tables available for mapping");
                return Err(HypervisorError::OutOfMemory);
            }
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
        self.large_pt_mappings.get_mut(&guest_large_page_pa).map(|pt| &mut **pt)
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
