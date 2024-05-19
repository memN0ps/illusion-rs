//! Module for managing memory allocations related to Extended Page Tables (EPT)
//! for a hypervisor. Provides pre-allocated memory resources for EPT hooks and
//! management functionalities to maintain and access these resources effectively.

use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{ept::Pt, page::Page},
    },
    alloc::boxed::Box,
    heapless::{LinearMap, Vec},
    log::trace,
};

/// The maximum number of hooks supported by the hypervisor. Change this value as needed.
const MAX_HOOK_ENTRIES: usize = 64;

/// Represents a memory management system that pre-allocates and manages page tables
/// and shadow pages for a hypervisor, using fixed-size arrays to avoid runtime allocation.
#[derive(Debug, Clone)]
pub struct MemoryManager {
    /// Active mappings of guest physical addresses to their respective page tables.
    active_page_tables: LinearMap<u64, Box<Pt>, MAX_HOOK_ENTRIES>,
    /// Active mappings of guest physical addresses to their respective shadow pages.
    active_shadow_pages: LinearMap<u64, Box<Page>, MAX_HOOK_ENTRIES>,

    /// Pool of pre-allocated, free page tables available for assignment.
    free_page_tables: Vec<Box<Pt>, MAX_HOOK_ENTRIES>,
    /// Pool of pre-allocated, free shadow pages available for assignment.
    free_shadow_pages: Vec<Box<Page>, MAX_HOOK_ENTRIES>,
}

impl MemoryManager {
    /// Constructs a new `MemoryManager` instance, pre-allocating all necessary resources.
    ///
    /// # Returns
    /// A new instance of `MemoryManager` or an error if initial allocation fails.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing memory manager");

        let active_page_tables = LinearMap::<u64, Box<Pt>, MAX_HOOK_ENTRIES>::new();
        let active_shadow_pages = LinearMap::<u64, Box<Page>, MAX_HOOK_ENTRIES>::new();

        let mut free_page_tables = Vec::<Box<Pt>, MAX_HOOK_ENTRIES>::new();
        let mut free_shadow_pages = Vec::<Box<Page>, MAX_HOOK_ENTRIES>::new();

        trace!("Pre-allocating page tables and shadow pages");

        // Pre-allocate shadow pages and page tables for hooks.
        for _ in 0..MAX_HOOK_ENTRIES {
            let pt = unsafe { box_zeroed::<Pt>() };
            let sp = unsafe { box_zeroed::<Page>() };

            free_page_tables.push(pt).map_err(|_| HypervisorError::PageTablesAllocationError)?;
            free_shadow_pages.push(sp).map_err(|_| HypervisorError::ShadowPageAllocationError)?;
        }

        trace!("Memory manager initialized");

        Ok(Self {
            active_page_tables,
            active_shadow_pages,
            free_page_tables,
            free_shadow_pages,
        })
    }

    /// Checks if a guest page is already associated with a split page table.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to check.
    ///
    /// # Returns
    /// `true` if the guest page is split, otherwise `false`.
    pub fn is_guest_page_split(&self, guest_page_pa: u64) -> bool {
        self.active_page_tables.contains_key(&guest_page_pa)
    }

    /// Checks if a shadow page has been copied and is active for the given guest physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to check.
    ///
    /// # Returns
    /// `true` if the shadow page is copied, otherwise `false`.
    pub fn is_shadow_page_copied(&self, guest_page_pa: u64) -> bool {
        self.active_shadow_pages.contains_key(&guest_page_pa)
    }

    /// Maps a free page table to a guest physical address, removing it from the free pool.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to map.
    ///
    /// # Returns
    /// `Ok(())` if successful, or an error if no free page tables are available or if already mapped.
    pub fn map_guest_page_table(&mut self, guest_page_pa: u64) -> Result<(), HypervisorError> {
        if let Some(free_pt) = self.free_page_tables.pop() {
            self.active_page_tables
                .insert(guest_page_pa, free_pt)
                .map_err(|_| HypervisorError::PageTableAlreadyMapped)?;
        } else {
            return Err(HypervisorError::PageTablesUnavailable);
        }
        Ok(())
    }

    /// Maps a free shadow page to a guest physical address, removing it from the free pool.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address to map.
    ///
    /// # Returns
    /// `Ok(())` if successful, or an error if no free shadow pages are available or if already mapped.
    pub fn map_shadow_page(&mut self, guest_page_pa: u64) -> Result<(), HypervisorError> {
        if let Some(free_shadow_page) = self.free_shadow_pages.pop() {
            self.active_shadow_pages
                .insert(guest_page_pa, free_shadow_page)
                .map_err(|_| HypervisorError::ShadowPageAlreadyMapped)?;
        } else {
            return Err(HypervisorError::ShadowPagesUnavailable);
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
        self.active_page_tables.get_mut(&guest_page_pa).map(|boxed_pt| &mut **boxed_pt)
    }

    /// Retrieves a pointer to the shadow page associated with a guest physical address.
    ///
    /// # Arguments
    /// * `guest_page_pa` - The guest physical address.
    ///
    /// # Returns
    /// An `Option` containing the memory address of the `Page` as a `u64` if found.
    pub fn get_shadow_page_as_ptr(&self, guest_page_pa: u64) -> Option<u64> {
        self.active_shadow_pages
            .get(&guest_page_pa)
            .map(|boxed_page| &**boxed_page as *const Page as u64)
    }
}
