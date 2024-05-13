//! Memory manager module for the Intel hypervisor.
//! Contains structures and functions for managing pre-allocated shadow pages and split page tables.

use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{ept::Pt, page::Page},
    },
    alloc::{collections::BTreeMap, vec::Vec},
    core::ptr::NonNull,
    log::{trace, warn},
    x86::bits64::paging::PAddr,
};

#[derive(Debug, Clone)]
pub struct MemoryManager {
    // A pool of free shadow pages.
    free_shadow_pages: Vec<NonNull<Page>>,

    // A pool of free page tables.
    free_page_tables: Vec<NonNull<Pt>>,

    /// A map of guest physical addresses to shadow pages.
    active_shadow_pages: BTreeMap<u64, NonNull<Page>>,

    /// A map of guest physical addresses to split page tables.
    active_page_tables: BTreeMap<u64, NonNull<Pt>>,
}

impl MemoryManager {
    /// Creates a new instance of `MemoryManager`.
    ///
    /// # Arguments
    ///
    /// * `max_hooks` - The maximum number of hooks supported by the hypervisor.
    ///
    /// # Returns
    ///
    /// A result containing a `MemoryManager` instance or an error of type `HypervisorError`.
    pub fn new(max_hooks: usize) -> Result<Self, HypervisorError> {
        let mut free_shadow_pages = Vec::with_capacity(max_hooks);
        let mut free_page_tables = Vec::with_capacity(max_hooks);

        let mut active_shadow_pages = BTreeMap::new();
        let mut active_page_tables = BTreeMap::new();

        // Pre-allocate shadow pages and page tables for hooks.
        for index in 0..max_hooks {
            let shadow_page = NonNull::new(unsafe { box_zeroed::<Page>().as_mut() }).ok_or(HypervisorError::ShadowPageAllocationError)?;
            free_shadow_pages.push(shadow_page);

            let pt = NonNull::new(unsafe { box_zeroed::<Pt>().as_mut() }).ok_or(HypervisorError::PageTablesAllocationError)?;
            free_page_tables.push(pt);

            // Insert dummy keys with a known dummy value, e.g., 0 or some offset index
            active_shadow_pages.insert(index as u64, shadow_page);
            active_page_tables.insert(index as u64, pt);
        }

        Ok(Self {
            active_shadow_pages,
            active_page_tables,
            free_shadow_pages,
            free_page_tables,
        })
    }

    /// Gets or creates a shadow page for the specified guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address for which to get or create a shadow page.
    ///
    /// # Returns
    ///
    /// A result containing a non-null pointer to the shadow page or an error of type `HypervisorError`.
    pub fn get_or_create_shadow_page(&mut self, guest_pa: u64, index: u64) -> Result<NonNull<Page>, HypervisorError> {
        let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page().as_u64();

        // Attempt to return the shadow page if it already exists.
        if let Some(&shadow_page) = self.active_shadow_pages.get(&guest_page_pa) {
            Ok(shadow_page)
        } else {
            // Try to find and reuse a shadow page allocated under a dummy index.
            if let Some((dummy_index, shadow_page)) = self.free_shadow_pages.pop().map(|page| (index, page)) {
                // Remove the dummy index if it exists and use the shadow page for the new guest_pa.
                trace!("Reusing shadow page for guest PA: {:#x}", guest_page_pa);
                self.active_shadow_pages.remove(&dummy_index);

                trace!("Inserting shadow page for guest PA: {:#x}", guest_page_pa);
                self.active_shadow_pages.insert(guest_page_pa, shadow_page);
                Ok(shadow_page)
            } else {
                Err(HypervisorError::ShadowPagesUnavailable)
            }
        }
    }

    /// Gets or creates a split page table for the specified guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address for which to get or create a split page table.
    ///
    /// # Returns
    ///
    /// A result containing a non-null pointer to the split page table or an error of type `HypervisorError`.
    pub fn get_or_create_page_table(&mut self, guest_pa: u64, index: u64) -> Result<NonNull<Pt>, HypervisorError> {
        let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page().as_u64();

        if let Some(&pt) = self.active_page_tables.get(&guest_page_pa) {
            Ok(pt)
        } else {
            if let Some((dummy_index, pt)) = self.free_page_tables.pop().map(|pt| (index, pt)) {
                // Remove the dummy index if it exists and use the page table for the new guest_pa.
                self.active_page_tables.remove(&dummy_index);
                self.active_page_tables.insert(guest_page_pa, pt);
                Ok(pt)
            } else {
                Err(HypervisorError::PageTablesUnavailable)
            }
        }
    }

    /// Retrieves an existing shadow page associated with the specified guest physical address, if available.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address for which to retrieve the associated shadow page.
    ///
    /// # Returns
    ///
    /// An `Option` containing a non-null pointer to the shadow page if it exists, or `None` if no shadow page is associated with the provided address.
    pub fn get_shadow_page(&self, guest_pa: u64) -> Option<NonNull<Page>> {
        let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page().as_u64();
        self.active_shadow_pages.get(&guest_page_pa).copied()
    }

    /// Retrieves an existing page table associated with the specified guest physical address, if available.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address for which to retrieve the associated page table.
    ///
    /// # Returns
    ///
    /// An `Option` containing a non-null pointer to the page table if it exists, or `None` if no page table is associated with the provided address.
    pub fn get_page_table(&self, guest_pa: u64) -> Option<NonNull<Pt>> {
        let aligned_pa = PAddr::from(guest_pa).align_down_to_base_page().as_u64();
        self.active_page_tables.get(&aligned_pa).copied()
    }

    /// Checks if a shadow page has already been copied for the specified guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address for which to check if a shadow page has been copied.
    ///
    /// # Returns
    ///
    /// A boolean value indicating if a shadow page has already been copied for the specified guest physical address.
    pub fn is_page_copied(&self, guest_pa: u64) -> bool {
        let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page().as_u64();
        let exists = self.active_shadow_pages.contains_key(&guest_page_pa);
        if exists {
            warn!("Shadow page already exists for guest PA: {:#x}", guest_page_pa);
        }
        exists
    }

    /// Checks if a split page table has already been created for the specified guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address for which to check if a split page table has been created.
    ///
    /// # Returns
    ///
    /// A boolean value indicating if a split page table has already been created for the specified guest physical address.
    pub fn is_page_split(&self, guest_pa: u64) -> bool {
        let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page().as_u64();
        let exists = self.active_page_tables.contains_key(&guest_page_pa);
        if exists {
            warn!("Split page table already exists for guest PA: {:#x}", guest_page_pa);
        }
        exists
    }
}
