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

#[derive(Debug, Clone)]
pub struct MemoryManager<const N: usize> {
    active_page_tables: LinearMap<u64, Box<Pt>, N>,
    active_shadow_pages: LinearMap<u64, Box<Page>, N>,

    free_page_tables: Vec<Box<Pt>, N>,
    free_shadow_pages: Vec<Box<Page>, N>,
}

impl<const N: usize> MemoryManager<N> {
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing memory manager");

        let active_page_tables = LinearMap::<u64, Box<Pt>, N>::new();
        let active_shadow_pages = LinearMap::<u64, Box<Page>, N>::new();

        let mut free_page_tables = Vec::<Box<Pt>, N>::new();
        let mut free_shadow_pages = Vec::<Box<Page>, N>::new();

        trace!("Pre-allocating page tables and shadow pages");

        // Pre-allocate shadow pages and page tables for hooks.
        for _ in 0..N {
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

    pub fn is_guest_page_split(&self, guest_page_pa: u64) -> bool {
        self.active_page_tables.contains_key(&guest_page_pa)
    }

    pub fn is_shadow_page_copied(&self, guest_page_pa: u64) -> bool {
        self.active_shadow_pages.contains_key(&guest_page_pa)
    }

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

    pub fn get_page_table_as_mut(&mut self, guest_page_pa: u64) -> Option<&mut Pt> {
        self.active_page_tables.get_mut(&guest_page_pa).map(|boxed_pt| &mut **boxed_pt)
    }

    pub fn get_shadow_page_as_ptr(&self, guest_page_pa: u64) -> Option<u64> {
        self.active_shadow_pages
            .get(&guest_page_pa)
            .map(|boxed_page| &**boxed_page as *const Page as u64)
    }
}
