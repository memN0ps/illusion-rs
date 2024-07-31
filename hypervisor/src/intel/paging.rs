//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.2 HIERARCHICAL PAGING STRUCTURES: AN OVERVIEW
//! This section covers the standard paging mechanism as used in x86-64 architecture.
//! Standard paging controls how virtual memory addresses are translated to physical memory addresses.
//!
//! Credits to the work by Satoshi in their 'Hello-VT-rp' project for assistance and a clear implementation of this Paging Structure:
//! https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/paging_structures.rs

use {
    crate::error::HypervisorError,
    bitfield::bitfield,
    core::ptr::addr_of,
    log::error,
    x86::bits64::paging::{pd_index, pdpt_index, pml4_index, pt_index, VAddr, BASE_PAGE_SHIFT, BASE_PAGE_SIZE, HUGE_PAGE_SIZE, LARGE_PAGE_SIZE},
};

/// Represents the entire Page Tables structure for the hypervisor.
///
/// The Page Tables mechanism is crucial for virtual memory management in x86-64 architecture.
/// It consists of four levels of tables: PML4, PDPT, PD, and PT, which together facilitate the translation of virtual to physical addresses.
///
/// Each level of the Page Tables plays a role in this translation process:
/// - PML4 (Page Map Level 4) is the highest level and points to the next level.
/// - PDPT (Page Directory Pointer Table) points to Page Directories.
/// - PD (Page Directory) contains entries that either point to Page Tables or map large pages (2MB).
/// - PT (Page Table) contains entries that map standard 4KB pages.
///
/// This structure is aligned to 4096 bytes (4KB), which is the size of a standard page in x86-64.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 4-LEVEL PAGING AND 5-LEVEL PAGING
#[repr(C, align(4096))]
pub struct PageTables {
    /// Page Map Level 4 (PML4) Table.
    pml4: Pml4,
    /// Page Directory Pointer Table (PDPT).
    pdpt: Pdpt,
    /// Array of Page Directory Table (PDT).
    pd: [Pd; 512],
}

impl PageTables {
    /// Initializes the Page Tables structure with empty tables.
    pub fn init(&mut self) {
        self.pml4 = Pml4(Table { entries: [Entry(0); 512] });
        self.pdpt = Pdpt(Table { entries: [Entry(0); 512] });
        self.pd = [Pd(Table { entries: [Entry(0); 512] }); 512];
    }

    /// Builds a basic identity map for the page tables.
    ///
    /// This setup ensures that each virtual address directly maps to the same physical address,
    /// a common setup for the initial stages of an operating system or hypervisor.
    pub fn build_identity(&mut self) {
        log::debug!("Building identity map for page tables");

        // Configure the first entry in the PML4 table.
        // Set it to present and writable, pointing to the base of the PDPT.
        self.pml4.0.entries[0].set_present(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);

        // Start mapping physical addresses from 0.
        let mut pa = 0;

        // Iterate over each PDPT entry.
        for (i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            // Set each PDPT entry to present and writable,
            // pointing to the corresponding page directory (PD).
            pdpte.set_present(true);
            pdpte.set_writable(true);
            pdpte.set_pfn(addr_of!(self.pd[i]) as u64 >> BASE_PAGE_SHIFT);

            // Configure each entry in the PD to map a large page (e.g., 2MB).
            for pde in &mut self.pd[i].0.entries {
                // Set each PD entry to present, writable, and as a large page.
                // Point it to the corresponding physical address.
                pde.set_present(true);
                pde.set_writable(true);
                pde.set_large(true);
                pde.set_pfn(pa >> BASE_PAGE_SHIFT);

                // Increment the physical address by the size of a large page.
                pa += LARGE_PAGE_SIZE as u64;
            }
        }

        log::debug!("Identity map built successfully");
    }

    /// Translates a guest virtual address to a guest physical address using the guest's CR3.
    /// This function traverses the guest's page tables, assuming an identity-mapped
    /// host address space for simplicity.
    ///
    /// # Arguments
    /// * `guest_cr3` - The guest CR3 register value, which contains the base address of the guest's page table hierarchy.
    /// * `guest_va` - The guest virtual address to translate.
    ///
    /// # Safety
    /// This function is unsafe because it involves raw memory access based on potentially
    /// arbitrary addresses, which may lead to undefined behavior if the addresses are invalid
    /// or the memory is not properly mapped.
    ///
    /// # Returns
    /// Returns a `Result<u64, HypervisorError>` containing the translated guest physical address if successful,
    /// or an error if the translation fails at any level of the page table hierarchy.
    ///
    /// # Credits
    /// Credits to Jessie (jessiep_) for the help.
    pub unsafe fn translate_guest_virtual_to_guest_physical(guest_cr3: u64, guest_va: u64) -> Result<u64, HypervisorError> {
        let guest_va = VAddr::from(guest_va);

        // Cast guest CR3 to the PML4 table structure
        let pml4_table = guest_cr3 as *const Pml4;

        // Calculate the PML4 index and access the corresponding entry.
        let pml4_index = pml4_index(guest_va);
        let pml4_entry = &(*pml4_table).0.entries[pml4_index];

        // Check if the PML4 entry is present (readable).
        if !pml4_entry.present() {
            error!("PML4 entry is not present: {:#x}", guest_va);
            return Err(HypervisorError::InvalidPml4Entry);
        }

        // Cast the entry to the PDPT table structure.
        let pdpt_table = (pml4_entry.pfn() << BASE_PAGE_SHIFT) as *const Pdpt;

        // Calculate the PDPT index and access the corresponding entry.
        let pdpt_index = pdpt_index(guest_va);
        let pdpt_entry = &(*pdpt_table).0.entries[pdpt_index];

        // Check if the PDPT entry is present (readable).
        if !pdpt_entry.present() {
            error!("PDPT entry is not present: {:#x}", guest_va);
            return Err(HypervisorError::InvalidPdptEntry);
        }

        // Check if the PDPT entry is a huge page (1 GB), if so, calculate the guest physical address.
        if pdpt_entry.large() {
            let guest_pa = (pdpt_entry.pfn() << BASE_PAGE_SHIFT) + (guest_va.as_u64() % HUGE_PAGE_SIZE as u64);
            return Ok(guest_pa);
        }

        // Cast the entry to the PD table structure.
        let pd_table = (pdpt_entry.pfn() << BASE_PAGE_SHIFT) as *const Pd;

        // Calculate the PD index and access the corresponding entry.
        let pd_index = pd_index(guest_va);
        let pd_entry = &(*pd_table).0.entries[pd_index];

        // Check if the PD entry is present (readable).
        if !pd_entry.present() {
            error!("PD entry is not present: {:#x}", guest_va);
            return Err(HypervisorError::InvalidPdEntry);
        }

        // Check if the PD entry is a large page (2 MB), if so, calculate the guest physical address.
        if pd_entry.large() {
            let guest_pa = (pd_entry.pfn() << BASE_PAGE_SHIFT) + (guest_va.as_u64() % LARGE_PAGE_SIZE as u64);
            return Ok(guest_pa);
        }

        // Cast the entry to the PT table structure.
        let pt_table = (pd_entry.pfn() << BASE_PAGE_SHIFT) as *const Pt;

        // Calculate the PT index and access the corresponding entry.
        let pt_index = pt_index(guest_va);
        let pt_entry = &(*pt_table).0.entries[pt_index];

        // Check if the PT entry is present (readable).
        if !pt_entry.present() {
            error!("PT entry is not present: {:#x}", guest_va);
            return Err(HypervisorError::InvalidPtEntry);
        }

        // The PT entry is a 4 KB page, calculate the guest physical address.
        let guest_pa = (pt_entry.pfn() << BASE_PAGE_SHIFT) + (guest_va.as_u64() % BASE_PAGE_SIZE as u64);

        Ok(guest_pa)
    }

    /// Gets the physical address of the PML4 table, ensuring it is 4KB aligned.
    ///
    /// This method is typically used to retrieve the address to be loaded into CR3.
    ///
    /// # Returns
    /// A `Result` containing the 4KB-aligned physical address of the PML4 table
    /// or an error if the address is not aligned.
    ///
    /// # Errors
    /// Returns `HypervisorError::InvalidCr3BaseAddress` if the address is not 4KB aligned.
    pub fn get_pml4_pa(&self) -> Result<u64, HypervisorError> {
        // Retrieve the virtual address of the PML4 table.
        let addr = addr_of!(self.pml4) as u64;

        // Get the physical address of the PML4 table for CR3.
        let pa = addr;

        // Check if the base address is 4KB aligned (the lower 12 bits should be zero).
        if pa.trailing_zeros() >= BASE_PAGE_SHIFT as u32 {
            Ok(pa)
        } else {
            Err(HypervisorError::InvalidCr3BaseAddress)
        }
    }
}

/// Represents a PML4 Entry (PML4E) that references a Page-Directory-Pointer Table.
///
/// PML4 is the top level in the standard x86-64 paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
pub struct Pml4(Table);

/// Represents a Page-Directory-Pointer-Table Entry (PDPTE) that references a Page Directory.
///
/// PDPTEs are part of the second level in the standard x86-64 paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
pub struct Pdpt(Table);

/// Represents a Page-Directory Entry (PDE) that references a Page Table.
///
/// PDEs are part of the third level in the standard x86-64 paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents an EPT Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are part of the fourth level in the standard x86-64 paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
pub struct Pt(Table);

/*
/// Represents a Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are the lowest level in the standard x86-64 paging hierarchy and are used to map individual
/// pages to physical addresses.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
pub struct Pt(Table);
*/

/// General struct to represent a table in the standard paging structure.
///
/// This struct is used as a basis for PML4, PDPT, PD, and PT. It contains an array of entries
/// where each entry can represent different levels of the paging hierarchy.
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct Table {
    entries: [Entry; 512],
}

bitfield! {
    /// Represents a Page Table Entry in standard paging.
    ///
    /// These entries are used to manage memory access and address mapping.
    ///
    /// # Fields
    ///
    /// * `present` - If set, the memory region is accessible.
    /// * `writable` - If set, the memory region can be written to.
    /// * `large` - If set, this entry maps a large page.
    /// * `pfn` - The Page Frame Number, indicating the physical address.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;

    present, set_present: 0;
    writable, set_writable: 1;
    large, set_large: 7;
    pfn, set_pfn: 51, 12;
}
