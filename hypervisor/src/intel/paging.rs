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
    x86::current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE},
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
            pdpte.set_pfn(
                addr_of!(self.pd[i]) as u64 >> BASE_PAGE_SHIFT,
            );

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
struct Pml4(Table);

/// Represents a Page-Directory-Pointer-Table Entry (PDPTE) that references a Page Directory.
///
/// PDPTEs are part of the second level in the standard x86-64 paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

/// Represents a Page-Directory Entry (PDE) that references a Page Table.
///
/// PDEs are part of the third level in the standard x86-64 paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents a Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are the lowest level in the standard x86-64 paging hierarchy and are used to map individual
/// pages to physical addresses.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.5 Paging
#[derive(Debug, Clone, Copy)]
struct Pt(Table);

/// General struct to represent a table in the standard paging structure.
///
/// This struct is used as a basis for PML4, PDPT, PD, and PT. It contains an array of entries
/// where each entry can represent different levels of the paging hierarchy.
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Table {
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