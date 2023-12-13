//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.

use {
    crate::{error::HypervisorError, intel::ept::mtrr::Mtrr},
    bitfield::bitfield,
    core::ptr::addr_of,
    x86::current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE},
};

pub mod mtrr;

pub const PAGE_SIZE: usize = 0x1000;

/// Represents the entire Extended Page Table structure.
///
/// EPT is a set of nested page tables similar to the standard x86-64 paging mechanism.
/// It consists of 4 levels: PML4, PDPT, PD, and PT.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct Ept {
    /// Page Map Level 4 (PML4) Table.
    pml4: Pml4,
    /// Page Directory Pointer Table (PDPT).
    pdpt: Pdpt,
    /// Array of Page Directory Table (PDT).
    pd: [Pd; 512],
    /// Page Table (PT).
    pt: Pt,
}

impl Ept {
    /// Builds an identity map for the Extended Page Table (EPT).
    ///
    /// This method sets up the EPT such that each guest-physical address
    /// maps directly to the same host-physical address. It also configures
    /// memory types based on the current MTRR (Memory Type Range Register) settings.
    ///
    /// # Returns
    /// A `Result<(), HypervisorError>` indicating whether the identity map was built successfully.
    pub fn build_identity_map(&mut self) -> Result<(), HypervisorError> {
        log::info!("Building identity map for EPT");
        // Retrieve the current MTRR settings.
        // This map is used to determine memory types for each physical address.
        let mtrr_map = Mtrr::build_mtrr_map();

        // Initialize the physical address to start mapping from.
        let mut pa = 0u64;

        // Configure the first PML4 entry.
        // The PML4 is the top-level structure in the paging hierarchy.
        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);

        // Iterate over all PDPT entries to configure them.
        for (i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            // Configure the PDPT entry.
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(addr_of!(self.pd[i]) as u64 >> BASE_PAGE_SHIFT);

            // Configure each PDE within the current PD.
            for pde in &mut self.pd[i].0.entries {
                if pa == 0 {
                    // Special handling for the first PDE.
                    // This is typically where the first PT is set up.
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_pfn(addr_of!(self.pt) as u64 >> BASE_PAGE_SHIFT);

                    // Iterate over all PTEs within the first PT.
                    for pte in &mut self.pt.0.entries {
                        // Determine the memory type for the current address.
                        let memory_type = Mtrr::find(&mtrr_map, pa..pa + PAGE_SIZE as u64)
                            .ok_or(HypervisorError::MemoryTypeResolutionError)?;

                        // Configure the PTE.
                        pte.set_readable(true);
                        pte.set_writable(true);
                        pte.set_executable(true);
                        pte.set_memory_type(memory_type as u64);
                        pte.set_pfn(pa >> BASE_PAGE_SHIFT);

                        // Move to the next page.
                        pa += PAGE_SIZE as u64;
                    }
                } else {
                    // Handling for subsequent PDEs.
                    // Configure large pages if used.
                    let memory_type = Mtrr::find(&mtrr_map, pa..pa + LARGE_PAGE_SIZE as u64)
                        .ok_or(HypervisorError::MemoryTypeResolutionError)?;

                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_memory_type(memory_type as u64);
                    pde.set_large(true);
                    pde.set_pfn(pa >> BASE_PAGE_SHIFT);

                    // Move to the next large page.
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }

        log::info!("Identity map for EPT built successfully!");

        Ok(())
    }

    /// Creates an Extended Page Table Pointer (EPTP) with a Write-Back memory type and a 4-level page walk.
    ///
    /// This function is used in the setup of Intel VT-x virtualization, specifically for configuring the EPT.
    /// It encodes the provided physical base address of the EPT PML4 table into the EPTP format, setting
    /// the memory type to Write-Back and indicating a 4-level page walk.
    ///
    /// # Arguments
    /// * `ept_pml4_base_addr` - The physical base address of the EPT PML4 table. This address must be 4KB aligned.
    ///
    /// # Returns
    /// A `Result<u64, HypervisorError>` containing the configured EPTP value. Returns an error if
    /// the base address is not properly aligned.
    pub fn create_eptp_with_wb_and_4lvl_walk(
        ept_pml4_base_addr: u64,
    ) -> Result<u64, HypervisorError> {
        // Represents the EPT page walk length for Intel VT-x, specifically for a 4-level page walk.
        // The value is 3 (encoded as '3 << 3' in EPTP) because the EPTP encoding requires "number of levels minus one".
        const EPT_PAGE_WALK_LENGTH_4: u64 = 3 << 3;

        // Check if the base address is 4KB aligned (the lower 12 bits should be zero).
        if ept_pml4_base_addr.trailing_zeros() >= 12 {
            Ok(ept_pml4_base_addr | EPT_PAGE_WALK_LENGTH_4 | Mtrr::WriteBack as u64)
        } else {
            Err(HypervisorError::InvalidEptPml4BaseAddress)
        }
    }
}

/// Represents an EPT PML4 Entry (PML4E) that references a Page-Directory-Pointer Table.
///
/// PML4 is the top level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-1. Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

/// Represents an EPT Page-Directory-Pointer-Table Entry (PDPTE) that references an EPT Page Directory.
///
/// PDPTEs are part of the second level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

/// Represents an EPT Page-Directory Entry (PDE) that references an EPT Page Table.
///
/// PDEs are part of the third level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-5. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents an EPT Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are the lowest level in the EPT paging hierarchy and are used to map individual
/// pages to guest-physical addresses.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Pt(Table);

/// General struct to represent a table in the EPT paging structure.
///
/// This struct is used as a basis for PML4, PDPT, PD, and PT. It contains an array of entries
/// where each entry can represent different levels of the EPT hierarchy.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct Table {
    entries: [Entry; 512],
}

bitfield! {
    /// Represents an Extended Page Table Entry (EPT Entry).
    ///
    /// EPT entries are used in Intel VT-x virtualization to manage memory access
    /// permissions and address mapping for virtual machines.
    ///
    /// # Fields
    ///
    /// * `readable` - If set, the memory region can be read.
    /// * `writable` - If set, the memory region can be written to.
    /// * `executable` - If set, code can be executed from the memory region.
    /// * `memory_type` - The memory type (e.g., WriteBack, Uncacheable).
    /// * `large` - If set, this entry maps a large page.
    /// * `pfn` - The Page Frame Number, indicating the physical address.
    /// * `verify_guest_paging` - Additional flag for guest paging verification.
    /// * `paging_write_access` - Additional flag for paging write access.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
    #[repr(C, align(4096))]
    #[derive(Clone, Copy, Default)]
    pub struct Entry(u64);
    impl Debug;

    // Flag definitions for an EPT entry.
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    memory_type, set_memory_type: 5, 3;
    large, set_large: 7;
    pfn, set_pfn: 51, 12;
    verify_guest_paging, set_verify_guest_paging: 57;
    paging_write_access, set_paging_write_access: 58;
}
