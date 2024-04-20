//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
//!
//! Credits to the work by Satoshi (https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/epts.rs) and Matthias (https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/svm/nested_page_table.rs).

use {
    crate::{
        error::HypervisorError,
        intel::{
            invept::invept_all_contexts,
            invvpid::invvpid_all_contexts,
            mtrr::{MemoryType, Mtrr},
        },
    },
    bitfield::bitfield,
    core::ptr::addr_of,
    log::*,
    x86::bits64::paging::{
        pd_index, pdpt_index, pt_index, VAddr, BASE_PAGE_SHIFT, BASE_PAGE_SIZE, LARGE_PAGE_SIZE,
    },
};

/// Represents the entire Extended Page Table structure.
///
/// EPT is a set of nested page tables similar to the standard x86-64 paging mechanism.
/// It consists of 4 levels: PML4, PDPT, PD, and PT.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
#[repr(C, align(4096))]
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
    /// Builds an identity-mapped Extended Page Table (EPT) structure with considerations for Memory Type Range Registers (MTRR).
    /// This function initializes the EPT with a 1:1 physical-to-virtual memory mapping,
    /// setting up the required PML4, PDPT, and PD entries for the initial memory range.
    ///
    /// # Returns
    /// A result indicating the success or failure of the operation. In case of failure,
    /// a `HypervisorError` is returned, detailing the nature of the error.
    ///
    /// # Errors
    /// This function returns an `Err(HypervisorError::MemoryTypeResolutionError)` if it fails
    /// to resolve memory types based on MTRR settings for any page.
    pub fn build_identity(&mut self) -> Result<(), HypervisorError> {
        // Initialize a new MTRR instance for memory type resolution.
        let mut mtrr = Mtrr::new();
        trace!("{mtrr:#x?}");
        trace!("Initializing EPTs");

        // Start with a physical address (pa) of 0.
        let mut pa = 0u64;

        // Configure the first PML4 entry to point to the PDPT. This sets up the root of our page table.
        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);

        // Iterate through each PDPT entry to configure PDs.
        for (i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(addr_of!(self.pd[i]) as u64 >> BASE_PAGE_SHIFT);

            // Configure each PDE within a PD. The first PD manages the first 2MB with 4KB granularity.
            for pde in &mut self.pd[i].0.entries {
                if pa == 0 {
                    // Handle the special case for the first 2MB to ensure MTRR types are correctly applied.
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_pfn(addr_of!(self.pt) as u64 >> BASE_PAGE_SHIFT);

                    // Configure the PT entries for the first 2MB, respecting MTRR settings.
                    for pte in &mut self.pt.0.entries {
                        let memory_type = mtrr
                            .find(pa..pa + BASE_PAGE_SIZE as u64)
                            .ok_or(HypervisorError::MemoryTypeResolutionError)?;
                        pte.set_readable(true);
                        pte.set_writable(true);
                        pte.set_executable(true);
                        pte.set_memory_type(memory_type as u64);
                        pte.set_pfn(pa >> BASE_PAGE_SHIFT);
                        pa += BASE_PAGE_SIZE as u64;
                    }
                } else {
                    // For the rest of the physical address space, configure PD entries for large pages (2MB).
                    let memory_type = mtrr
                        .find(pa..pa + LARGE_PAGE_SIZE as u64)
                        .ok_or(HypervisorError::MemoryTypeResolutionError)?;

                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_memory_type(memory_type as u64);
                    pde.set_large(true);
                    pde.set_pfn(pa >> BASE_PAGE_SHIFT);
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }

        Ok(())
    }

    /// Splits a large 2MB page into 512 smaller 4KB pages for a given guest physical address.
    ///
    /// This is necessary to apply more granular hooks and reduce the number of
    /// page faults that occur when the guest tries to access a page that is hooked.
    ///
    /// # Arguments
    ///
    /// * `guest_pa`: The guest physical address within the 2MB page that needs to be split.
    /// * `pt`: The page table to use for the split operation.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn split_2mb_to_4kb(&mut self, guest_pa: u64, pt: &mut Pt) -> Result<(), HypervisorError> {
        trace!("Splitting 2mb page into 4kb pages: {:#x}", guest_pa);

        let guest_pa = VAddr::from(guest_pa);

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pde = &mut self.pd[pdpt_index].0.entries[pd_index];

        // We can only split large pages and not page directories.
        // If it's a page directory, it is already split.
        //
        if !pde.large() {
            trace!("Page is already split: {:x}.", guest_pa);
            return Err(HypervisorError::PageAlreadySplit);
        }

        // Get the memory type of the large page, before we unmap (reset) it.
        let memory_type = pde.memory_type();

        // Zero out the PD entry to ensure it's clean.
        *pde = Entry(0);

        trace!("Dumping EPT entries while splitting......");

        // Map the unmapped physical memory to 4KB pages.
        for (i, pte) in &mut pt.0.entries.iter_mut().enumerate() {
            // Zero out the PT entry to ensure it's clean.
            *pte = Entry(0);

            let pa = (guest_pa.as_usize() + i * BASE_PAGE_SIZE) as u64;
            pte.set_readable(true);
            pte.set_writable(true);
            pte.set_executable(true);
            pte.set_memory_type(memory_type);
            pte.set_pfn(pa >> BASE_PAGE_SHIFT);

            // trace!("PTE at index {}: {:#x?}", i, pte);
        }

        // Update the PDE to point to the new page table.
        pde.set_readable(true);
        pde.set_writable(true);
        pde.set_executable(true);
        pde.set_memory_type(0); // Table 29-6. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table: 6:3 Reserved (must be 0)
        pde.set_large(false); // This is no longer a large page.
        pde.set_pfn((pt as *mut _ as u64) >> BASE_PAGE_SHIFT);

        Ok(())
    }

    /// Modifies the access permissions for a page within the extended page table (EPT).
    ///
    /// This function adjusts the permissions of either a 2MB or a 4KB page based on its alignment.
    /// It is the responsibility of the caller to ensure that the `guest_pa` is aligned to the size
    /// of the page they intend to modify.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose permissions are to be changed.
    /// * `access_type` - The new access permissions to set for the page.
    /// * `pt` - The page table to modify. This is required to update 4KB pages.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn modify_page_permissions(
        &mut self,
        guest_pa: u64,
        access_type: AccessType,
        pt: &mut Pt,
    ) -> Result<(), HypervisorError> {
        trace!("Modifying permissions for GPA {:#x}", guest_pa);

        let guest_pa = VAddr::from(guest_pa);

        // Ensure the guest physical address is aligned to a page boundary.
        if !guest_pa.is_large_page_aligned() && !guest_pa.is_base_page_aligned() {
            error!("Page is not aligned: {:#x}", guest_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        let pde = &mut self.pd[pdpt_index].0.entries[pd_index];

        if pde.large() {
            trace!("Changing the permissions of a 2MB page");
            pde.set_readable(access_type.contains(AccessType::READ));
            pde.set_writable(access_type.contains(AccessType::WRITE));
            pde.set_executable(access_type.contains(AccessType::EXECUTE));
        } else {
            trace!("Changing the permissions of a 4KB page");
            let pte = &mut pt.0.entries[pt_index];
            pte.set_readable(access_type.contains(AccessType::READ));
            pte.set_writable(access_type.contains(AccessType::WRITE));
            pte.set_executable(access_type.contains(AccessType::EXECUTE));
        }

        Ok(())
    }

    /// Remaps a guest physical address to a new host physical address within the EPT.
    ///
    /// This function updates the EPT entry corresponding to the provided guest physical address (GPA)
    /// to map to the specified host physical address (HPA). It is designed to remap 4KB pages.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address that needs to be remapped.
    /// * `host_pa` - The new host physical address to map the guest physical address to.
    /// * `pt` - The page table to modify. This is required to update 4KB pages.
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` indicating if the operation was successful.
    /// On success, returns the old host physical address that was previously mapped to the guest physical address.
    /// In case of failure, a `HypervisorError` is returned, detailing the nature of the error.
    pub fn remap_gpa_to_hpa(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        pt: &mut Pt,
    ) -> Result<u64, HypervisorError> {
        trace!("Remapping GPA {:#x} to HPA {:#x}", guest_pa, host_pa);

        let guest_pa = VAddr::from(guest_pa);
        let host_pa = VAddr::from(host_pa);

        // Ensure both addresses are page aligned
        if !guest_pa.is_base_page_aligned() || !host_pa.is_base_page_aligned() {
            error!(
                "Addresses are not aligned: GPA {:#x}, HPA {:#x}",
                guest_pa, host_pa
            );
            return Err(HypervisorError::UnalignedAddressError);
        }

        // Calculate indexes for accessing the EPT hierarchy
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        let pde = &self.pd[pdpt_index].0.entries[pd_index];

        // Verify that we're not dealing with a large page mapping
        if pde.large() {
            error!("Cannot remap a large page: GPA {:#x}", guest_pa);
            return Err(HypervisorError::LargePageRemapError);
        }

        // Access the corresponding PT entry
        let pte = &mut pt.0.entries[pt_index];
        let old_hpa = pte.pfn() << BASE_PAGE_SHIFT; // Calculate the old HPA from the Page Frame Number

        // Update the PTE to point to the new HPA
        pte.set_pfn(host_pa >> BASE_PAGE_SHIFT);
        trace!(
            "Updated PTE for GPA {:#x} from old HPA {:#x} to new HPA {:#x}",
            guest_pa,
            old_hpa,
            host_pa
        );

        Ok(old_hpa)
    }

    pub fn dump_ept_entries(&self, guest_pa: u64, pt: &Pt) {
        let guest_pa = VAddr::from(guest_pa);
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        // Trace the PDPT entry to access the PD address
        let pdpte = &self.pdpt.0.entries[pdpt_index];
        trace!("PDPT at index {}: {:#x?}", pdpt_index, pdpte);

        // Calculate the physical address of the PD table
        let pd_address = pdpte.pfn() << BASE_PAGE_SHIFT;
        trace!("PD located at physical address: {:#x}", pd_address);

        // Access the PDE within the PD
        let pde = &self.pd[pdpt_index].0.entries[pd_index];
        trace!("PDE at index {}: {:#x?}", pd_index, pde);

        if pde.large() {
            trace!("This is a large page, no PT involved.");
        } else {
            // For non-large pages, calculate the physical address of the PT
            let pt_address = pde.pfn() << BASE_PAGE_SHIFT;
            trace!("PT located at physical address: {:#x}", pt_address);

            // Trace the PTE within the PT
            let pte = pt.0.entries[pt_index];
            trace!("PTE at index {}: {:#x?}", pt_index, pte);
        }
    }

    /// Updates the EPT mapping between a guest physical address and a specified host physical address,
    /// and modifies the page access permissions according to the provided type.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address to remap.
    /// * `host_pa` - The new host physical address to map to the guest physical address.
    /// * `access_type` - The access permissions to set for the mapped page.
    /// * `pt` - The page table to use for the remap operation.
    ///
    /// # Returns
    ///
    /// * `Result<(), HypervisorError>` - The result of the operation, `Ok` if successful, otherwise a `HypervisorError`.
    #[rustfmt::skip]
    pub fn swap_page(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType, pt: &mut Pt) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);
        let host_pa = VAddr::from(host_pa);

        // Ensure both addresses are page aligned
        if !guest_pa.is_base_page_aligned() || !host_pa.is_base_page_aligned() {
            error!("Addresses are not aligned: GPA {:#x}, HPA {:#x}", guest_pa, host_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        // Modify the permissions for the guest physical address.
        trace!("Modifying permissions for GPA {:#x} to {:?}", guest_pa, access_type);
        self.modify_page_permissions(guest_pa.as_u64(), access_type, pt)?;

        // Remap the guest physical address to the new host physical address in the primary EPT.
        trace!("Remapping GPA {:#x} to HPA {:#x} in the primary EPT", guest_pa, host_pa);
        self.remap_gpa_to_hpa(guest_pa.as_u64(), host_pa.as_u64(), pt)?;

        // Invalidate the EPT cache for all contexts.
        invept_all_contexts();

        // Invalidate the VPID cache for all contexts.
        invvpid_all_contexts();

        Ok(())
    }

    /// Creates an Extended Page Table Pointer (EPTP) with a Write-Back memory type and a 4-level page walk.
    ///
    /// This function is used in the setup of Intel VT-x virtualization, specifically for configuring the EPT.
    /// It encodes the provided physical base address of the EPT PML4 table into the EPTP format, setting
    /// the memory type to Write-Back and indicating a 4-level page walk.
    ///
    /// # Returns
    /// A `Result<u64, HypervisorError>` containing the configured EPTP value. Returns an error if
    /// the base address is not properly aligned.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 28.2.6 EPT Paging-Structure Entries
    pub fn create_eptp_with_wb_and_4lvl_walk(&self) -> Result<u64, HypervisorError> {
        // Get the virtual address of the PML4 table for EPT.
        let addr = addr_of!(self.pml4) as u64;

        // Get the physical address of the PML4 table for EPT.
        let ept_pml4_base_addr = addr;

        // Represents the EPT page walk length for Intel VT-x, specifically for a 4-level page walk.
        // The value is 3 (encoded as '3 << 3' in EPTP) because the EPTP encoding requires "number of levels minus one".
        const EPT_PAGE_WALK_LENGTH_4: u64 = 3 << 3;

        // Represents the memory type setting for Write-Back (WB) in the EPTP.
        const EPT_MEMORY_TYPE_WB: u64 = MemoryType::WriteBack as u64;

        // Check if the base address is 4KB aligned (the lower 12 bits should be zero).
        if ept_pml4_base_addr.trailing_zeros() >= 12 {
            // Construct the EPTP with the page walk length and memory type for WB.
            Ok(ept_pml4_base_addr | EPT_PAGE_WALK_LENGTH_4 | EPT_MEMORY_TYPE_WB)
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
#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

/// Represents an EPT Page-Directory-Pointer-Table Entry (PDPTE) that references an EPT Page Directory.
///
/// PDPTEs are part of the second level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

/// Represents an EPT Page-Directory Entry (PDE) that references an EPT Page Table.
///
/// PDEs are part of the third level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-5. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents an EPT Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are the lowest level in the EPT paging hierarchy and are used to map individual
/// pages to guest-physical addresses.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
#[derive(Debug, Clone, Copy)]
pub struct Pt(Table);

/// General struct to represent a table in the EPT paging structure.
///
/// This struct is used as a basis for PML4, PDPT, PD, and PT. It contains an array of entries
/// where each entry can represent different levels of the EPT hierarchy.
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
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
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;

    // Flag definitions for an EPT entry.
    pub readable, set_readable: 0;
    pub writable, set_writable: 1;
    pub executable, set_executable: 2;
    pub memory_type, set_memory_type: 5, 3;
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
    pub verify_guest_paging, set_verify_guest_paging: 57;
    pub paging_write_access, set_paging_write_access: 58;
}

bitflags::bitflags! {
    /// Represents the different access permissions for an EPT entry.
    #[derive(Debug, Clone, Copy)]
    pub struct AccessType: u8 {
        /// The EPT entry allows read access.
        const READ = 0b001;
        /// The EPT entry allows write access.
        const WRITE = 0b010;
        /// The EPT entry allows execute access.
        const EXECUTE = 0b100;
        /// The EPT entry allows read and write access.
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        /// The EPT entry allows read and execute access.
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
        /// The EPT entry allows write and execute access.
        const WRITE_EXECUTE = Self::WRITE.bits() | Self::EXECUTE.bits();
        /// The EPT entry allows read, write, and execute access.
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}
