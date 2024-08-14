//! Abstraction over physical addresses with utility functions for address conversion.
//!
//! This module introduces the `PhysicalAddress` structure that simplifies operations around
//! physical addresses. It provides conversions between virtual addresses (VAs) and physical addresses (PAs),
//! as well as methods for extracting page frame numbers (PFNs) and other address-related information.

use {
    crate::{
        error::HypervisorError,
        intel::{ept::Ept, paging::PageTables, support::vmread},
    },
    log::trace,
    x86::{
        bits64::paging::{PAddr, BASE_PAGE_SHIFT},
        vmx::vmcs,
    },
};

/// A representation of physical addresses.
///
/// Provides utility methods to work with physical addresses,
/// including conversions between physical and virtual addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalAddress(PAddr);

impl PhysicalAddress {
    /// Constructs a `PhysicalAddress` from a given physical address.
    pub fn from_pa(pa: u64) -> Self {
        Self(PAddr::from(pa))
    }

    /// Constructs a `PhysicalAddress` from a given virtual address.
    pub fn from_va(va: u64) -> Result<Self, HypervisorError> {
        Ok(Self(PAddr::from(Self::pa_from_va(va)?)))
    }

    /// Constructs a `PhysicalAddress` from a given page frame number (PFN).
    pub fn from_pfn(pfn: u64) -> Self {
        Self(PAddr::from(pfn << BASE_PAGE_SHIFT))
    }

    /// Retrieves the page frame number (PFN) for the physical address.
    pub fn pfn(&self) -> u64 {
        self.0.as_u64() >> BASE_PAGE_SHIFT
    }

    /// Retrieves the physical address.
    pub fn pa(&self) -> u64 {
        self.0.as_u64()
    }

    /// Converts a guest virtual address to its corresponding host physical address.
    ///
    /// This function first translates the guest virtual address to a guest physical address
    /// using the guest's CR3. It then translates the guest physical address to a host physical
    /// address using the EPT (Extended Page Table).
    ///
    /// # Arguments
    ///
    /// * `va` - The guest virtual address to translate.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity
    /// of the VMCS (Virtual Machine Control Structure).
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the host physical address on success, or an error if the translation fails.
    pub fn pa_from_va(va: u64) -> Result<u64, HypervisorError> {
        let guest_cr3 = vmread(vmcs::guest::CR3);
        trace!("Guest CR3: {:#x}", guest_cr3);

        let guest_pa = unsafe { PageTables::translate_guest_virtual_to_guest_physical(guest_cr3, va)? };
        trace!("Guest VA: {:#x} -> Guest PA: {:#x}", va, guest_pa);

        // Translate guest physical address (GPA) to host physical address (HPA) using Extended Page Tables (EPT)
        // In a 1:1 mapping, the guest physical address is the same as the host physical address.
        // This translation is not required in a 1:1 mapping but is done for demonstration purposes
        // and in case changes are made to the Paging/EPT.
        let vmcs_eptp = vmread(vmcs::control::EPTP_FULL);
        trace!("VMCS EPTP: {:#x}", vmcs_eptp);

        let (pml4_address, _, _) = Ept::decode_eptp(vmcs_eptp)?;
        trace!("EPT PML4 Address: {:#x}", pml4_address);

        // Note: This may cause a crash at `!pt_entry.readable()` because the hypervisor has pre-allocated page tables
        // in the hook_manager that are not passed to this function. We're attempting to translate a guest physical address to a host physical address using the EPT.
        // The hypervisor maps everything as 2MB pages. The hooked pages are split and stored in the pre-allocated Pt,
        // which are usually passed as a parameter, those are not stored in the EPT structure.
        // This translation is not required in a 1:1 mapping but is done for demonstration purposes and in case changes are made to the Paging/EPT.
        let host_pa = unsafe { Ept::translate_guest_pa_to_host_pa(pml4_address, guest_pa)? };
        trace!("Guest PA: {:#x} -> Host PA: {:#x}", guest_pa, host_pa);

        Ok(guest_pa)
    }

    /// Converts a guest virtual address to its corresponding host physical address.
    ///
    /// This function first translates the guest virtual address to a guest physical address
    /// using the guest's CR3. It then translates the guest physical address to a host physical address using the EPT (Extended Page Table).
    ///
    /// # Arguments
    ///
    /// * `va` - The guest virtual address to translate.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS (Virtual Machine Control Structure).
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the host physical address on success, or an error if the translation fails.
    pub fn read_guest_virt<T: Sized>(ptr: *const T) -> Option<T> {
        let phys_addr = PhysicalAddress::pa_from_va(ptr as u64).ok()? as *const T;
        Some(unsafe { phys_addr.read() })
    }

    /// Reads a slice of guest memory.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to start reading from.
    /// * `len` - The number of elements to read.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS (Virtual Machine Control Structure).
    ///
    /// # Returns
    ///
    /// A `Result<&[T], HypervisorError>` containing the borrowed slice on success, or an error if the read fails.
    pub fn read_guest_slice<'a, T: Sized>(ptr: *const T, len: usize) -> Option<&'a [T]> {
        // Translate the guest virtual address to a host physical address
        let phys_addr = PhysicalAddress::pa_from_va(ptr as u64).ok()? as *const T;

        // Safety: Create a slice from the translated physical address and length.
        // The caller must ensure that the address and length are valid.
        Some(unsafe { core::slice::from_raw_parts(phys_addr, len) })
    }
}
