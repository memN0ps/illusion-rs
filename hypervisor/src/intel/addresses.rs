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

    /// Converts a guest virtual address to a host physical address using a provided CR3.
    ///
    /// This function encapsulates the logic for converting a virtual address to a physical address based on a
    /// specific CR3 value. It is used internally by other functions to avoid code duplication.
    ///
    /// # Arguments
    ///
    /// * `va` - The guest virtual address to translate.
    /// * `guest_cr3` - The CR3 value to use for translation.
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the physical address on success, or an error if the translation fails.
    fn pa_from_va(va: u64, guest_cr3: u64) -> Result<u64, HypervisorError> {
        trace!("Guest CR3: {:#x}", guest_cr3);

        // Translate the guest virtual address (VA) to a guest physical address (PA).
        let guest_pa = unsafe { PageTables::translate_guest_virtual_to_guest_physical(guest_cr3, va)? };
        trace!("Guest VA: {:#x} -> Guest PA: {:#x}", va, guest_pa);

        // Translate the guest physical address (GPA) to a host physical address (HPA) using the Extended Page Table (EPT).
        // In a 1:1 mapping, the guest physical address is the same as the host physical address.
        // This translation is performed to handle cases where paging/EPT changes occur.
        let vmcs_eptp = vmread(vmcs::control::EPTP_FULL);
        trace!("VMCS EPTP: {:#x}", vmcs_eptp);

        let (pml4_address, _, _) = Ept::decode_eptp(vmcs_eptp)?;
        trace!("EPT PML4 Address: {:#x}", pml4_address);

        // Convert the guest physical address to the host physical address.
        let host_pa = unsafe { Ept::translate_guest_pa_to_host_pa(pml4_address, guest_pa)? };
        trace!("Guest PA: {:#x} -> Host PA: {:#x}", guest_pa, host_pa);

        Ok(host_pa)
    }

    /// Converts a guest virtual address to a host physical address using the current guest CR3.
    ///
    /// This function reads the current CR3 value from the VMCS and uses it to translate the guest virtual address to a physical address.
    ///
    /// # Arguments
    ///
    /// * `va` - The guest virtual address to translate.
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the physical address on success, or an error if the translation fails.
    pub fn pa_from_va_with_current_cr3(va: u64) -> Result<u64, HypervisorError> {
        let guest_cr3 = vmread(vmcs::guest::CR3);
        Self::pa_from_va(va, guest_cr3)
    }

    /// Converts a guest virtual address to a host physical address using a specified guest CR3.
    ///
    /// This function accepts a CR3 value explicitly provided by the caller and uses it to translate
    /// the guest virtual address to a physical address.
    ///
    /// # Arguments
    ///
    /// * `va` - The guest virtual address to translate.
    /// * `guest_cr3` - The CR3 value to use for translation.
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the physical address on success, or an error if the translation fails.
    pub fn pa_from_va_with_explicit_cr3(va: u64, guest_cr3: u64) -> Result<u64, HypervisorError> {
        Self::pa_from_va(va, guest_cr3)
    }

    /// Reads a value from a guest virtual address using the current guest CR3.
    ///
    /// This function reads from the guest virtual address using the current CR3 value from the VMCS.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to read from.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<T, HypervisorError>` containing the read value on success, or an error if the read fails.
    pub fn read_guest_virt_with_current_cr3<T: Sized>(ptr: *const T) -> Option<T> {
        let phys_addr = PhysicalAddress::pa_from_va_with_current_cr3(ptr as u64).ok()? as *const T;
        Some(unsafe { phys_addr.read() })
    }

    /// Reads a value from a guest virtual address using a specified guest CR3.
    ///
    /// This function reads from the guest virtual address using a CR3 value provided by the caller.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to read from.
    /// * `guest_cr3` - The CR3 value to use for translation.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<T, HypervisorError>` containing the read value on success, or an error if the read fails.
    pub fn read_guest_virt_with_explicit_cr3<T: Sized>(ptr: *const T, guest_cr3: u64) -> Option<T> {
        let phys_addr = PhysicalAddress::pa_from_va_with_explicit_cr3(ptr as u64, guest_cr3).ok()? as *const T;
        Some(unsafe { phys_addr.read() })
    }

    /// Reads a slice of guest memory using the current guest CR3.
    ///
    /// This function reads from the guest virtual address using the current CR3 value from the VMCS.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to start reading from.
    /// * `len` - The number of elements to read.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<&[T], HypervisorError>` containing the borrowed slice on success, or an error if the read fails.
    pub fn read_guest_slice_with_current_cr3<'a, T: Sized>(ptr: *const T, len: usize) -> Option<&'a [T]> {
        let phys_addr = PhysicalAddress::pa_from_va_with_current_cr3(ptr as u64).ok()? as *const T;
        Some(unsafe { core::slice::from_raw_parts(phys_addr, len) })
    }

    /// Reads a slice of guest memory using a specified guest CR3.
    ///
    /// This function reads from the guest virtual address using a CR3 value provided by the caller.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to start reading from.
    /// * `len` - The number of elements to read.
    /// * `guest_cr3` - The CR3 value to use for translation.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<&[T], HypervisorError>` containing the borrowed slice on success, or an error if the read fails.
    pub fn read_guest_slice_with_explicit_cr3<'a, T: Sized>(ptr: *const T, len: usize, guest_cr3: u64) -> Option<&'a [T]> {
        let phys_addr = PhysicalAddress::pa_from_va_with_explicit_cr3(ptr as u64, guest_cr3).ok()? as *const T;
        Some(unsafe { core::slice::from_raw_parts(phys_addr, len) })
    }

    /// Writes a value to a guest virtual address using the current guest CR3.
    ///
    /// This function writes to the guest virtual address using the current CR3 value from the VMCS.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to write to.
    /// * `value` - The value to write.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating success or failure.
    pub fn write_guest_virt_with_current_cr3<T: Sized>(ptr: *mut T, value: T) -> Option<()> {
        let phys_addr = PhysicalAddress::pa_from_va_with_current_cr3(ptr as u64).ok()? as *mut T;
        unsafe {
            phys_addr.write(value);
        }
        Some(())
    }

    /// Writes a value to a guest virtual address using a specified guest CR3.
    ///
    /// This function writes to the guest virtual address using a CR3 value provided by the caller.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to write to.
    /// * `value` - The value to write.
    /// * `guest_cr3` - The CR3 value to use for translation.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating success or failure.
    pub fn write_guest_virt_with_explicit_cr3<T: Sized>(ptr: *mut T, value: T, guest_cr3: u64) -> Option<()> {
        let phys_addr = PhysicalAddress::pa_from_va_with_explicit_cr3(ptr as u64, guest_cr3).ok()? as *mut T;
        unsafe {
            phys_addr.write(value);
        }
        Some(())
    }

    /// Writes a slice of data to guest memory using the current guest CR3.
    ///
    /// This function writes to the guest virtual address using the current CR3 value from the VMCS.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to start writing to.
    /// * `data` - The slice of data to write.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating success or failure.
    pub fn write_guest_slice_with_current_cr3<T: Sized>(ptr: *mut T, data: &[T]) -> Option<()> {
        let phys_addr = PhysicalAddress::pa_from_va_with_current_cr3(ptr as u64).ok()? as *mut T;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), phys_addr, data.len());
        }
        Some(())
    }

    /// Writes a slice of data to guest memory using a specified guest CR3.
    ///
    /// This function writes to the guest virtual address using a CR3 value provided by the caller.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The guest virtual address to start writing to.
    /// * `data` - The slice of data to write.
    /// * `guest_cr3` - The CR3 value to use for translation.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it involves raw memory access and relies on the integrity of the VMCS.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating success or failure.
    pub fn write_guest_slice_with_explicit_cr3<T: Sized>(ptr: *mut T, data: &[T], guest_cr3: u64) -> Option<()> {
        let phys_addr = PhysicalAddress::pa_from_va_with_explicit_cr3(ptr as u64, guest_cr3).ok()? as *mut T;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), phys_addr, data.len());
        }
        Some(())
    }
}
