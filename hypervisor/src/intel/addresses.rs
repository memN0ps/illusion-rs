//! Abstraction over physical addresses with utility functions for address conversion.
//!
//! This module introduces the `PhysicalAddress` structure that simplifies operations around
//! physical addresses. It provides conversions between virtual addresses (VAs) and physical addresses (PAs),
//! as well as methods for extracting page frame numbers (PFNs) and other address-related information.

use {
    crate::intel::paging::PageTables,
    x86::bits64::paging::{PAddr, BASE_PAGE_SHIFT},
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

    /// Constructs a `PhysicalAddress` from a given virtual address.
    pub fn from_va(va: u64) -> Self {
        Self(PAddr::from(Self::pa_from_va(va)))
    }

    /// Retrieves the page frame number (PFN) for the physical address.
    pub fn pfn(&self) -> u64 {
        self.0.as_u64() >> BASE_PAGE_SHIFT
    }

    /// Retrieves the physical address.
    pub fn pa(&self) -> u64 {
        self.0.as_u64()
    }

    /// Converts a virtual address to its corresponding physical address.
    pub fn pa_from_va(va: u64) -> u64 {
        let guest_cr3 = PageTables::get_guest_cr3();
        PageTables::translate_guest_virtual_to_physical(guest_cr3 as usize, va as _).unwrap() as u64
    }

    /// Reads a value of a specified type from guest memory at the provided virtual address, ensuring safety by internal validation.
    ///
    /// # Arguments
    ///
    /// * `guest_cr3` - The base address of the guest's page table hierarchy.
    /// * `guest_va` - The guest virtual address from which to read.
    ///
    /// # Returns
    ///
    /// * Returns an `Option<T>` which is `Some(value)` if the read is successful and safe, or `None` if the address cannot be translated or if safety conditions are not met.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of the value to read. This can be any type that implements the `Copy` trait and has a size that can be read atomically.
    ///
    /// # Credits
    /// Credits to Jessie (jessiep_) for the initial concept.
    pub fn read_guest_memory<T: Copy>(guest_cr3: usize, guest_va: usize) -> Option<T> {
        // Safety justification:
        // The translation function ensures that the physical address is valid and maps to a real physical memory location.
        // The dereference is only performed if the translation succeeds, and it's constrained to types that are Copy, implying they can be safely duplicated and do not manage resources that require manual cleanup.
        // Still, the caller must ensure that reading from this specific address does not violate any safety contracts.
        let pa = PageTables::translate_guest_virtual_to_physical(guest_cr3, guest_va)?;
        unsafe { Some(*(pa as *const T)) }
    }
}

/// Converts a virtual address to its corresponding physical address.
///
/// # Arguments
///
/// * `ptr` - The virtual address to convert.
pub fn physical_address(ptr: *const u64) -> PAddr {
    PhysicalAddress::from_va(ptr as u64).0
}
