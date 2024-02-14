//! This module provides utilities and structures to manage segment descriptors
//! in the GDT (Global Descriptor Table) and LDT (Local Descriptor Table).
//! It handles the extraction, representation, and manipulation of segment descriptors.
//!
//! Credits to rCore OS for providing an accessible and comprehensible implementation of segmentation:
//! https://github.com/rcore-os/RVM1.5/blob/main/src/arch/x86_64/segmentation.rs

use {
    crate::intel::descriptor::DescriptorTables,
    bit_field::BitField,
    bitflags::bitflags,
    x86::{dtables::DescriptorTablePointer, segmentation::SegmentSelector},
    x86_64::structures::gdt::DescriptorFlags,
};

bitflags! {
    /// Access rights for VMCS guest register states.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.4.1 Guest Register State
    /// and Table 24-2. Format of Access Rights.
    pub struct SegmentAccessRights: u32 {
        /// Accessed flag.
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const ACCESSED = 1 << 0;

        /// Readable (for code segments) or Writable (for data segments).
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const RW = 1 << 1;

        /// Conforming bit for code segments.
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const CONFORMING = 1 << 2;

        /// Executable bit. Must be set for code segments.
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const EXECUTABLE = 1 << 3;

        /// Descriptor type (0 = system; 1 = code or data).
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const CODE_DATA = 1 << 4;

        /// Segment present.
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const PRESENT = 1 << 7;

        /// Long mode active (for CS only).
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const LONG_MODE = 1 << 13;

        /// Default operation size (0 = 16-bit segment; 1 = 32-bit segment).
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const DB = 1 << 14;

        /// Granularity.
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const GRANULARITY = 1 << 15;

        /// Segment unusable (0 = usable; 1 = unusable).
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.4.1 Guest Register State
        const UNUSABLE = 1 << 16;

        /// Privilege level mask (bits 5-6).
        /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const DPL_MASK = 3 << 5;
    }
}

impl SegmentAccessRights {
    /// Constructs `SegmentAccessRights` from a segment descriptor.
    ///
    /// The access rights are extracted from bits 40-55 of the segment descriptor.
    /// Only bits 8-15 and 0-7 within this range are directly related to access rights.
    ///
    /// # Arguments
    ///
    /// * `desc` - The segment descriptor from which to extract access rights.
    ///
    /// # Returns
    ///
    /// A `SegmentAccessRights` instance representing the extracted access rights.
    pub fn from_descriptor(desc: u64) -> Self {
        // Extract bits 40-55 from the descriptor
        let access_bits = desc.get_bits(40..56) as u32;

        // Mask out the unwanted bits to get only the relevant access rights
        let relevant_bits = access_bits & 0xf0ff;

        Self::from_bits_truncate(relevant_bits)
    }
}

/// Represents the details of a segment descriptor in the GDT or LDT.
/// Segment descriptors are used to define the characteristics of a segment.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
/// and Figure 3-8. Segment Descriptor
#[repr(C, align(16))]
pub struct SegmentDescriptor {
    /// Selector provides an index into the GDT or LDT, pointing to the segment descriptor.
    pub selector: SegmentSelector,
    /// The starting address of the segment.
    pub base_address: u64,
    /// The size of the segment. The ending address is calculated as base_address + segment_limit.
    pub segment_limit: u32,
    /// Flags detailing the properties of the segment.
    pub access_rights: SegmentAccessRights,
}

impl SegmentDescriptor {
    /// Returns an invalid `SegmentDescriptor`.
    /// This is useful to represent a non-present or non-configured segment.
    pub const fn invalid() -> Self {
        Self {
            selector: SegmentSelector::empty(),
            base_address: 0,
            segment_limit: 0,
            access_rights: SegmentAccessRights::UNUSABLE,
        }
    }

    /// Constructs a `SegmentDescriptor` from a given segment selector and a pointer to the GDT.
    ///
    /// The method uses the segment selector to index into the GDT and retrieve the associated segment descriptor.
    /// It then extracts the base address, segment limit, and access rights from the descriptor.
    ///
    /// # Arguments
    ///
    /// * `selector` - A segment selector that provides an index into the GDT.
    /// * `gdtr` - A pointer to the GDT.
    pub fn from_selector(selector: SegmentSelector, gdtr: &DescriptorTablePointer<u64>) -> Self {
        // Index into the GDT using the selector's index value.
        let index = selector.index() as usize;
        let table = DescriptorTables::from_pointer(gdtr);

        // Fetch the descriptor entry from the GDT.
        let entry_value = table[index];

        // Convert the entry value into descriptor flags.
        let entry = DescriptorFlags::from_bits_truncate(entry_value);

        // If the segment is present in memory, extract its properties.
        if entry.contains(DescriptorFlags::PRESENT) {
            // Extract base address from the descriptor.
            let base_low = entry_value.get_bits(16..40);
            let base_high = entry_value.get_bits(56..64) << 24;
            let mut base_address = base_low | base_high;

            // Extract segment limit from the descriptor.
            let segment_limit_low = entry_value.get_bits(0..16);
            let segment_limit_high = entry_value.get_bits(48..52) << 12;
            let mut segment_limit = segment_limit_low | segment_limit_high;

            // For non-user segments (like TSS), the base address can span two GDT entries.
            // If this is the case, fetch the high 32 bits of the base address from the next GDT entry.
            if !entry.contains(DescriptorFlags::USER_SEGMENT) {
                let high = table[index + 1];
                base_address += high << 32;
            }

            // If the granularity flag is set, the segment limit is scaled by a factor of 4096.
            if entry.contains(DescriptorFlags::GRANULARITY) {
                segment_limit = (segment_limit << 12) | 0xfff;
            }

            // Construct and return the `SegmentDescriptor`.
            Self {
                selector,
                base_address,
                segment_limit: segment_limit as _,
                access_rights: SegmentAccessRights::from_descriptor(entry_value),
            }
        } else {
            // If the segment is not present, return an invalid descriptor.
            Self::invalid()
        }
    }
}