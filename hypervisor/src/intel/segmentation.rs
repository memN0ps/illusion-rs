//! Utilities for VMX segment selectors and access rights.
//!
//! Includes functions to handle segment selectors and access rights for VMX. Essential for
//! virtual machine setup and control in a virtualized environment. Focuses on segment state
//! management, aligning with VMX requirements.
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/vm.rs

use {
    bitfield::bitfield,
    core::arch::asm,
    x86::{bits64::rflags::RFlags, segmentation::SegmentSelector},
};

/// Converts native segment access rights to VMX format.
///
/// Transforms the native access rights format used by the processor into the format expected by VMX for segment access rights. If the input is 0, indicating an unusable segment, it sets the corresponding VMX unusable flag.
///
/// # Arguments
///
/// - `access_rights`: The native access rights value to be converted.
///
/// # Returns
///
/// Returns the access rights in VMX format, with the unusable segment flag set if applicable.
pub fn access_rights_from_native(access_rights: u32) -> u32 {
    const VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG: u32 = 1 << 16;

    if access_rights == 0 {
        return VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG;
    }

    (access_rights >> 8) & 0b1111_0000_1111_1111
}

/// Retrieves the segment limit using the LSL (Load Segment Limit) instruction.
///
/// Executes the LSL instruction to obtain the segment limit for a given segment selector.
/// The segment limit is then returned, which specifies the maximum offset that can be accessed in the segment.
///
/// # Arguments
///
/// - `selector`: The segment selector for which the segment limit is requested.
///
/// # Returns
///
/// Returns the segment limit as a 32-bit unsigned integer.
///
/// # Safety
///
/// This function is `unsafe` because it directly interacts with processor state via inline assembly and assumes the selector is valid.
///
/// # Panics
///
/// Panics if the Zero Flag (ZF) is not set, indicating an unsuccessful LSL instruction, possibly due to an invalid selector.
pub fn lsl(selector: SegmentSelector) -> u32 {
    let flags: u64;
    let mut limit: u64;
    unsafe {
        asm!(
        "lsl {}, {}",
        "pushfq",
        "pop {}",
        out(reg) limit,
        in(reg) u64::from(selector.bits()),
        lateout(reg) flags
        );
    };
    assert!(RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF));
    limit as u32
}

/// LAR-Load Access Rights Byte
pub fn lar(selector: SegmentSelector) -> u32 {
    let flags: u64;
    let mut access_rights: u64;
    unsafe {
        asm!(
        "lar {}, {}",
        "pushfq",
        "pop {}",
        out(reg) access_rights,
        in(reg) u64::from(selector.bits()),
        lateout(reg) flags
        );
    };
    assert!(RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF));
    access_rights as u32
}

bitfield! {
    /// Represents the VMX Segment Access Rights, as detailed in Intel's Software Developer's Manual,
    /// specifically in Section 25.4.1 Guest Register State.
    ///
    /// This struct encapsulates the access rights associated with a segment selector in a VMX operation,
    /// which includes properties such as the segment type, privilege level, and presence. These rights are
    /// crucial for the proper setup and control of guest and host segments in virtualization environments.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual.
    #[derive(Clone, Copy)]
    pub struct VmxSegmentAccessRights(u32);
    impl Debug;

    /// Extracts or sets the segment type (bits 3:0). This field specifies the type of segment or gate descriptor,
    /// including data, code, system segments, etc. The exact meaning of these bits varies based on the descriptor
    /// type (system, code, or data).
    pub segment_type, set_segment_type: 3, 0;

    /// Indicates the descriptor type (bit 4). A value of 0 signifies a system descriptor (like LDT or TSS),
    /// while 1 signifies a code or data descriptor. This distinction affects the interpretation of other fields
    /// in the descriptor.
    pub descriptor_type, set_descriptor_type: 4;

    /// Represents the Descriptor Privilege Level (DPL, bits 6:5). This specifies the privilege level of the segment,
    /// ranging from 0 (highest privilege, kernel) to 3 (lowest privilege, user applications).
    pub descriptor_privilege_level, set_descriptor_privilege_level: 6, 5;

    /// Indicates whether the segment is present (bit 7). If this bit is cleared, any attempt to access the segment
    /// results in a segment not present exception (#NP). This bit is used to control loading of segments that
    /// might not be currently available in memory.
    pub present, set_present: 7;

    /// Reserved bits (11:8). These bits are reserved and should not be modified. They are present for alignment
    /// and future compatibility.

    /// Available for use by system software (bit 12). This bit is available for use by system software and does not
    /// have a defined meaning in the VMX operation. It can be used by hypervisors to store additional information.
    pub available, set_available: 12;

    /// Indicates 64-bit mode active (for CS only, bit 13). For the CS segment, setting this bit indicates that
    /// the segment is running in 64-bit mode (long mode). This bit is ignored for other segment types.
    pub long_mode, set_long_mode: 13;

    /// Default operation size (D/B, bit 14). For code segments, this bit controls the default operation size
    /// (0 for 16-bit, 1 for 32-bit). For stack segments (SS), it controls the stack pointer size.
    pub default_big, set_default_big: 14;

    /// Granularity (bit 15). When set, the segment limit is scaled by 4K, allowing for larger segments.
    /// This bit is used in conjunction with the segment limit field to determine the actual size of the segment.
    pub granularity, set_granularity: 15;

    /// Indicates if the segment is unusable (bit 16). If set, the segment cannot be used for memory access.
    /// An unusable segment is typically one that has been loaded with a null selector.
    pub unusable, set_unusable: 16;

    // Reserved bits (31:17). These bits are reserved for future use and should always be cleared to ensure
    // compatibility with future processors.
}
