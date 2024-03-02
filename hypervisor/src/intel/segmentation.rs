//! Utilities for VMX segment selectors and access rights.
//!
//! Includes functions to handle segment selectors and access rights for VMX. Essential for
//! virtual machine setup and control in a virtualized environment. Focuses on segment state
//! management, aligning with VMX requirements.
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/vm.rs

use {core::arch::asm, x86::bits64::rflags::RFlags, x86::segmentation::SegmentSelector};

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
