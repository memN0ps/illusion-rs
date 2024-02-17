use core::arch::asm;
use x86::bits64::rflags::RFlags;
use x86::segmentation::SegmentSelector;

pub fn access_rights_from_native(access_rights: u32) -> u32 {
    const VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG: u32 = 1 << 16;

    if access_rights == 0 {
        return VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG;
    }

    (access_rights >> 8) & 0b1111_0000_1111_1111
}

//
pub(crate) fn lsl(selector: SegmentSelector) -> u32 {
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
pub(crate) fn lar(selector: SegmentSelector) -> u32 {
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