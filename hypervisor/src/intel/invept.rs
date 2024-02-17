//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.4.3.1 Operations that Invalidate Cached Mappings
//!
//! The INVEPT instruction invalidates entries in the translation lookaside buffer (TLB) and other processor structures
//! that cache translations derived from EPT. It's used to ensure that modifications to EPT entries don't cause
//! inconsistencies due to stale cached translations.

/// Represents the types of INVEPT operations.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InveptType {
    /// Invalidate mappings associated with a single EPTP value.
    /// This type causes the logical processor to invalidate all guest-physical mappings and
    /// combined mappings associated with the EPTRTA specified in the INVEPT descriptor.
    /// Combined mappings for that EPTRTA are invalidated for all VPIDs and all PCIDs.
    SingleContext = 1,

    /// Invalidate mappings associated with all EPTP values.
    /// This type causes the logical processor to invalidate guest-physical mappings and combined mappings
    /// associated with all EPTRTAs (and, for combined mappings, for all VPIDs and PCIDs).
    AllContexts = 2,
}

/// Executes the INVEPT instruction.
///
/// # Arguments
/// * `invept_type` - The type of INVEPT operation to perform.
/// * `eptp` - The EPT pointer used for Single Context INVEPT. It should be a 64-bit value formed by
///   concatenating the EPTP's memory type (bits 2:0), page-walk length (bits 5:3), and address of the EPTP
///   (bits 63:12). For All Contexts INVEPT, this value is ignored.
///
/// # Safety
/// This function is unsafe because it involves inline assembly and direct interaction with CPU features.
fn invept(invept_type: InveptType, eptp: u64) {
    // The INVEPT descriptor is a 128-bit value. The first 64-bits (low part) should be 0 for All-Contexts
    // and the EPTP for Single-Context. The second 64-bits (high part) should always be 0.
    let descriptor: [u64; 2] = [eptp, 0];

    unsafe {
        core::arch::asm!(
        "invept {0}, [{1}]",
        in(reg) invept_type as u64,
        in(reg) &descriptor,
        options(nostack)
        );
    };
}

/// Invalidates entries in the TLB and other processor structures that cache translations derived from EPT.
///
/// This function is used to ensure that modifications to EPT entries don't cause inconsistencies due to
/// stale cached translations. It specifically invalidates mappings associated with a single EPTP value.
///
/// # Arguments
/// * `eptp` - The Extended Page Table Pointer used for Single Context INVEPT.
///            It should be a 64-bit value formed by concatenating the EPTP's memory type (bits 2:0),
///            page-walk length (bits 5:3), and address of the EPTP (bits 63:12).
pub fn invept_single_context(eptp: u64) {
    // Perform the INVEPT operation for a single context.
    invept(InveptType::SingleContext, eptp);
}

/// Invalidates entries in the TLB and other processor structures that cache translations derived from EPT
/// for all EPTP values.
///
/// This function is used to invalidate guest-physical mappings and combined mappings associated with all
/// EPT Pointer Table Roots (EPTRTAs) and, for combined mappings, for all VPIDs and PCIDs.
pub fn invept_all_contexts() {
    // Perform the INVEPT operation for all contexts.
    // The EPT pointer is irrelevant for this type of operation and is thus set to 0.
    invept(InveptType::AllContexts, 0);
}
