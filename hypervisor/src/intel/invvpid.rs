//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.10.4 Invalidation of TLBs and Paging-Structure Caches
//!
//! The INVVPID (Invalidate VPID) instruction is used to invalidate entries in the TLB and paging-structure caches
//! that are associated with a specific Virtual Processor Identifier (VPID). This is essential in virtualization
//! environments to maintain consistency of memory translations across different virtual processors.

pub const VPID_TAG: u16 = 0x1;

/// Represents the types of INVVPID operations.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvvpidType {
    /// Invalidate mappings associated with a specific linear address and VPID.
    /// This type invalidates mappings—except global translations—associated with the specified VPID
    /// that would be used to translate the specified linear address.
    IndividualAddress = 0,

    /// Invalidate mappings associated with a specific VPID.
    /// This type invalidates all mappings—except global translations—associated with the specified VPID.
    SingleContext = 1,

    /// Invalidate mappings—including global translations—associated with all VPIDs.
    /// This type invalidates all mappings for all VPIDs.
    AllContextsIncludingGlobals = 2,

    /// Invalidate mappings associated with all VPIDs except global translations.
    /// This type invalidates all mappings except for global translations for all VPIDs.
    AllContexts = 3,
}

/// Represents an INVVPID descriptor.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvvpidDescriptor {
    /// Virtual Processor Identifier
    pub vpid: u16,
    /// Reserved fields (must be zero)
    pub reserved: [u16; 3],
    /// Linear address (used only for IndividualAddress type)
    pub linear_address: u64,
}

/// Performs the INVVPID instruction.
///
/// # Arguments
/// * `invvpid_type` - The type of invalidation to perform.
/// * `descriptor` - The INVVPID descriptor.
fn invvpid(invvpid_type: InvvpidType, descriptor: &InvvpidDescriptor) {
    let descriptor_ptr = descriptor as *const _ as u64;
    unsafe {
        core::arch::asm!(
        "invvpid {0}, [{1}]",
        in(reg) invvpid_type as u64,
        in(reg) descriptor_ptr,
        options(nostack)
        );
    }
}

/// Invalidates TLB and paging-structure cache entries associated with a specific linear address and VPID.
///
/// # Arguments
/// * `vpid` - Virtual Processor Identifier.
/// * `linear_address` - Specific linear address whose mappings are to be invalidated.
pub fn invvpid_individual_address(vpid: u16, linear_address: u64) {
    let descriptor = InvvpidDescriptor {
        vpid,
        reserved: [0; 3], // Reserved fields, must be zero
        linear_address,
    };
    // Perform the INVVPID operation for an individual address.
    invvpid(InvvpidType::IndividualAddress, &descriptor);
}

/// Invalidates TLB and paging-structure cache entries associated with a specific VPID.
///
/// # Arguments
/// * `vpid` - Virtual Processor Identifier.
pub fn invvpid_single_context(vpid: u16) {
    let descriptor = InvvpidDescriptor {
        vpid,              // VPID of the target context
        reserved: [0; 3],  // Reserved fields, must be zero
        linear_address: 0, // Irrelevant for SingleContext, but required for struct completeness
    };
    // Perform the INVVPID operation for a single context.
    invvpid(InvvpidType::SingleContext, &descriptor);
}

/// Invalidates TLB and paging-structure cache entries for all VPIDs.
///
/// This operation ignores the descriptor fields as they are irrelevant for the AllContexts type.
pub fn invvpid_all_contexts() {
    let descriptor = InvvpidDescriptor {
        vpid: 0,           // Irrelevant for AllContexts
        reserved: [0; 3],  // Reserved fields, must be zero
        linear_address: 0, // Irrelevant for AllContexts
    };
    // Perform the INVVPID operation for all contexts.
    invvpid(InvvpidType::AllContexts, &descriptor);
}