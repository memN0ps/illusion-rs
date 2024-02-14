use x86::bits64::paging::BASE_PAGE_SIZE;
use crate::intel::support::rdmsr;

/// Represents the VMCS region in memory.
///
/// The VMCS region is essential for VMX operations on the CPU.
/// This structure offers methods for setting up the VMCS region, adjusting VMCS entries,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; BASE_PAGE_SIZE - 8],
}
const _: () = assert_eq!(core::mem::size_of::<Vmcs>(), BASE_PAGE_SIZE);


impl Default for Vmcs {
    fn default() -> Self {
        Self {
            revision_id: rdmsr(x86::msr::IA32_VMX_BASIC) as u32,
            abort_indicator: 0,
            reserved: [0; BASE_PAGE_SIZE - 8],
        }
    }
}