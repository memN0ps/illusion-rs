use super::vmcs::Vmcs;
use crate::error::HypervisorError;

/// Enable VMX operation.
pub fn vmxon(vmxon_region: u64) {
    unsafe { x86::bits64::vmx::vmxon(vmxon_region).unwrap() };
}

/// Disable VMX operation.
pub fn vmxoff() -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmxoff() } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMXOFFFailed),
    }
}

/// Clear VMCS.
pub fn vmclear(vmcs_region: u64) {
    unsafe { x86::bits64::vmx::vmclear(vmcs_region).unwrap() };
}

/// Load current VMCS pointer.
pub fn vmptrld(vmcs_region: u64) {
    unsafe { x86::bits64::vmx::vmptrld(vmcs_region).unwrap() }
}

/// Return current VMCS pointer.
#[allow(dead_code)]
pub fn vmptrst() -> *const Vmcs {
    unsafe { x86::bits64::vmx::vmptrst().unwrap() as *const Vmcs }
}

/// Read a specified field from a VMCS.
pub fn vmread(field: u32) -> u64 {
    unsafe { x86::bits64::vmx::vmread(field) }.unwrap_or(0)
}

/// Write to a specified field in a VMCS.
pub fn vmwrite<T: Into<u64>>(field: u32, val: T)
where
    u64: From<T>,
{
    unsafe { x86::bits64::vmx::vmwrite(field, u64::from(val)) }.unwrap();
}
