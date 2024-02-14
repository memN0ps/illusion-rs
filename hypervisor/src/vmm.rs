use log::*;
use x86::cpuid::cpuid;
use crate::intel::vmx::Vmx;

pub const CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
pub const VENDOR_NAME: u32 = 0x5441_4c48; // "HLAT"

pub fn start_hypervisor() -> ! {
    debug!("Starting hypervisor");

    let mut vmx = Vmx::new();

    match vmx.enable() {
        Ok(_) => debug!("VMX enabled"),
        Err(e) => error!("Failed to enable VMX: {:?}", e),
    };

    let vm = Vm::new();

    loop {
        //vmx.vmlaunch();
    }
}

/// Checks if this hypervisor is already installed.
pub fn is_hypervisor_present() -> bool {
    let regs = cpuid!(CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == regs.ecx) && (regs.ecx == regs.edx) && (regs.edx == VENDOR_NAME)
}