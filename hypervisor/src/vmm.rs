use log::*;
use x86::cpuid::cpuid;
use crate::intel::capture::GuestRegisters;
use crate::intel::shared_data::SharedData;
use crate::intel::vm::Vm;
use crate::intel::vmx::Vmx;

pub const CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
pub const VENDOR_NAME: u32 = 0x5441_4c48; // "HLAT"

// pass shared data to the hypervisor soon too
pub fn start_hypervisor(guest_registers: &GuestRegisters, shared_data: &mut SharedData) -> ! {
    debug!("Starting hypervisor");

    let mut vmx = Vmx::new();

    match vmx.activate_vmxon() {
        Ok(_) => debug!("VMX enabled"),
        Err(e) => panic!("Failed to enable VMX: {:?}", e),
    };

    // shared data and guest registers need to go here
    let mut vm = Vm::new(guest_registers, shared_data);

    match vm.activate_vmcs() {
        Ok(_) => debug!("VMCS activated"),
        Err(e) => panic!("Failed to activate VMCS: {:?}", e),
    }

    // vm.run() and vmexit handles
    loop {
        //vmx.vmlaunch();
    }
}

/// Checks if this hypervisor is already installed.
pub fn is_hypervisor_present() -> bool {
    let regs = cpuid!(CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == regs.ecx) && (regs.ecx == regs.edx) && (regs.edx == VENDOR_NAME)
}