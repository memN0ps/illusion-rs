use {
    log::*,
    x86::{
        cpuid::cpuid, vmx::vmcs::{guest, ro}
    },
    crate::{
        intel::{
            capture::GuestRegisters,
            shared_data::SharedData,
            vm::Vm,
            vmx::Vmx,
            vmerror::VmxBasicExitReason,
            support::{vmread, vmwrite},
            vmexit::{
                ExitType,
                cpuid::handle_cpuid,
                ept::{handle_ept_misconfiguration, handle_ept_violation},
                exception::{handle_exception, handle_undefined_opcode_exception},
                invd::handle_invd,
                invept::handle_invept,
                invvpid::handle_invvpid,
                msr::{handle_msr_access, MsrAccessType},
                rdtsc::handle_rdtsc,
                xsetbv::handle_xsetbv,
            }
        },
    },
};

pub const CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
pub const VENDOR_NAME: u32 = 0x5441_4c48; // "HLAT"

/// Checks if this hypervisor is already installed.
pub fn is_hypervisor_present() -> bool {
    let regs = cpuid!(CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == regs.ecx) && (regs.ecx == regs.edx) && (regs.edx == VENDOR_NAME)
}

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

    loop {
        if let Ok(basic_exit_reason ) = vm.run() {
            let exit_type = match basic_exit_reason {
                //VmxBasicExitReason::ExceptionOrNmi => handle_exception(guest_registers, vmx),
                VmxBasicExitReason::Cpuid => handle_cpuid(&mut vm.guest_registers),

                // Grouping multiple exit reasons that are handled by the same function
                VmxBasicExitReason::Getsec
                | VmxBasicExitReason::Vmcall
                | VmxBasicExitReason::Vmclear
                | VmxBasicExitReason::Vmlaunch
                | VmxBasicExitReason::Vmptrld
                | VmxBasicExitReason::Vmptrst
                | VmxBasicExitReason::Vmresume
                | VmxBasicExitReason::Vmxon
                | VmxBasicExitReason::Vmxoff => handle_undefined_opcode_exception(),

                VmxBasicExitReason::Rdmsr => handle_msr_access(&mut vm.guest_registers, MsrAccessType::Read),
                VmxBasicExitReason::Wrmsr => handle_msr_access(&mut vm.guest_registers, MsrAccessType::Write),
                VmxBasicExitReason::Invd => handle_invd(&mut vm.guest_registers),
                VmxBasicExitReason::Rdtsc => handle_rdtsc(&mut vm.guest_registers),
                VmxBasicExitReason::EptViolation => handle_ept_violation(&mut vm),
                VmxBasicExitReason::EptMisconfiguration => handle_ept_misconfiguration(),
                VmxBasicExitReason::Invept => handle_invept(),
                VmxBasicExitReason::Invvpid => handle_invvpid(),
                VmxBasicExitReason::Xsetbv => handle_xsetbv(&mut vm.guest_registers),
                _ => panic!("Unhandled VM exit reason: {:?}", basic_exit_reason),
            };

            if exit_type == ExitType::IncrementRIP {
                advance_guest_rip(&mut vm.guest_registers);
            }

        } else {
            panic!("Failed to run the VM");
        }
    }
}

/// Advances the guest's instruction pointer (RIP) after a VM exit.
///
/// When a VM exit occurs, the guest's execution is interrupted, and control is transferred
/// to the hypervisor. To ensure that the guest does not re-execute the instruction that
/// caused the VM exit, the hypervisor needs to advance the guest's RIP to the next instruction.
#[rustfmt::skip]
fn advance_guest_rip(guest_registers: &mut GuestRegisters) {
    trace!("Advancing guest RIP...");
    let len = vmread(ro::VMEXIT_INSTRUCTION_LEN);
    guest_registers.rip += len;
    vmwrite(guest::RIP, guest_registers.rip);
    trace!("Guest RIP advanced to: {:#x}", vmread(guest::RIP));
}
