use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            support::{vmread, vmwrite},
            vm::Vm,
            vmerror::VmxBasicExitReason,
            vmexit::{
                cpuid::handle_cpuid,
                ept::{handle_ept_misconfiguration, handle_ept_violation},
                exception::{handle_exception, handle_undefined_opcode_exception},
                invd::handle_invd,
                invept::handle_invept,
                invvpid::handle_invvpid,
                msr::{handle_msr_access, MsrAccessType},
                rdtsc::handle_rdtsc,
                xsetbv::handle_xsetbv,
                ExitType,
            },
            vmx::Vmx,
        },
    },
    log::*,
    x86::vmx::vmcs::{guest, ro},
};

/// Starts the hypervisor.
pub fn start_hypervisor(guest_registers: &GuestRegisters) -> ! {
    debug!("Starting hypervisor");

    match check_supported_cpu() {
        Ok(_) => debug!("CPU is supported"),
        Err(e) => panic!("CPU is not supported: {:?}", e),
    };

    let mut vmx = Vmx::new();

    match vmx.activate_vmxon() {
        Ok(_) => debug!("VMX enabled"),
        Err(e) => panic!("Failed to enable VMX: {:?}", e),
    };

    let mut vm = match Vm::new(&guest_registers) {
        Ok(vm) => vm,
        Err(e) => panic!("Failed to create VM: {:?}", e),
    };

    match vm.activate_vmcs() {
        Ok(_) => debug!("VMCS activated"),
        Err(e) => panic!("Failed to activate VMCS: {:?}", e),
    }

    info!("Launching the VM until a vmexit occurs...");

    loop {
        if let Ok(basic_exit_reason) = vm.run() {
            trace!("Handling VM exit reason: {:?}", basic_exit_reason);
            debug!(
                "Register state before handling VM exit: {:#x?}",
                vm.guest_registers
            );

            let exit_type = match basic_exit_reason {
                VmxBasicExitReason::ExceptionOrNmi => handle_exception(&mut vm),
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

                VmxBasicExitReason::Rdmsr => {
                    handle_msr_access(&mut vm.guest_registers, MsrAccessType::Read)
                }
                VmxBasicExitReason::Wrmsr => {
                    handle_msr_access(&mut vm.guest_registers, MsrAccessType::Write)
                }
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

            debug!(
                "Register state after handling VM exit: {:#x?}",
                vm.guest_registers
            );
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

/// Check if the CPU is supported.
///
/// # Returns
///
/// A `Result` which is `Ok` if the CPU is supported, or `Err` if it's not.
fn check_supported_cpu() -> Result<(), HypervisorError> {
    /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
    has_intel_cpu()?;
    info!("CPU is Intel");

    has_vmx_support()?;
    info!("Virtual Machine Extension (VMX) technology is supported");

    has_mtrr()?;
    info!("Memory Type Range Registers (MTRRs) are supported");

    Ok(())
}

/// Check to see if CPU is Intel (“GenuineIntel”).
///
/// # Returns
///
/// A `Result` which is `Ok` if the CPU is Intel, or `Err` if it's not.
fn has_intel_cpu() -> Result<(), HypervisorError> {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
            return Ok(());
        }
    }
    Err(HypervisorError::CPUUnsupported)
}

/// Check processor support for Virtual Machine Extension (VMX) technology.
///
/// # Returns
///
/// A `Result` which is `Ok` if VMX technology is supported, or `Err` if it's not.
fn has_vmx_support() -> Result<(), HypervisorError> {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return Ok(());
        }
    }
    Err(HypervisorError::VMXUnsupported)
}

/// Check processor support for Memory Type Range Registers (MTRRs).
///
/// # Returns
///
/// A `Result` which is `Ok` if MTRRs are supported, or `Err` if it's not.
fn has_mtrr() -> Result<(), HypervisorError> {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_mtrr() {
            return Ok(());
        }
    }
    Err(HypervisorError::MTRRUnsupported)
}
