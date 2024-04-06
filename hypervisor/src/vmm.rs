//! Manages hypervisor startup and VM exit handling.
//!
//! Provides the infrastructure for starting a hypervisor, including checking CPU support and enabling VMX.
//! Also, handles various VM exit reasons, ensuring that the guest VM can be efficiently managed and controlled.
//! This crate is essential for hypervisor operation, facilitating VM execution and interaction with the physical CPU.

use {
    crate::{
        error::HypervisorError,
        intel::{
            bitmap::MsrAccessType,
            capture::GuestRegisters,
            shared::SharedData,
            support::{vmread, vmwrite},
            vm::Vm,
            vmerror::VmxBasicExitReason,
            vmexit::{
                cpuid::handle_cpuid,
                ept::{handle_ept_misconfiguration, handle_ept_violation},
                exception::{handle_exception, handle_undefined_opcode_exception},
                halt::handle_halt,
                init::handle_init_signal,
                invd::handle_invd,
                invept::handle_invept,
                invvpid::handle_invvpid,
                msr::handle_msr_access,
                rdtsc::handle_rdtsc,
                sipi::handle_sipi_signal,
                vmcall::handle_vmcall,
                xsetbv::handle_xsetbv,
                ExitType,
            },
            vmx::Vmx,
        },
    },
    log::*,
    x86::vmx::vmcs::{guest, ro},
};

/// Initiates the hypervisor, activating VMX and setting up the initial VM state.
///
/// Validates CPU compatibility and VMX support, then proceeds to enable VMX operation.
/// Initializes a VM instance and activates its VMCS, handling VM exits in a continuous loop.
///
/// # Arguments
///
/// - `guest_registers`: The initial state of the guest's general-purpose registers.
/// - `shared_data`: Shared data between the hypervisor and the guest VM.
///
/// # Panics
///
/// Panics if the CPU is not supported, VMX cannot be enabled, VM or VMCS activation fails,
/// or an unhandled VM exit reason is encountered.
pub fn start_hypervisor(guest_registers: &GuestRegisters, shared_data: &mut SharedData) -> ! {
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

    let mut vm = match Vm::new(&guest_registers, shared_data) {
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
                VmxBasicExitReason::InitSignal => handle_init_signal(&mut vm.guest_registers),
                VmxBasicExitReason::StartupIpi => handle_sipi_signal(&mut vm.guest_registers),
                VmxBasicExitReason::Hlt => handle_halt(),
                VmxBasicExitReason::Cpuid => handle_cpuid(&mut vm.guest_registers),

                // Grouping multiple exit reasons that are handled by the same function
                VmxBasicExitReason::Getsec
                | VmxBasicExitReason::Vmclear
                | VmxBasicExitReason::Vmlaunch
                | VmxBasicExitReason::Vmptrld
                | VmxBasicExitReason::Vmptrst
                | VmxBasicExitReason::Vmresume
                | VmxBasicExitReason::Vmxon
                | VmxBasicExitReason::Vmxoff => handle_undefined_opcode_exception(),

                VmxBasicExitReason::Rdmsr => {
                    handle_msr_access(&mut vm, MsrAccessType::Read).expect("Failed to handle RDMSR")
                }
                VmxBasicExitReason::Wrmsr => handle_msr_access(&mut vm, MsrAccessType::Write)
                    .expect("Failed to handle WRMSR"),
                VmxBasicExitReason::Invd => handle_invd(&mut vm.guest_registers),
                VmxBasicExitReason::Rdtsc => handle_rdtsc(&mut vm.guest_registers),
                VmxBasicExitReason::Vmcall => {
                    handle_vmcall(&mut vm).expect("Failed to handle VMCALL")
                }
                VmxBasicExitReason::EptViolation => handle_ept_violation(&mut vm),
                VmxBasicExitReason::EptMisconfiguration => handle_ept_misconfiguration(&mut vm),
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

/// Advances the guest's instruction pointer after handling a VM exit.
///
/// Ensures the guest VM does not re-execute the instruction causing the VM exit
/// by moving the instruction pointer to the next instruction.
///
/// # Arguments
///
/// - `guest_registers`: A mutable reference to the guest's general-purpose registers.
#[rustfmt::skip]
fn advance_guest_rip(guest_registers: &mut GuestRegisters) {
    trace!("Advancing guest RIP...");
    let len = vmread(ro::VMEXIT_INSTRUCTION_LEN);
    guest_registers.rip += len;
    vmwrite(guest::RIP, guest_registers.rip);
    trace!("Guest RIP advanced to: {:#x}", vmread(guest::RIP));
}

/// Checks if the CPU is supported for hypervisor operation.
///
/// Verifies the CPU is Intel with VMX support and Memory Type Range Registers (MTRRs) support.
///
/// # Returns
///
/// Returns `Ok(())` if the CPU meets all requirements, otherwise returns `Err(HypervisorError)`.
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

/// Verifies the CPU is from Intel.
///
/// # Returns
///
/// Returns `Ok(())` if the CPU vendor is GenuineIntel, otherwise `Err(HypervisorError::CPUUnsupported)`.
fn has_intel_cpu() -> Result<(), HypervisorError> {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
            return Ok(());
        }
    }
    Err(HypervisorError::CPUUnsupported)
}

/// Checks for Virtual Machine Extension (VMX) support on the CPU.
///
/// # Returns
///
/// Returns `Ok(())` if VMX is supported, otherwise `Err(HypervisorError::VMXUnsupported)`.
fn has_vmx_support() -> Result<(), HypervisorError> {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return Ok(());
        }
    }
    Err(HypervisorError::VMXUnsupported)
}

/// Checks for Memory Type Range Registers (MTRRs) support on the CPU.
///
/// # Returns
///
/// Returns `Ok(())` if MTRRs are supported, otherwise `Err(HypervisorError::MTRRUnsupported)`.
fn has_mtrr() -> Result<(), HypervisorError> {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_mtrr() {
            return Ok(());
        }
    }
    Err(HypervisorError::MTRRUnsupported)
}
