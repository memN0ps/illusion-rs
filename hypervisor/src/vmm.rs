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
            support::{rdmsr, vmread, vmwrite},
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
                mtf::handle_monitor_trap_flag,
                rdtsc::handle_rdtsc,
                sipi::handle_sipi_signal,
                vmcall::handle_vmcall,
                xsetbv::handle_xsetbv,
                ExitType,
            },
        },
    },
    log::*,
    x86::{
        msr::IA32_VMX_EPT_VPID_CAP,
        vmx::vmcs::{guest, ro},
    },
};

/// Initiates the hypervisor, activating VMX and setting up the initial VM state.
///
/// Validates CPU compatibility and VMX support, then proceeds to enable VMX operation.
/// Initializes a VM instance and activates its VMCS, handling VM exits in a continuous loop.
///
/// # Arguments
///
/// - `guest_registers`: The initial state of the guest's general-purpose registers.
///
/// # Panics
///
/// Panics if the CPU is not supported, VMX cannot be enabled, VM or VMCS activation fails,
/// or an unhandled VM exit reason is encountered.
pub fn start_hypervisor(guest_registers: &GuestRegisters) -> ! {
    debug!("Starting hypervisor");

    match check_supported_cpu() {
        Ok(_) => debug!("CPU is supported"),
        Err(e) => panic!("CPU is not supported: {:?}", e),
    };

    let mut vm = unsafe { Vm::zeroed().assume_init() };
    match vm.init(guest_registers) {
        Ok(_) => debug!("VM initialized"),
        Err(e) => panic!("Failed to initialize VM: {:?}", e),
    }

    match vm.activate_vmxon() {
        Ok(_) => debug!("VMX enabled"),
        Err(e) => panic!("Failed to enable VMX: {:?}", e),
    }

    match vm.activate_vmcs() {
        Ok(_) => debug!("VMCS activated"),
        Err(e) => panic!("Failed to activate VMCS: {:?}", e),
    }

    trace!("VMCS Dump: {:#x?}", vm.vmcs_region);

    /*
    match HookManager::hide_hypervisor_memory(&mut vm, AccessType::READ_WRITE_EXECUTE) {
        Ok(_) => debug!("Hypervisor memory hidden"),
        Err(e) => panic!("Failed to hide hypervisor memory: {:?}", e),
    };
     */

    info!("Launching the VM until a vmexit occurs...");

    loop {
        if let Ok(basic_exit_reason) = vm.run() {
            trace!("VM exit reason: {:?}", basic_exit_reason);

            let exit_type = match basic_exit_reason {
                // 0
                VmxBasicExitReason::ExceptionOrNmi => handle_exception(&mut vm),
                // 3
                VmxBasicExitReason::InitSignal => handle_init_signal(&mut vm.guest_registers),
                // 4
                VmxBasicExitReason::StartupIpi => handle_sipi_signal(&mut vm.guest_registers),
                // 10
                VmxBasicExitReason::Cpuid => handle_cpuid(&mut vm).expect("Failed to handle CPUID"),
                // 11
                VmxBasicExitReason::Getsec => handle_undefined_opcode_exception(),
                // 12
                VmxBasicExitReason::Hlt => handle_halt(),
                // 13
                VmxBasicExitReason::Invd => handle_invd(&mut vm.guest_registers),
                // 18
                VmxBasicExitReason::Vmcall => handle_vmcall(&mut vm).expect("Failed to handle VMCALL"),
                // 19
                VmxBasicExitReason::Vmclear => handle_undefined_opcode_exception(),
                // 20
                VmxBasicExitReason::Vmlaunch => handle_undefined_opcode_exception(),
                // 21
                VmxBasicExitReason::Vmptrld => handle_undefined_opcode_exception(),
                // 22
                VmxBasicExitReason::Vmptrst => handle_undefined_opcode_exception(),
                // 23
                VmxBasicExitReason::Vmread => handle_undefined_opcode_exception(),
                // 24
                VmxBasicExitReason::Vmresume => handle_undefined_opcode_exception(),
                // 25
                VmxBasicExitReason::Vmwrite => handle_undefined_opcode_exception(),
                // 26
                VmxBasicExitReason::Vmxoff => handle_undefined_opcode_exception(),
                // 27
                VmxBasicExitReason::Vmxon => handle_undefined_opcode_exception(),
                // 31
                VmxBasicExitReason::Rdmsr => handle_msr_access(&mut vm, MsrAccessType::Read).expect("Failed to handle RDMSR"),
                // 32
                VmxBasicExitReason::Wrmsr => handle_msr_access(&mut vm, MsrAccessType::Write).expect("Failed to handle WRMSR"),
                // 37
                VmxBasicExitReason::MonitorTrapFlag => handle_monitor_trap_flag(&mut vm).expect("Failed to handle Monitor Trap Flag"),
                // 48
                VmxBasicExitReason::EptViolation => handle_ept_violation(&mut vm).expect("Failed to handle EPT violation"),
                // 49
                VmxBasicExitReason::EptMisconfiguration => handle_ept_misconfiguration(&mut vm).expect("Failed to handle EPT misconfiguration"),
                // 50
                VmxBasicExitReason::Invept => handle_invept(),
                // 51
                VmxBasicExitReason::Rdtsc => handle_rdtsc(&mut vm.guest_registers),
                // 53
                VmxBasicExitReason::Invvpid => handle_invvpid(),
                // 55
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

/// Advances the guest's instruction pointer after handling a VM exit.
///
/// Ensures the guest VM does not re-execute the instruction causing the VM exit
/// by moving the instruction pointer to the next instruction.
///
/// # Arguments
///
/// - `guest_registers`: A mutable reference to the guest's general-purpose registers.
fn advance_guest_rip(guest_registers: &mut GuestRegisters) {
    // trace!("Advancing guest RIP...");
    let len = vmread(ro::VMEXIT_INSTRUCTION_LEN);
    guest_registers.rip += len;
    vmwrite(guest::RIP, guest_registers.rip);
    // trace!("Guest RIP advanced to: {:#x}", vmread(guest::RIP));
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

    check_ept_support()?;
    info!("Extended Page Tables (EPT) are supported");

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

/// Checks for Extended Page Tables (EPT) support on the CPU.
///
/// # Returns
///
/// Returns `Ok(())` if EPT is supported, otherwise `Err(HypervisorError::EPTUnsupported)`.
///
/// Credits Satoshi Tanda: https://github.com/tandasat/MiniVisorPkg/blob/master/Sources/MiniVisor.c#L534-L550
fn check_ept_support() -> Result<(), HypervisorError> {
    /// [Bit 6] Indicates support for a page-walk length of 4.
    const PAGE_WALK_LENGTH_4: u64 = 1 << 6;

    /// [Bit 14] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be * write-back (WB).
    const MEMORY_TYPE_WRITE_BACK: u64 = 1 << 14;

    /// [Bit 16] When set to 1, the logical processor allows software to configure a EPT PDE to map a 2-Mbyte page (by setting * bit 7 in the EPT PDE).
    const PDE_2MB_PAGES: u64 = 1 << 16;

    /// [Bit 20] If bit 20 is read as 1, the INVEPT instruction is supported.
    const INVEPT: u64 = 1 << 20;

    /// [Bit 25] When set to 1, the single-context INVEPT type is supported.
    const INVEPT_SINGLE_CONTEXT: u64 = 1 << 25;

    /// [Bit 26] When set to 1, the all-context INVEPT type is supported.
    const INVEPT_ALL_CONTEXTS: u64 = 1 << 26;

    /// [Bit 32] When set to 1, the INVVPID instruction is supported.
    const INVVPID: u64 = 1 << 32;

    /// [Bit 41] When set to 1, the single-context INVVPID type is supported.
    const INVVPID_SINGLE_CONTEXT: u64 = 1 << 41;

    /// [Bit 42] When set to 1, the all-context INVVPID type is supported.
    const INVVPID_ALL_CONTEXTS: u64 = 1 << 42;

    let ept_vpid_cap = rdmsr(IA32_VMX_EPT_VPID_CAP);

    // Construct a combined mask for all required features for simplicity
    let required_features = PAGE_WALK_LENGTH_4
        | MEMORY_TYPE_WRITE_BACK
        | PDE_2MB_PAGES
        | INVEPT
        | INVEPT_SINGLE_CONTEXT
        | INVEPT_ALL_CONTEXTS
        | INVVPID
        | INVVPID_SINGLE_CONTEXT
        | INVVPID_ALL_CONTEXTS;

    if ept_vpid_cap & required_features != required_features {
        return Err(HypervisorError::EPTUnsupported);
    }

    Ok(())
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
