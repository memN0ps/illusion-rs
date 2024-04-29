//! This crate includes functionalities to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            ept::AccessType,
            events::EventInjection,
            vm::Vm,
            vmexit::{
                mtf::{set_monitor_trap_flag, update_guest_interrupt_flag},
                ExitType,
            },
        },
    },
    log::*,
};

/// Represents various VMCALL commands that a guest can issue to the hypervisor.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmcallCommand {
    /// Command to indicate an unknown or unimplemented VMCALL command.
    Unknown = 0,
}

/// Handles a VMCALL VM exit by executing the corresponding action based on the VMCALL command.
///
/// # Parameters
///
/// * `vm`: A mutable reference to the virtual machine instance encountering the VMCALL exit.
///
/// # Returns
///
/// * `Ok(ExitType)`: The continuation exit type after handling the VMCALL, usually indicates that VM execution should continue.
/// * `Err(HypervisorError)`: An error if the VMCALL command is unknown or if there's a failure in handling the command.
///
/// # Errors
///
/// * `HypervisorError::UnknownVmcallCommand`: Returned if the VMCALL command is not recognized.
pub fn handle_vmcall(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    debug!("Handling VMCALL VM exit...");
    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    let vmcall_number = vm.guest_registers.rax;
    trace!("VMCALL command number: {:#x}", vmcall_number);

    // Set the current hook to the EPT hook for handling MTF exit

    let exit_type = if let Some(ept_hook) = vm.hook_manager.find_hook_by_guest_va_as_mut(vm.guest_registers.rip) {
        info!("Executing VMCALL hook on shadow page for EPT hook at PA: {:#x} with VA: {:#x}", ept_hook.guest_pa, vm.guest_registers.rip);

        // log_nt_query_system_information_params(&vm.guest_registers);

        // log_nt_create_file_params(&vm.guest_registers);

        log_nt_open_process_params(&vm.guest_registers);

        // log_mm_is_address_valid_params(&vm.guest_registers);

        let guest_page_pa = ept_hook.guest_pa.align_down_to_base_page().as_u64();

        // Perform swap_page before the mutable borrow for update_guest_interrupt_flag
        vm.primary_ept
            .swap_page(guest_page_pa, guest_page_pa, AccessType::READ_WRITE_EXECUTE, ept_hook.primary_ept_pre_alloc_pt.as_mut())?;

        // Calculate the number of instructions in the function to set the MTF counter for restoring overwritten instructions by single-stepping.
        let instruction_count = unsafe { calculate_instruction_count(ept_hook.guest_pa.as_u64(), ept_hook.inline_hook.unwrap().hook_size()) as u64 };
        ept_hook.mtf_counter = Some(instruction_count);

        // Set the monitor trap flag and initialize counter to the number of overwritten instructions
        set_monitor_trap_flag(true);

        // Ensure all data mutations to vm are done before calling this
        update_guest_interrupt_flag(vm, false)?;

        Ok(ExitType::Continue)
    } else if cfg!(feature = "hyperv") {
        // If the address is not a hook and we are running under hyper-v forward it.
        debug!("Hyper-V VMCALL detected and handled.");
        asm_hyperv_vmcall(vm.guest_registers.rcx, vm.guest_registers.rdx, vm.guest_registers.r8);
        Ok(ExitType::IncrementRIP)
    } else {
        EventInjection::vmentry_inject_gp(0);
        Ok(ExitType::Continue)
    };

    exit_type
}

/// Execute a Hyper-V VMCALL.
///
/// # Safety
///
/// This function is unsafe because it uses inline assembly and can cause a VM exit or other undefined behavior
/// if not used within the proper hypervisor context.
///
/// # Parameters
///
/// * `hypercall_input_value` - The input value for the hypercall.
/// * `input_parameters_gpa` - Guest Physical Address (GPA) of the input parameters.
/// * `output_parameters_gpa` - Guest Physical Address (GPA) of the output parameters.
pub fn asm_hyperv_vmcall(hypercall_input_value: u64, input_parameters_gpa: u64, output_parameters_gpa: u64) {
    unsafe {
        core::arch::asm!("vmcall",
        in("rcx") hypercall_input_value,
        in("rdx") input_parameters_gpa,
        in("r8") output_parameters_gpa,
        options(nostack, nomem)
        );
    }
}

/// Calculates the number of instructions that fit into the given number of bytes,
/// adjusting for partial instruction overwrites by including the next full instruction.
///
/// # Safety
///
/// This function is unsafe because it performs operations on raw pointers. The caller must
/// ensure that the memory at `guest_pa` (converted properly to a virtual address if necessary)
/// is valid and that reading beyond `hook_size` bytes does not cause memory violations.
pub unsafe fn calculate_instruction_count(guest_pa: u64, hook_size: usize) -> usize {
    // Define a buffer size, typical maximum x86-64 instruction length is 15 bytes.
    let buffer_size = hook_size + 15; // Buffer size to read, slightly larger than hook_size to accommodate potential long instructions at the boundary.
    let bytes = core::slice::from_raw_parts(guest_pa as *const u8, buffer_size);

    let mut byte_count = 0;
    let mut instruction_count = 0;
    // Use a disassembler engine to iterate over the instructions within the bytes read.
    for (opcode, pa) in lde::X64.iter(bytes, guest_pa) {
        byte_count += opcode.len();
        instruction_count += 1;

        trace!("{:x}: {}", pa, opcode);
        if byte_count >= hook_size {
            break;
        }
    }

    trace!("Calculated byte count: {}", byte_count);
    trace!("Calculated instruction count: {}", instruction_count);

    instruction_count
}

#[allow(dead_code)]
fn log_mm_is_address_valid_params(regs: &GuestRegisters) {
    info!(
        "MmIsAddressValid called with parameters:\n\
         VirtualAddress: {:#018x}", // Typically passed in RCX for x64 calling convention
        regs.rcx // VirtualAddress to check
    );
}

#[allow(dead_code)]
fn log_nt_query_system_information_params(regs: &GuestRegisters) {
    info!(
        "NtQuerySystemInformation called with parameters: SystemInformationClass: {}, \
        SystemInformation: {:#018x}, SystemInformationLength: {}, ReturnLength: {:#018x}",
        system_information_class_name(regs.rcx as u32),
        regs.rdx,
        regs.r8,
        regs.r9,
    );
}

#[allow(dead_code)]
fn system_information_class_name(class: u32) -> &'static str {
    match class {
        0x00 => "SystemBasicInformation",
        0x01 => "SystemProcessorInformation",
        0x02 => "SystemPerformanceInformation",
        0x03 => "SystemTimeOfDayInformation",
        0x04 => "SystemPathInformation",
        0x05 => "SystemProcessInformation",
        0x06 => "SystemCallCountInformation",
        0x07 => "SystemDeviceInformation",
        0x08 => "SystemProcessorPerformanceInformation",
        0x09 => "SystemFlagsInformation",
        0x0A => "SystemCallTimeInformation",
        0x0B => "SystemModuleInformation",
        0x0C => "SystemLocksInformation",
        0x0D => "SystemStackTraceInformation",
        0x0E => "SystemPagedPoolInformation",
        0x0F => "SystemNonPagedPoolInformation",
        0x10 => "SystemHandleInformation",
        0x11 => "SystemObjectInformation",
        0x12 => "SystemPageFileInformation",
        0x13 => "SystemVdmInstemulInformation",
        0x14 => "SystemVdmBopInformation",
        0x15 => "SystemFileCacheInformation",
        0x16 => "SystemPoolTagInformation",
        0x17 => "SystemInterruptInformation",
        0x18 => "SystemDpcBehaviorInformation",
        0x19 => "SystemMemoryInformation",
        0x1A => "SystemLoadGdiDriverInformation",
        0x1B => "SystemUnloadGdiDriverInformation",
        0x1C => "SystemTimeAdjustmentInformation",
        0x1D => "SystemSummaryMemoryInformation",
        0x1E => "SystemNextEventIdInformation",
        0x1F => "SystemEventIdsInformation",
        0x20 => "SystemCrashDumpInformation",
        0x21 => "SystemExceptionInformation",
        0x22 => "SystemCrashDumpStateInformation",
        0x23 => "SystemKernelDebuggerInformation",
        0x24 => "SystemContextSwitchInformation",
        0x25 => "SystemRegistryQuotaInformation",
        0x26 => "SystemExtendServiceTableInformation",
        0x27 => "SystemPrioritySeperation",
        0x28 => "SystemPlugPlayBusInformation",
        0x29 => "SystemDockInformation",
        0x2A => "SystemPowerInformation",
        0x2B => "SystemProcessorSpeedInformation",
        0x2C => "SystemCurrentTimeZoneInformation",
        0x2D => "SystemLookasideInformation",
        // This pattern continues for all known System Information Classes
        0x2E => "SystemTimeSlipNotification",
        0x2F => "SystemSessionCreate",
        0x30 => "SystemSessionDetach",
        0x31 => "SystemSessionInformation",
        // Add additional mappings here up to 0xD5...
        0xD5 => "SystemSecureSpeculationControlInformation",
        _ => "Unknown Information Class",
    }
}

#[allow(dead_code)]
fn log_nt_create_file_params(regs: &GuestRegisters) {
    info!(
        "NtCreateFile called with parameters:\n\
         FileHandle: {:#018x}, DesiredAccess: {:#018x}, ObjectAttributes: {:#018x},\n\
         IoStatusBlock: {:#018x}, AllocationSize: {:#018x}, FileAttributes: {:#x},\n\
         ShareAccess: {:#x}, CreateDisposition: {:#x}, CreateOptions: {:#x},\n\
         EaBuffer: {:#018x}, EaLength: {:#x}",
        regs.rcx,        // FileHandle (typically an out parameter, pointer passed in RCX)
        regs.rdx,        // DesiredAccess (passed in RDX)
        regs.r8,         // ObjectAttributes (pointer in R8)
        regs.r9,         // IoStatusBlock (pointer in R9)
        regs.rsp + 0x28, // AllocationSize (pointer, next stack parameter)
        regs.rsp + 0x30, // FileAttributes
        regs.rsp + 0x38, // ShareAccess
        regs.rsp + 0x40, // CreateDisposition
        regs.rsp + 0x48, // CreateOptions
        regs.rsp + 0x50, // EaBuffer (pointer)
        regs.rsp + 0x58  // EaLength
    );
}

#[allow(dead_code)]
fn log_nt_open_process_params(regs: &GuestRegisters) {
    info!(
        "NtOpenProcess called with parameters:\n\
         ProcessHandle (out): {:#018x},\n\
         DesiredAccess: {:#018x},\n\
         ObjectAttributes: {:#018x},\n\
         ClientId (PID): {:#018x}", // Assuming ClientId is a pointer to a CLIENT_ID structure that contains PID
        regs.rcx, // ProcessHandle, typically a pointer to a HANDLE, passed back out to the caller
        regs.rdx, // DesiredAccess, specifies access rights
        regs.r8,  // ObjectAttributes, pointer to an OBJECT_ATTRIBUTES structure
        regs.r9   // ClientId, pointer to a CLIENT_ID structure (which typically includes a PID)
    );
}
