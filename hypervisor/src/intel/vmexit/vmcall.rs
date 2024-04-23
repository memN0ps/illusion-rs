//! This crate includes functionalities to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            ept::AccessType,
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
#[rustfmt::skip]
pub fn handle_vmcall(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    debug!("Handling VMCALL VM exit...");
    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    let vmcall_number = vm.guest_registers.rax;
    trace!("VMCALL command number: {:#x}", vmcall_number);

    // Set the current hook to the EPT hook for handling MTF exit

    if let Some(ept_hook) = vm.hook_manager.find_hook_by_guest_va_as_mut(vm.guest_registers.rip) {
        info!("Executing VMCALL hook on shadow page for EPT hook at PA: {:#x} with VA: {:#x}", ept_hook.guest_pa, vm.guest_registers.rip);

        log_nt_query_system_information_params(&vm.guest_registers);

        // log_nt_create_file_params(&vm.guest_registers);

        let guest_page_pa = ept_hook.guest_pa.align_down_to_base_page().as_u64();

        // Perform swap_page before the mutable borrow for update_guest_interrupt_flag
        vm.primary_ept.swap_page(guest_page_pa, guest_page_pa, AccessType::READ_WRITE_EXECUTE, ept_hook.primary_ept_pre_alloc_pt.as_mut())?;

        // Set the monitor trap flag and initialize counter to the number of overwritten instructions
        set_monitor_trap_flag(true);

        // Ensure all data mutations to vm are done before calling this
        update_guest_interrupt_flag(vm, false)?;
    } else {
        warn!("Unhandled VMCALL number: {:#x}", vmcall_number);
        return Ok(ExitType::Continue);
    }

    trace!("Register state after handling VM exit: {:?}", vm.guest_registers);
    Ok(ExitType::Continue)
}

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

fn log_nt_create_file_params(regs: &GuestRegisters) {
    debug!(
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
