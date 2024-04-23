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
        log_nt_create_file_params(&vm.guest_registers);

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
