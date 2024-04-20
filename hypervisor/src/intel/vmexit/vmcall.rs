//! This crate includes functionalities to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::AccessType,
            vm::Vm,
            vmexit::{mtf::set_monitor_trap_flag, ExitType},
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

    // Get the VMCALL command number from the guest's RAX register.
    let vmcall_number = vm.guest_registers.rax;
    trace!("VMCALL command number: {:#x}", vmcall_number);

    match vm.hook_manager.find_hook_by_guest_va_as_mut(vmcall_number) {
        Some(ept_hook) => {
            // Capture and log the parameters used in NtCreateFile
            debug!(
                "NtCreateFile called with parameters:\n\
                 FileHandle: {:#018x}, DesiredAccess: {:#018x}, ObjectAttributes: {:#018x},\n\
                 IoStatusBlock: {:#018x}, AllocationSize: {:#018x}, FileAttributes: {:#x},\n\
                 ShareAccess: {:#x}, CreateDisposition: {:#x}, CreateOptions: {:#x},\n\
                 EaBuffer: {:#018x}, EaLength: {:#x}",
                vm.guest_registers.rcx, // FileHandle (typically an out parameter, pointer passed in RCX)
                vm.guest_registers.rdx, // DesiredAccess (passed in RDX)
                vm.guest_registers.r8,  // ObjectAttributes (pointer in R8)
                vm.guest_registers.r9,  // IoStatusBlock (pointer in R9)
                vm.guest_registers.rsp + 0x28, // AllocationSize (pointer, next stack parameter)
                vm.guest_registers.rsp + 0x30, // FileAttributes
                vm.guest_registers.rsp + 0x38, // ShareAccess
                vm.guest_registers.rsp + 0x40, // CreateDisposition
                vm.guest_registers.rsp + 0x48, // CreateOptions
                vm.guest_registers.rsp + 0x50, // EaBuffer (pointer)
                vm.guest_registers.rsp + 0x58  // EaLength
            );

            // Align the guest physical address from the EPT hook to the base page size.
            let guest_page_pa = ept_hook.guest_pa.align_down_to_base_page().as_u64();

            vm.primary_ept.swap_page(guest_page_pa, guest_page_pa, AccessType::READ_WRITE_EXECUTE, ept_hook.primary_ept_pre_alloc_pt.as_mut())?;

            set_monitor_trap_flag(true);
        }
        None => {
            warn!("Unhandled VMCALL number: {:#x}", vmcall_number);
            return Ok(ExitType::Continue);
        }
    };

    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    // Return the exit type to continue VM execution.
    Ok(ExitType::Continue)
}
