//! This crate includes functionalities to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use {
    crate::{
        error::HypervisorError,
        intel::{vm::Vm, vmexit::ExitType},
    },
    log::trace,
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
    log::debug!("Handling VMCALL VM exit...");

    // Get the VMCALL command number from the guest's RAX register.
    let vmcall_number = vm.guest_registers.rax;

    trace!("VMCALL command number: {:#x}", vmcall_number);

    // Return the exit type to continue VM execution.
    Ok(ExitType::Continue)
}
