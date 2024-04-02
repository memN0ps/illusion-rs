//! This crate includes functionalities to interpret and modify Portable Executable (PE) format images used in Windows operating systems,
//! as well as to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use crate::{
    error::HypervisorError,
    intel::{vm::Vm, vmexit::ExitType},
    windows::guest,
};

/// Represents various VMCALL commands that a guest can issue to the hypervisor.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmcallCommand {
    /// Command to inject a guest agent task into the guest.
    InjectGuestAgentTask = 0x1337,

    /// Command to restore the guest's context from a previously saved state.
    RestoreGuestContext = 0x1338,
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

    match VmcallCommand::try_from(vmcall_number) {
        // Handle the inject guest agent task command.
        Ok(VmcallCommand::InjectGuestAgentTask) => {
            guest::inject_guest_agent_task(vm, vmcall_number)?
        }

        // Handle the restore guest context command.
        Ok(VmcallCommand::RestoreGuestContext) => guest::restore_guest_context(vm)?,

        // Handle an unknown VMCALL command number.
        Err(_) => {
            log::error!("Unknown VMCALL command number: {:#x}", vmcall_number);
            return Err(HypervisorError::UnknownVmcallCommand);
        }
    }

    // Return the exit type to continue VM execution.
    Ok(ExitType::Continue)
}

/// Attempts to convert a u64 value to a VmcallCommand.
impl TryFrom<u64> for VmcallCommand {
    type Error = HypervisorError;

    /// Attempts to convert a u64 value to a VmcallCommand.
    ///
    /// # Parameters
    ///
    /// * `value`: The u64 value to convert to a VmcallCommand.
    ///
    /// # Returns
    ///
    /// * `Ok(VmcallCommand)`: The VmcallCommand value if the conversion is successful.
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == VmcallCommand::InjectGuestAgentTask as u64 => {
                Ok(VmcallCommand::InjectGuestAgentTask)
            }
            x if x == VmcallCommand::RestoreGuestContext as u64 => {
                Ok(VmcallCommand::RestoreGuestContext)
            }
            _ => Err(HypervisorError::UnknownVmcallCommand),
        }
    }
}
