//! This crate includes functionalities to interpret and modify Portable Executable (PE) format images used in Windows operating systems,
//! as well as to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use {
    crate::{
        error::HypervisorError,
        intel::{support::vmwrite, vm::Vm, vmexit::ExitType},
        windows::guest::{command::GuestAgentCommand, entry::asm_guest_agent_entry_point},
    },
    log::trace,
    x86::vmx::vmcs,
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
        Ok(VmcallCommand::InjectGuestAgentTask) => inject_guest_agent_task(vm, vmcall_number)?,

        // Handle the restore guest context command.
        Ok(VmcallCommand::RestoreGuestContext) => restore_guest_context(vm)?,

        // Handle an unknown VMCALL command number.
        Err(_) => {
            log::error!("Unknown VMCALL command number: {:#x}", vmcall_number);
            return Err(HypervisorError::UnknownVmcallCommand);
        }
    }

    // Return the exit type to continue VM execution.
    Ok(ExitType::Continue)
}

/// Injects a guest agent task into the guest by transferring control to the guest agent entry point.
///
/// This function is called when the guest issues a VMCALL command to the hypervisor.
///
/// # Parameters
///
/// * `vm`: A mutable reference to the virtual machine instance.
/// * `command_number`: The command number issued by the guest to the hypervisor.
///
/// # Returns
///
/// * `Ok(())`: If the guest agent task is successfully injected.
pub fn inject_guest_agent_task(vm: &mut Vm, command_number: u64) -> Result<(), HypervisorError> {
    trace!("Transferring to the guest agent.");

    // Save the original guest RIP and RSP values.
    vm.host_guest_agent_context.original_guest_rip = vm.guest_registers.rip;
    vm.host_guest_agent_context.original_guest_rsp = vm.guest_registers.rsp;

    // Save the original guest RAX value.
    vm.host_guest_agent_context.original_guest_rax = vm.guest_registers.rax;

    // Convert the command number to a GuestAgentCommand enum.
    vm.host_guest_agent_context.command_number = GuestAgentCommand::try_from(command_number)?;

    // Get the guest agent stack address from the shared data.
    let guest_agent_stack = unsafe { vm.shared_data.as_mut().guest_agent_stack };

    // Set the guest RIP and RSP to the guest agent entry point and stack address.
    vmwrite(vmcs::guest::RIP, asm_guest_agent_entry_point as u64);
    vmwrite(vmcs::guest::RSP, guest_agent_stack);

    Ok(())
}

/// Restores the guest's context from a previously saved state.
///
/// This function is called after the guest agent has completed its task and the hypervisor needs to return control to the guest.
///
/// # Parameters
///
/// * `vm`: A mutable reference to the virtual machine instance.
///
/// # Returns
///
/// * `Ok(())`: If the guest context is successfully restored.
pub fn restore_guest_context(vm: &mut Vm) -> Result<(), HypervisorError> {
    trace!("Returning from the guest agent.");

    // Restore the original guest RIP and RSP values.
    vmwrite(
        vmcs::guest::RIP,
        vm.host_guest_agent_context.original_guest_rip,
    );
    vmwrite(
        vmcs::guest::RSP,
        vm.host_guest_agent_context.original_guest_rsp,
    );

    // Restore the original guest RAX value.
    vm.guest_registers.rax = vm.host_guest_agent_context.original_guest_rax;

    Ok(())
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

impl Default for VmcallCommand {
    /// Returns the default VMCALL command number.
    fn default() -> Self {
        VmcallCommand::InjectGuestAgentTask
    }
}
