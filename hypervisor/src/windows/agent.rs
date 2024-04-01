use {
    crate::{
        error::HypervisorError,
        intel::{support::vmwrite, vm::Vm},
    },
    log::*,
    x86::vmx::vmcs,
};

pub fn restore_guest_context(vm: &mut Vm) -> Result<(), HypervisorError> {
    trace!("Returning from the guest agent.");

    vmwrite(vmcs::guest::RIP, vm.host_guest_agent_context.rip);
    vmwrite(vmcs::guest::RSP, vm.host_guest_agent_context.rsp);

    Ok(())
}

pub fn inject_guest_agent_task(vm: &mut Vm, command_number: u64) -> Result<(), HypervisorError> {
    trace!("Transferring to the guest agent.");

    vm.host_guest_agent_context.rip = vm.guest_registers.rip;
    vm.host_guest_agent_context.rsp = vm.guest_registers.rsp;
    vm.host_guest_agent_context.command_number = command_number;
    let guest_agent_stack = unsafe { vm.shared_data.as_mut().guest_agent_stack };

    vmwrite(vmcs::guest::RIP, guest_agent_entry_point as u64);
    vmwrite(vmcs::guest::RSP, guest_agent_stack);

    Ok(())
}

// Guest Agent entry point in Rust. Actual implementation would likely involve inline assembly.
extern "C" fn guest_agent_entry_point() {
    // Hook installation logic here
    // test_windows_kernel_ept_hooks();
}
