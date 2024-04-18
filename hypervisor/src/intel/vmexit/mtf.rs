use {
    crate::intel::{
        support::{vmread, vmwrite},
        vm::Vm,
        vmexit::ExitType,
    },
    log::trace,
    x86::vmx::vmcs,
};

pub fn handle_monitor_trap_flag(vm: &mut Vm) -> ExitType {
    trace!("Handling Monitor Trap Flag exit.");

    // Presumably, you would check if the instruction pointer is within the range of the trampoline
    // If it is, you may want to single step through the trampoline code or execute some cleanup logic.
    // Here, disable MTF if the trampoline has finished executing or certain conditions are met.
    set_monitor_trap_flag(false);

    // Perform any specific actions post-trampoline execution here, such as logging or cleanup.
    trace!("Monitor Trap Flag handled, continuing post-trampoline execution.");

    ExitType::Continue
}

/// Set the monitor trap flag
///
/// # Arguments
///
/// * `set` - A flag indicating whether to set the monitor trap flag.
pub fn set_monitor_trap_flag(set: bool) {
    let controls = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
    let mut primary_controls =
        unsafe { vmcs::control::PrimaryControls::from_bits_unchecked(controls as u32) };

    if set {
        // Enabling the monitor trap flag
        primary_controls.insert(vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG);
    } else {
        // Disabling the monitor trap flag
        primary_controls.remove(vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG);
    }

    vmwrite(
        vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
        primary_controls.bits(),
    );
    trace!("Monitor Trap Flag set to: {}", set);
}
