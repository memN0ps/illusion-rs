use {
    crate::intel::{
        support::{vmread, vmwrite},
        vm::Vm,
        vmexit::ExitType,
    },
    x86::vmx::vmcs,
};

pub fn handle_monitor_trap_flag(vm: &mut Vm) -> ExitType {
    // TODO: Implement the monitor trap flag handler
    ExitType::Continue
}

/// Set the monitor trap flag
///
/// # Arguments
///
/// * `set` - A flag indicating whether to set the monitor trap flag.
pub fn set_monitor_trap_flag(set: bool) {
    let controls = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
    let mut primary_controls = vmcs::control::PrimaryControls::from_bits_truncate(controls as u32);

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
}
