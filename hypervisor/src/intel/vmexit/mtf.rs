use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::AccessType,
            support::{vmread, vmwrite},
            vm::Vm,
            vmexit::ExitType,
        },
    },
    log::trace,
    x86::vmx::vmcs,
};

#[rustfmt::skip]
pub fn handle_monitor_trap_flag(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling Monitor Trap Flag exit.");

    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    // Assuming 'find_hook_by_guest_va' fetches the hook data based on the virtual address space.
    // Access the current hook based on `current_hook_index`
    // Get the EPT hook manager from the VM.
    let hook_manager = vm.hook_manager.as_mut();
    let ept_hook = hook_manager.ept_hooks.get_mut(hook_manager.current_hook_index - 1).ok_or(HypervisorError::FailedToGetCurrentHookIndex)?;

    let hook_size = ept_hook.inline_hook.ok_or(HypervisorError::InlineHookNotFound)?.hook_size();

    // Calculate the end of the range for the overwritten instructions
    let start_of_hooked_range = ept_hook.guest_va.as_u64();

    // To find the last byte that is part of the hook, you calculate it by adding the hook_size to the start address and then subtracting 1.
    // This subtraction is key because if you add the size directly to the start address without subtracting 1,
    // you end up one byte past the actual end of the hooked region.
    let end_of_hooked_range = start_of_hooked_range + (hook_size as u64) - 1;
    trace!("Hooked range: Start: {:#x} to End: {:#x}", start_of_hooked_range, end_of_hooked_range);

    // Check if RIP is still within the range of the original overwritten instructions
    let in_range = vm.guest_registers.rip >= start_of_hooked_range && vm.guest_registers.rip <= end_of_hooked_range;
    trace!("RIP: {:#x}, In range: {}", vm.guest_registers.rip, in_range);

    if in_range {
        // Continue single stepping if still within the original function's range
        // Ensure MTF is still enabled for the next instruction
        set_monitor_trap_flag(true);
    } else {
        // If RIP is out of range, disable MTF and restore the hook
        set_monitor_trap_flag(false);
        vm.primary_ept.swap_page(
            ept_hook.guest_pa.align_down_to_base_page().as_u64(),
            ept_hook.host_shadow_page_pa.align_down_to_base_page().as_u64(),
            AccessType::EXECUTE,
            ept_hook.primary_ept_pre_alloc_pt.as_mut()
        )?;
    }

    trace!("Monitor Trap Flag handled, continuing post-trampoline execution.");

    trace!("Register state after handling VM exit: {:?}", vm.guest_registers);

    Ok(ExitType::Continue)
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
