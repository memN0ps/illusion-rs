use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::AccessType,
            hooks::hook::EptHook,
            support::{vmread, vmwrite},
            vm::Vm,
            vmexit::ExitType,
        },
    },
    log::trace,
    x86::vmx::vmcs,
    x86_64::registers::rflags::RFlags,
};

/// Handles the Monitor Trap Flag (MTF) VM exit.
///
/// This function ensures single stepping through overwritten instructions on a hooked function
/// and restores the original execution flow once all instructions have been executed.
///
/// # Parameters
/// * `vm`: A mutable reference to the virtual machine instance.
///
/// # Returns
/// * `Result<ExitType, HypervisorError>`: Ok with the appropriate exit type or an error.
#[rustfmt::skip]
pub fn handle_monitor_trap_flag(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling Monitor Trap Flag exit.");
    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    let hook_manager = &mut vm.hook_manager;
    let ept_hook = hook_manager
        .find_hook_by_guest_va_as_mut(vm.guest_registers.rip)
        .ok_or(HypervisorError::HookNotFound)?;

    // Dynamic range calculation
    let start_of_hook = ept_hook.guest_va.as_u64();
    let end_of_hook = start_of_hook + calculate_original_instructions_length(ept_hook) as u64;
    let current_rip = vm.guest_registers.rip;

    trace!("Hooked range: Start: {:#x}, End: {:#x}, Current RIP: {:#x}", start_of_hook, end_of_hook, current_rip);

    if current_rip >= start_of_hook && current_rip < end_of_hook {
        // Continue single stepping if within the hooked instruction range
        set_monitor_trap_flag(true);
        Ok(ExitType::Continue)
    } else {
        // If RIP is out of range, disable MTF and restore the original page and interrupt flag.
        set_monitor_trap_flag(false);
        vm.primary_ept.swap_page(
            ept_hook.guest_pa.align_down_to_base_page().as_u64(),
            ept_hook.host_shadow_page_pa.align_down_to_base_page().as_u64(),
            AccessType::EXECUTE,
            ept_hook.primary_ept_pre_alloc_pt.as_mut()
        )?;
        restore_guest_interrupt_flag(vm)?;
        trace!("Monitor Trap Flag disabled, original execution restored.");
        Ok(ExitType::Continue)
    }
}

/// Calculates the total length of the original instructions over the hook.
fn calculate_original_instructions_length(hook: &EptHook) -> usize {
    let base_address = hook.guest_pa.as_u64() as *const u8;
    let bytes = unsafe {
        core::slice::from_raw_parts(base_address, hook.inline_hook.as_ref().unwrap().hook_size())
    };
    lde::X64
        .iter(bytes, hook.guest_va.as_u64())
        .map(|(opcode, _)| opcode.len())
        .sum()
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

/// Sets or clears the Interrupt Flag (IF) in the guest's RFLAGS register based on the specified state,
/// and stores the old RFLAGS value for potential restoration.
///
/// # Parameters
/// * `vm`: A mutable reference to the virtual machine instance.
/// * `enable`: If `true`, sets the Interrupt Flag; if `false`, clears the Interrupt Flag and optionally restores from old RFLAGS.
///
/// # Returns
/// * `Result<(), HypervisorError>`: Ok if successful, Err if an error occurred during VMCS read/write operations.
#[rustfmt::skip]
pub fn update_guest_interrupt_flag(vm: &mut Vm, enable: bool) -> Result<(), HypervisorError> {
    trace!("Updating guest interrupt flag...");

    // Retrieve the current RFLAGS from the VMCS guest state area
    let current_rflags_bits = vmread(vmcs::guest::RFLAGS);
    let mut current_rflags = RFlags::from_bits_retain(current_rflags_bits);
    trace!("Current guest RFLAGS before update: {:#x}", current_rflags_bits);

    // Optionally save the current RFLAGS to old_rflags before modification
    vm.hook_manager.old_rflags = Some(current_rflags_bits);

    // Set or clear the Interrupt Flag based on the 'enable' parameter
    if enable {
        current_rflags.insert(RFlags::INTERRUPT_FLAG);
    } else {
        current_rflags.remove(RFlags::INTERRUPT_FLAG);
    }

    // Update the guest's RFLAGS register in the VMCS
    vmwrite(vmcs::guest::RFLAGS, current_rflags.bits());
    trace!("Updated guest RFLAGS: {:#x}", current_rflags.bits());

    // Synchronize the local VM state if necessary
    vm.guest_registers.rflags = current_rflags.bits();

    Ok(())
}

/// Restores the guest's RFLAGS register from the saved old RFLAGS.
///
/// # Parameters
/// * `vm`: A mutable reference to the virtual machine instance.
///
/// # Returns
/// * `Result<(), HypervisorError>`: Ok if successful, Err if an error occurred during VMCS read/write operations.
#[rustfmt::skip]
pub fn restore_guest_interrupt_flag(vm: &mut Vm) -> Result<(), HypervisorError> {
    if let Some(old_rflags_bits) = vm.hook_manager.old_rflags {
        trace!("Restoring guest RFLAGS to old value: {:#x}", old_rflags_bits);

        // Update VM register state first
        vm.guest_registers.rflags = old_rflags_bits;

        // Then write to VMCS
        vmwrite(vmcs::guest::RFLAGS, old_rflags_bits);
        Ok(())
    } else {
        Err(HypervisorError::OldRflagsNotSet)
    }
}
