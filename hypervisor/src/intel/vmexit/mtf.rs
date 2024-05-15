use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            ept::AccessType,
            support::{vmread, vmwrite},
            vm::Vm,
            vmexit::ExitType,
        },
    },
    log::*,
    x86::{current::paging::PAddr, vmx::vmcs},
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
pub fn handle_monitor_trap_flag(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling Monitor Trap Flag exit.");

    if let Some(counter) = vm.hook_manager.mtf_counter.as_mut() {
        trace!("Guest RIP: {:#x}", vm.guest_registers.rip);
        trace!("MTF counter before decrement: {}", *counter);
        *counter = counter.saturating_sub(1); // Safely decrement the counter
        trace!("MTF counter after decremented: {}", *counter);

        // If the counter is zero, we have completed the single-stepping process, restore the hook.
        if *counter == 0 {
            set_monitor_trap_flag(false);

            let guest_pa = PAddr::from(PhysicalAddress::pa_from_va(vm.guest_registers.rip));
            trace!("Guest PA: {:#x}", guest_pa.as_u64());

            let guest_page_pa = guest_pa.align_down_to_base_page();

            let shadow_page_pa = PAddr::from(
                vm.hook_manager
                    .memory_manager
                    .get_shadow_page_as_ptr(guest_page_pa.as_u64())
                    .ok_or(HypervisorError::ShadowPageNotFound)?,
            );
            trace!("Shadow Page PA: {:#x}", shadow_page_pa);

            let pre_alloc_pt = vm
                .hook_manager
                .memory_manager
                .get_page_table_as_mut(guest_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            // Restore the hook to continue monitoring
            vm.primary_ept
                .swap_page(guest_pa.align_down_to_base_page().as_u64(), shadow_page_pa.as_u64(), AccessType::EXECUTE, pre_alloc_pt)?;

            restore_guest_interrupt_flag(vm)?;
        } else {
            set_monitor_trap_flag(true); // Keep MTF enabled if there are more steps
        }
    } else {
        error!("No active MTF counter found, possibly an error in state management.");
        return Err(HypervisorError::MtfCounterNotSet);
    }

    Ok(ExitType::Continue)
}

/// Set the monitor trap flag
///
/// # Arguments
///
/// * `set` - A flag indicating whether to set the monitor trap flag.
pub fn set_monitor_trap_flag(set: bool) {
    let controls = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
    let mut primary_controls = unsafe { vmcs::control::PrimaryControls::from_bits_unchecked(controls as u32) };

    if set {
        // Enabling the monitor trap flag
        primary_controls.insert(vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG);
    } else {
        // Disabling the monitor trap flag
        primary_controls.remove(vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG);
    }

    vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, primary_controls.bits());
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
