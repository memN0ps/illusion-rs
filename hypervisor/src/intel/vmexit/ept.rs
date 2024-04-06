use {
    crate::{
        error::HypervisorError,
        intel::{
            invept::invept_all_contexts, support::vmread, support::vmwrite, vm::Vm,
            vmerror::EptViolationExitQualification, vmexit::ExitType,
        },
    },
    log::*,
    x86::vmx::vmcs,
};

/// Handle VM exits for EPT violations. Violations are thrown whenever an operation is performed on an EPT entry that does not provide permissions to access that page.
/// 29.3.3.2 EPT Violations
/// Table 28-7. Exit Qualification for EPT Violations
#[rustfmt::skip]
pub fn handle_ept_violation(vm: &mut Vm) -> ExitType {
    debug!("Handling EPT Violation VM exit...");

    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    debug!("EPT Violation: Guest Physical Address: {:#x}", guest_physical_address);

    // Translate the page from a physical address to virtual so we can read its memory.
    //let va = PhysicalAddress::va_from_pa(guest_physical_address);
    //debug!("EPT Violation: Guest Virtual Address: {:#x}", va);

    // Log the detailed information about the EPT violation
    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);
    debug!("Exit Qualification for EPT Violations: {}", ept_violation_qualification);

    // If the page is Read/Write, then we need to swap it to the secondary EPTP
    if ept_violation_qualification.readable && ept_violation_qualification.writable && !ept_violation_qualification.executable {
        //trace!("EPT Violation: Execute acccess attempted on Guest Physical Address: {:#x} / Guest Virtual Address: {:#x}", guest_physical_address, va);
        // Change to the secondary EPTP and invalidate the EPT cache.
        // The hooked page that is Execute-Only will be executed from the secondary EPTP.
        // if Read or Write occurs on that page, then a vmexit will occur
        // and we can swap the page back to the primary EPTP, (original page) with RW permissions.
        let secondary_eptp = unsafe { vm.shared_data.as_ref().secondary_eptp };
        vmwrite(vmcs::control::EPTP_FULL, secondary_eptp);
        invept_all_contexts();
        //invept_single_context(secondary_eptp);
    }

    // If the page is Execute-Only, then we need to swap it back to the primary EPTP
    if !ept_violation_qualification.readable && !ept_violation_qualification.writable && ept_violation_qualification.executable {
        // Change to the primary EPTP and invalidate the EPT cache.
        // The original page that is Read-Write-Only will be executed from the primary EPTP.
        // if Execute occurs on that page, then a vmexit will occur
        // and we can swap the page back to the secondary EPTP, (hooked page) with X permissions.
        let primary_eptp = unsafe { vm.shared_data.as_ref().primary_eptp };
        vmwrite(vmcs::control::EPTP_FULL, primary_eptp);
        invept_all_contexts();
        //invept_single_context(primary_eptp);
    }

    debug!("EPT Violation handled successfully!");

    // Do not increment RIP, since we want it to execute the same instruction again.
    ExitType::Continue
}

/// Handles an EPT misconfiguration VM exit.
///
/// This function is invoked when an EPT misconfiguration VM exit occurs, indicating
/// an issue with the Extended Page Tables (EPT) setup. It logs the faulting
/// guest physical address and triggers a breakpoint exception for immediate debugging.
///
/// # Safety
///
/// This function executes an `int3` instruction, which triggers a breakpoint exception.
/// This is used for debugging critical issues and should be employed cautiously.
/// Appropriate debugging tools must be attached to handle the `int3` exception.
///
/// Note: EPT misconfigurations are critical errors that can lead to system instability or crashes.
/// Continuing normal execution after such an exception is not recommended, as it may result in
/// unpredictable behavior or a crashed operating system.
///
/// Reference: 29.3.3.1 EPT Misconfigurations
#[rustfmt::skip]
pub fn handle_ept_misconfiguration(vm: &mut Vm) -> ExitType {
    debug!("Handling EPT Misconfiguration VM exit...");

    // Retrieve the guest physical address that caused the EPT misconfiguration.
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);

    // Log the critical error information.
    trace!("EPT Misconfiguration: Faulting guest address: {:#x}. This is a critical error that cannot be safely ignored.", guest_physical_address);

    // Get the shared data from the VM.
    let shared_data = unsafe { vm.shared_data.as_mut() };

    // We minus 1 from the current hook index to get the current hook index because the current hook index is incremented when the hook was placed in `ept_hook`.
    trace!("Current Hook Index: {:#x}", shared_data.current_hook_index - 1);

    // Access the current hook based on `current_hook_index`
    let hook = shared_data
        .hook_manager
        .get_mut(shared_data.current_hook_index - 1)
        .ok_or(HypervisorError::FailedToGetCurrentHookIndex).unwrap();

    //trace!("Hook Index {:#x}", shared_data.current_hook_index);

    // Get the primary and secondary EPTs.
    let primary_ept = &mut shared_data.primary_ept;
    let secondary_ept = &mut shared_data.secondary_ept;

    trace!("Dumping Primary EPT entries for guest physical address: {:#x}", guest_physical_address);
    primary_ept.dump_ept_entries(guest_physical_address, hook.pt_table_index);

    trace!("Dumping Secondary EPT entries for guest physical address: {:#x}", guest_physical_address);
    secondary_ept.dump_ept_entries(guest_physical_address, hook.pt_table_index);


    // Trigger a breakpoint exception to halt execution for debugging.
    // Continuing after this point is unsafe due to the potential for system instability.
    unsafe {  core::arch::asm!("int3") };

    // Execution should not continue beyond this point.
    // EPT misconfiguration is a fatal exception and continuing may lead to system crashes.

    // We may chose to exit the hypervisor here instead of triggering a breakpoint exception.
    return ExitType::ExitHypervisor;
}
