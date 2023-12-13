use crate::intel::support::vmread;
use crate::intel::vmexit::ExitType;
use crate::utils::capture::GuestRegisters;
use x86::vmx::vmcs;

/// Handle VM exits for EPT violations. Violations are thrown whenever an operation is performed on an EPT entry that does not provide permissions to access that page.
pub fn handle_ept_violation(_guest_registers: &mut GuestRegisters) -> ExitType {
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    log::info!(
        "EPT Violation: Guest Physical Address: {:#x}",
        guest_physical_address
    );

    let exit_qualification = vmread(vmcs::ro::EXIT_QUALIFICATION);
    log::info!(
        "EPT Violation: Exit Qualification: {:#x}",
        exit_qualification
    );

    //ept_handle_page_hook_exit(exit_qualification, guest_physical_address);

    ExitType::IncrementRIP
}

/*
fn ept_handle_page_hook_exit(exit_qualification: u64, guest_physical_address: u64) -> bool {

    return true;
}
*/

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
pub fn handle_ept_misconfiguration() -> ExitType {
    // Retrieve the guest physical address that caused the EPT misconfiguration.
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);

    // Log the critical error information.
    log::info!(
        "EPT Misconfiguration: Faulting guest address: {:#x}. This is a critical error that cannot be safely ignored.",
        guest_physical_address
    );

    // Trigger a breakpoint exception to halt execution for debugging.
    // Continuing after this point is unsafe due to the potential for system instability.
    unsafe {
        core::arch::asm!("int3");
    }

    // Execution should not continue beyond this point.
    // EPT misconfiguration is a fatal exception and continuing may lead to system crashes.

    // We may chose to exit the hypervisor here instead of triggering a breakpoint exception.
    return ExitType::ExitHypervisor;
}
