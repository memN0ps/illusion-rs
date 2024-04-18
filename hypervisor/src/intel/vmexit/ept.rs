use {
    crate::{
        error::HypervisorError,
        intel::{
            hooks::hook::EptHook,
            support::vmread,
            vm::Vm,
            vmerror::EptViolationExitQualification,
            vmexit::{mtf::set_monitor_trap_flag, ExitType},
        },
    },
    log::*,
    x86::{bits64::paging::PAddr, vmx::vmcs},
};

/// Handle VM exits for EPT violations. Violations are thrown whenever an operation is performed on an EPT entry that does not provide permissions to access that page.
/// 29.3.3.2 EPT Violations
/// Table 28-7. Exit Qualification for EPT Violations
#[rustfmt::skip]
pub fn handle_ept_violation(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling EPT Violation VM exit...");

    let guest_pa = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    trace!("Faulting Guest PA: {:#x}", guest_pa);
    //dump_primary_and_secondary_ept(vm, guest_physical_address);

    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);
    trace!("Exit Qualification for EPT Violations: {:#?}", ept_violation_qualification);
    trace!("Faulting Guest RIP: {:#x}", vm.guest_registers.rip);

    if ept_violation_qualification.instruction_fetch && !ept_violation_qualification.executable {
        //   Instruction Fetch: true,
        //   Page Permissions: R:true, W:true, X:false (readable, writable, but non-executable).
        trace!("Execution attempt on non-executable page, switching to shadow page.");
        EptHook::swap_page(vm, guest_pa, true)?;
        set_monitor_trap_flag(true);
    } else if !ept_violation_qualification.instruction_fetch && ept_violation_qualification.executable {
        //   Instruction Fetch: false,
        //   Page Permissions: R:false, W:false, X:true (non-readable, non-writable, but executable).
        trace!("Read/Write attempt on execute-only page, restoring original page.");
        EptHook::swap_page(vm, guest_pa, false)?;
    }
    
    trace!("EPT Violation handled successfully!");

    // Do not increment RIP, since we want it to execute the same instruction again.
    Ok(ExitType::Continue)
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
pub fn handle_ept_misconfiguration(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling EPT Misconfiguration VM exit...");

    // Retrieve the guest physical address that caused the EPT misconfiguration.
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);

    trace!("EPT Misconfiguration: Faulting guest address: {:#x}. This is a critical error that cannot be safely ignored.", guest_physical_address);
    dump_primary_ept_entries(vm, guest_physical_address)?;

    // Trigger a breakpoint exception to halt execution for debugging.
    // Continuing after this point is unsafe due to the potential for system instability.
    unsafe {  core::arch::asm!("int3") };

    // Execution should not continue beyond this point.
    // EPT misconfiguration is a fatal exception and continuing may lead to system crashes.

    // We may chose to exit the hypervisor here instead of triggering a breakpoint exception.
    return Ok(ExitType::ExitHypervisor);
}

/// Dumps the EPT entries for the primary EPT at the specified guest physical address.
///
/// This function is used for debugging EPT misconfigurations and violations and prints the EPT entries for the primary EPTs.
///
/// # Arguments
///
/// * `vm` - The virtual machine instance.
/// * `faulting_guest_pa` - The faulting guest physical address that caused the EPT misconfiguration or violation.
pub fn dump_primary_ept_entries(
    vm: &mut Vm,
    faulting_guest_pa: u64,
) -> Result<(), HypervisorError> {
    // Log the critical error information.
    trace!("Faulting guest address: {:#x}", faulting_guest_pa);

    // Get the hook manager from the VM.
    let hook_manager = vm.hook_manager.as_mut();

    // Align the faulting guest physical address to the base page size.
    let faulting_guest_page_pa = PAddr::from(faulting_guest_pa)
        .align_down_to_base_page()
        .as_u64();
    trace!("Faulting guest page address: {:#x}", faulting_guest_page_pa);

    let ept_hook = hook_manager
        .find_hook_by_guest_page_pa(faulting_guest_pa)
        .ok_or(HypervisorError::HookNotFound)?;

    // Get the primary EPTs.
    let primary_ept = &mut vm.primary_ept;

    trace!(
        "Dumping Primary EPT entries for guest physical address: {:#x}",
        faulting_guest_pa
    );
    primary_ept.dump_ept_entries(
        faulting_guest_pa,
        ept_hook.primary_ept_pre_alloc_pt.as_ref(),
    );

    Ok(())
}
