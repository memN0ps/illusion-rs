use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::AccessType,
            hooks::hook_manager::SHARED_HOOK_MANAGER,
            support::vmread,
            vm::Vm,
            vmerror::EptViolationExitQualification,
            vmexit::{
                mtf::{set_monitor_trap_flag, update_guest_interrupt_flag},
                ExitType,
            },
        },
    },
    log::*,
    x86::{bits64::paging::PAddr, vmx::vmcs},
};

/// Handles VM exits for EPT violations.
/// EPT violations occur when an operation is performed on an EPT entry that does not provide permissions to access that page.
///
/// This function addresses the EPT violation by either swapping the page to a shadow page
/// or restoring the original page based on the exit qualification. It also sets up the monitor trap flag
/// if necessary.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
///
/// # Returns
///
/// * `Result<ExitType, HypervisorError>` - `Ok(ExitType::Continue)` if the EPT violation was handled successfully, or a `HypervisorError` if an error occurred.
pub fn handle_ept_violation(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling EPT Violation VM exit...");

    let guest_pa = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    trace!("Faulting Guest PA: {:#x}", guest_pa);

    let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page();
    trace!("Faulting Guest Page PA: {:#x}", guest_page_pa);

    let guest_large_page_pa = guest_page_pa.align_down_to_large_page();
    trace!("Faulting Guest Large Page PA: {:#x}", guest_large_page_pa);

    // Lock the shared hook manager
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    let shadow_page_pa = PAddr::from(
        hook_manager
            .memory_manager
            .get_shadow_page_as_ptr(guest_page_pa.as_u64())
            .ok_or(HypervisorError::ShadowPageNotFound)?,
    );
    trace!("Shadow Page PA: {:#x}", shadow_page_pa.as_u64());

    let pre_alloc_pt = hook_manager
        .memory_manager
        .get_page_table_as_mut(guest_large_page_pa.as_u64())
        .ok_or(HypervisorError::PageTableNotFound)?;

    // dump_primary_ept_entries(vm, guest_pa, pre_alloc_pt)?;

    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);
    trace!("Exit Qualification for EPT Violations: {:#?}", ept_violation_qualification);
    trace!("Faulting Guest RIP: {:#x}", vm.guest_registers.rip);

    if ept_violation_qualification.readable && ept_violation_qualification.writable && !ept_violation_qualification.executable {
        // if the instruction fetch is true and the page is not executable, we need to swap the page to a shadow page.
        //   Instruction Fetch: true,
        //   Page Permissions: R:true, W:true, X:false (readable, writable, but non-executable).
        trace!("Page Permissions: R:true, W:true, X:false (readable, writable, but non-executable).");
        trace!("Execution attempt on non-executable page, switching to hooked shadow-copy page.");
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), shadow_page_pa.as_u64(), AccessType::EXECUTE, pre_alloc_pt)?;
        trace!("Page swapped successfully!");
    } else if ept_violation_qualification.executable && !ept_violation_qualification.readable && !ept_violation_qualification.writable {
        // if the instruction fetch is false and the page is executable, we need to swap the page to a shadow page.
        //   Instruction Fetch: false,
        //   Page Permissions: R:false, W:false, X:true (non-readable, non-writable, but executable).
        trace!("Read/Write attempt on execute-only page, restoring original page.");
        trace!("Page Permissions: R:false, W:false, X:true (non-readable, non-writable, but executable).");
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;

        // We make this read-write-execute to allow the instruction performing a read-write
        // operation and then switch back to execute-only shadow page from handle_mtf vmexit
        vm.mtf_counter = Some(1);

        // Set the monitor trap flag and initialize counter to the number of overwritten instructions
        set_monitor_trap_flag(true);

        // Ensure all data mutations to vm are done before calling this.
        // This function will update the guest interrupt flag to prevent interrupts while single-stepping
        update_guest_interrupt_flag(vm, false)?;
    }

    trace!("EPT Violation handled successfully!");

    // Do not increment RIP, since we want it to execute the same instruction again.
    Ok(ExitType::Continue)
}
