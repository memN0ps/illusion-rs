use {
    crate::{
        error::HypervisorError,
        intel::{ept::Pt, hooks::hook_manager::SHARED_HOOK_MANAGER, support::vmread, vm::Vm, vmexit::ExitType},
    },
    log::trace,
    x86::{bits64::paging::PAddr, vmx::vmcs},
};

/// Handles an EPT misconfiguration VM exit.
///
/// This function is invoked when an EPT misconfiguration VM exit occurs, indicating
/// an issue with the Extended Page Tables (EPT) setup. It logs the faulting
/// guest physical address and returns a `HypervisorError` for immediate debugging.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
///
/// # Returns
///
/// * `Result<ExitType, HypervisorError>` - Returns a `HypervisorError` indicating a critical issue with the EPT configuration.
pub fn handle_ept_misconfiguration(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling EPT Misconfiguration VM exit...");

    // Retrieve the guest physical address that caused the EPT misconfiguration.
    let guest_physical_address = PAddr::from(vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL));

    trace!(
        "EPT Misconfiguration: Faulting guest address: {:#x}. This is a critical error that cannot be safely ignored.",
        guest_physical_address.as_u64()
    );

    // Lock the shared hook manager
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    let pre_alloc_pt = hook_manager
        .memory_manager
        .get_page_table_as_mut(guest_physical_address.align_down_to_large_page().as_u64())
        .ok_or(HypervisorError::PageTableNotFound)?;

    dump_primary_ept_entries(vm, guest_physical_address.as_u64(), pre_alloc_pt)?;

    // Return a HypervisorError indicating a critical issue with the EPT configuration.
    Err(HypervisorError::EptMisconfiguration)
}

/// Dumps the EPT entries for the primary EPT at the specified guest physical address.
///
/// This function is used for debugging EPT misconfigurations and violations and prints the EPT entries for the primary EPTs.
///
/// # Arguments
///
/// * `vm` - The virtual machine instance.
/// * `faulting_guest_pa` - The faulting guest physical address that caused the EPT misconfiguration or violation.
/// * `pre_alloc_pt` - The pre-allocated page table to be used for the entries.
pub fn dump_primary_ept_entries(vm: &mut Vm, faulting_guest_pa: u64, pre_alloc_pt: &mut Pt) -> Result<(), HypervisorError> {
    // Log the critical error information.
    trace!("Faulting guest address: {:#x}", faulting_guest_pa);

    // Align the faulting guest physical address to the base page size.
    let faulting_guest_page_pa = PAddr::from(faulting_guest_pa).align_down_to_base_page().as_u64();
    trace!("Faulting guest page address: {:#x}", faulting_guest_page_pa);

    let guest_large_page_pa = PAddr::from(faulting_guest_pa).align_down_to_large_page();
    trace!("Faulting guest large page address: {:#x}", guest_large_page_pa);

    // Get the primary EPTs.
    let primary_ept = &mut vm.primary_ept;

    trace!("Dumping Primary EPT entries for guest physical address: {:#x}", faulting_guest_pa);
    primary_ept.dump_ept_entries(faulting_guest_pa, pre_alloc_pt);

    Ok(())
}
