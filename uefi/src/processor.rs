//! This module provides utility functions for processor-related operations in UEFI,
//! facilitating the initialization of virtualization across multiple processors.

use {
    crate::virtualize::virtualize_system,
    core::ffi::c_void,
    hypervisor::intel::capture::{capture_registers, GuestRegisters},
    log::*,
    uefi::{prelude::*, proto::pi::mp::MpServices},
};

/// Starts the hypervisor on all processors.
///
/// # Arguments
///
/// * `boot_services` - A reference to the UEFI Boot Services.
///
/// # Returns
///
/// A result indicating the success or failure of starting the hypervisor.
pub fn start_hypervisor_on_all_processors(boot_services: &BootServices) -> uefi::Result<()> {
    if cfg!(feature = "hyperv") {
        warn!("Hyper-V feature is enabled");
        start_hypervisor();
        // Multi-processor initialization is not supported in Hyper-V mode yet (ACPI).
    } else {
        let handle = boot_services.get_handle_for_protocol::<MpServices>()?;
        let mp_services = boot_services.open_protocol_exclusive::<MpServices>(handle)?;
        let processor_count = mp_services.get_number_of_processors()?;

        info!("Total processors: {}", processor_count.total);
        info!("Enabled processors: {}", processor_count.enabled);

        if processor_count.enabled == 1 {
            info!("Found only one processor, virtualizing it");
            start_hypervisor();
        } else {
            info!("Found multiple processors, virtualizing all of them");

            // Don't forget to virtualize this thread...
            start_hypervisor();

            // Virtualize all other threads...
            mp_services.startup_all_aps(true, start_hypervisor_on_ap as _, core::ptr::null_mut(), None, None)?;
        }

        info!("The hypervisor has been installed successfully!");
    }

    Ok(())
}

/// Hypervisor initialization procedure for Application Processors (APs).
///
/// # Arguments
///
/// * `procedure_argument` - A pointer to the `*mut c_void`.
extern "efiapi" fn start_hypervisor_on_ap(_procedure_argument: *mut c_void) {
    start_hypervisor();
}

/// Initiates the virtualization process.
fn start_hypervisor() {
    let mut guest_registers = GuestRegisters::default();
    // Unsafe block to capture the current CPU's register state.
    let is_virtualized = unsafe { capture_registers(&mut guest_registers) };

    // After `vmlaunch`, Guest execution will begin here. We then check for an existing hypervisor:
    // if absent, proceed with installation; otherwise, no further action is needed.
    // The guest will return here and it will have it's value of rax set to 1, meaning the logical core is virtualized.
    guest_registers.rax = 1;

    // Proceed with virtualization only if the current processor is not yet virtualized.
    debug!("Is virtualized: {}", is_virtualized);
    if !is_virtualized {
        debug!("Virtualizing the system");
        virtualize_system(&guest_registers);
    }
}
