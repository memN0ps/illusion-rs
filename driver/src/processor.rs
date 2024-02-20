//! This module provides utility functions for processor-related operations in UEFI,
//! facilitating the initialization of virtualization across multiple processors.

use {
    crate::virtualize::virtualize_system,
    core::{
        ffi::c_void,
        sync::atomic::{AtomicU64, Ordering},
    },
    hypervisor::intel::capture::{capture_registers, GuestRegisters},
    log::*,
    uefi::{
        prelude::*,
        proto::pi::mp::{MpServices, Procedure, ProcessorCount},
        table::boot::ScopedProtocol,
    },
};

/// Tracks the virtualization status of processors.
///
/// Each bit in this `AtomicU64` represents the virtualization status of a processor:
/// a set bit indicates that the processor has been virtualized.
pub static VIRTUALIZED_BITSET: AtomicU64 = AtomicU64::new(0);

pub struct MpManager<'a> {
    /// UEFI MP Services Protocol instance.
    mp_services: ScopedProtocol<'a, MpServices>,
}

impl<'a> MpManager<'a> {
    /// Creates a new `MpManager` instance by acquiring the MP Services Protocol.
    ///
    /// # Arguments
    ///
    /// * `bt` - A reference to the UEFI Boot Services.
    ///
    /// # Returns
    ///
    /// A result containing the new `MpManager` instance or an error.
    pub fn new(bt: &'a BootServices) -> uefi::Result<Self> {
        let handle = bt.get_handle_for_protocol::<MpServices>()?;
        let mp_services = bt.open_protocol_exclusive::<MpServices>(handle)?;
        Ok(Self { mp_services })
    }

    /// Initiates virtualization on all processors by executing the provided procedure.
    ///
    /// # Arguments
    ///
    /// * `procedure` - The function to execute on all application processors.
    /// * `procedure_argument` - A pointer to the argument to pass to the procedure.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure of the operation.
    pub fn start_virtualization_on_all_processors(
        &self,
        procedure: Procedure,
        procedure_argument: *mut c_void,
    ) -> uefi::Result<()> {
        self.mp_services
            .startup_all_aps(false, procedure, procedure_argument, None, None)
    }

    /// Determines if the current processor is already virtualized.
    ///
    /// # Returns
    ///
    /// True if the current processor is virtualized, false otherwise.
    pub fn is_virtualized(&self) -> bool {
        let current_processor_index = self.current_processor_index().unwrap_or(0);
        let bit = 1 << current_processor_index;
        VIRTUALIZED_BITSET.load(Ordering::SeqCst) & bit != 0
    }

    /// Marks the current processor as virtualized.
    pub fn set_virtualized(&self) {
        let current_processor_index = self.current_processor_index().unwrap_or(0);
        let bit = 1 << current_processor_index;
        VIRTUALIZED_BITSET.fetch_or(bit, Ordering::SeqCst);
    }

    /// Retrieves the number of active logical processors.
    ///
    /// # Returns
    ///
    /// A result containing the processor count or an error.
    pub fn processor_count(&self) -> uefi::Result<ProcessorCount> {
        self.mp_services.get_number_of_processors()
    }

    /// Identifies the index of the logical processor that is calling this method.
    ///
    /// # Returns
    ///
    /// A result containing the processor index or an error.
    pub fn current_processor_index(&self) -> uefi::Result<usize> {
        self.mp_services.who_am_i()
    }
}

/// Starts the hypervisor on all processors.
///
/// # Arguments
///
/// * `system_table` - A reference to the UEFI System Table.
///
/// # Returns
///
/// A result indicating the success or failure of starting the hypervisor.
pub fn start_hypervisor_on_all_processors(system_table: &SystemTable<Boot>) -> uefi::Result<()> {
    let mp_manager = MpManager::new(system_table.boot_services())?;
    let processor_count = mp_manager.processor_count()?;

    info!(
        "Total processors: {}, Enabled processors: {}",
        processor_count.total, processor_count.enabled
    );

    if processor_count.enabled == 1 {
        info!("Found only one processor, virtualizing it");
        start_hypervisor(&mp_manager);
    } else {
        info!("Found multiple processors, virtualizing all of them");
        mp_manager.start_virtualization_on_all_processors(
            start_hypervisor_on_ap,
            &mp_manager as *const _ as *mut _,
        )?;
    }

    info!("The hypervisor has been installed successfully!");

    Ok(())
}

/// Hypervisor initialization procedure for Application Processors (APs).
///
/// # Arguments
///
/// * `procedure_argument` - A pointer to the `MpManager` instance.
extern "efiapi" fn start_hypervisor_on_ap(procedure_argument: *mut c_void) {
    let mp_manager = unsafe { &*(procedure_argument as *const MpManager) };
    start_hypervisor(mp_manager);
}

/// Initiates the virtualization process.
///
/// # Arguments
///
/// * `mp_manager` - A reference to the `MpManager` to check and set virtualization status.
fn start_hypervisor(mp_manager: &MpManager) {
    let mut guest_registers = GuestRegisters::default();
    // Unsafe block to capture the current CPU's register state.
    unsafe { capture_registers(&mut guest_registers) };

    // After capturing RIP, Guest execution will begin here. We then check for an existing hypervisor:
    // if absent, proceed with installation; otherwise, no further action is needed.

    // Proceed with virtualization only if the current processor is not yet virtualized.
    if !mp_manager.is_virtualized() {
        debug!("Virtualizing the system");
        mp_manager.set_virtualized();
        virtualize_system(&guest_registers);
    }
}
