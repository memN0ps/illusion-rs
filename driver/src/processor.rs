//! This module provides utility functions for processor-related operations in UEFI.

use {
    core::{
        ffi::c_void,
        sync::atomic::{AtomicU64, Ordering},
    },
    uefi::{
        prelude::*,
        proto::pi::mp::{MpServices, Procedure, ProcessorCount},
        table::boot::ScopedProtocol,
    },
};

/// Atomic bitset used to track which processors have been virtualized.
static VIRTUALIZED_BITSET: AtomicU64 = AtomicU64::new(0);

pub struct MpManager<'a> {
    mp_services: ScopedProtocol<'a, MpServices>,
}

impl<'a> MpManager<'a> {
    /// Creates a new instance of MpManager, acquiring the MP Services Protocol.
    pub fn new(bt: &'a BootServices) -> uefi::Result<Self> {
        let handle = bt.get_handle_for_protocol::<MpServices>()?;
        let mp_services = bt.open_protocol_exclusive::<MpServices>(handle)?;
        Ok(Self { mp_services })
    }

    pub fn start_virtualization_on_all_processors(
        &self,
        procedure: Procedure,
        procedure_argument: *mut c_void,
    ) -> uefi::Result<()> {
        // The `procedure` is an `extern "efiapi" fn(_: *mut c_void)` compatible with `Procedure`
        // and performs the necessary actions to initialize virtualization per-processor.
        self.mp_services.startup_all_aps(
            false, // Run on all processors simultaneously.
            procedure,
            procedure_argument,
            None, // No associated event.
            None, // No timeout.
        )
    }

    /// Determines if the current processor is already virtualized.
    pub fn is_virtualized(&self) -> bool {
        let current_processor_index = self.current_processor_index().unwrap_or(0);
        let bit = 1 << current_processor_index;
        VIRTUALIZED_BITSET.load(Ordering::Relaxed) & bit != 0
    }

    /// Marks the current processor as virtualized.
    pub fn set_virtualized(&self) {
        let current_processor_index = self.current_processor_index().unwrap_or(0);
        let bit = 1 << current_processor_index;
        VIRTUALIZED_BITSET.fetch_or(bit, Ordering::Relaxed);
    }

    /// Returns the number of active logical processors.
    pub fn processor_count(&self) -> uefi::Result<ProcessorCount> {
        self.mp_services.get_number_of_processors()
    }

    /// Gets the processor number of the logical processor that the caller is running on.
    pub fn current_processor_index(&self) -> uefi::Result<usize> {
        self.mp_services.who_am_i()
    }
}
