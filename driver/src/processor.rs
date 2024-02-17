//! This module provides utility functions for processor-related operations in UEFI.

use core::sync::atomic::{AtomicU64, Ordering};
use uefi::prelude::*;
use uefi::proto::pi::mp::{MpServices, ProcessorCount};
use uefi::table::boot::ScopedProtocol;

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
