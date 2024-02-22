//! A crate for managing hypervisor functionality, particularly focused on
//! Extended Page Tables (EPT) and Model-Specific Register (MSR) bitmaps.
//! Includes support for primary and optional secondary EPTs.

use {
    crate::{error::HypervisorError, intel::ept::paging::Ept},
    alloc::boxed::Box,
};

/// Represents shared data structures for hypervisor operations.
///
/// This struct manages the MSR (Model-Specific Register) bitmap and Extended Page Tables (EPT)
/// for the hypervisor, enabling memory virtualization and control over certain processor features.
#[repr(C)]
pub struct SharedData {
    /// The primary EPT (Extended Page Tables) for the VM.
    pub primary_ept: Box<Ept>,

    /// The secondary EPTP (Extended Page Tables Pointer) for the VM.
    pub primary_eptp: u64,

    /// The secondary EPT (Extended Page Tables) for the VM.
    pub secondary_ept: Box<Ept>,

    /// The secondary EPTP (Extended Page Tables Pointer) for the VM.
    pub secondary_eptp: u64,
}

impl SharedData {
    /// Creates a new instance of `SharedData` with primary and optionally secondary EPTs.
    ///
    /// This function initializes the MSR bitmap and sets up the EPTs.
    ///
    /// # Arguments
    ///
    /// * `primary_ept`: The primary EPT to be used.
    /// * `secondary_ept`: The secondary EPT to be used if the feature is enabled.
    ///
    /// # Returns
    /// A result containing a boxed `SharedData` instance or an error of type `HypervisorError`.
    pub fn new(
        primary_ept: Box<Ept>,
        secondary_ept: Box<Ept>,
    ) -> Result<Box<Self>, HypervisorError> {
        log::trace!("Initializing shared data");

        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;
        let secondary_eptp = secondary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        Ok(Box::new(Self {
            primary_ept,
            primary_eptp,
            secondary_ept,
            secondary_eptp,
        }))
    }
}
