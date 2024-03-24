//! A crate for managing hypervisor functionality, particularly focused on
//! Extended Page Tables (EPT) and Model-Specific Register (MSR) bitmaps.
//! Includes support for primary and optional secondary EPTs.

use x86::msr;
use {
    crate::{
        error::HypervisorError,
        intel::{bitmap::MsrBitmap, ept::Ept},
    },
    alloc::boxed::Box,
    x86::msr::IA32_EFER,
};

/// Represents shared data structures for hypervisor operations.
///
/// This struct manages the MSR (Model-Specific Register) bitmap and Extended Page Tables (EPT)
/// for the hypervisor, enabling memory virtualization and control over certain processor features.
#[repr(C)]
pub struct SharedData {
    /// A bitmap for handling MSRs.
    pub msr_bitmap: Box<MsrBitmap>,

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

        let mut msr_bitmap = MsrBitmap::new();

        // Intercept read and write operations for the IA32_LSTAR MSR.
        // The value of 'true' indicates a write operation` and 'false' indicates a read operation
        msr_bitmap.mask(msr::IA32_LSTAR, false);
        msr_bitmap.mask(msr::IA32_LSTAR, true);

        Ok(Box::new(Self {
            msr_bitmap,
            primary_ept,
            primary_eptp,
            secondary_ept,
            secondary_eptp,
        }))
    }
}
