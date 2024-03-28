//! A crate for managing hypervisor functionality, particularly focused on
//! Extended Page Tables (EPT) and Model-Specific Register (MSR) bitmaps.
//! Includes support for primary and optional secondary EPTs.

use {
    crate::{
        error::HypervisorError,
        intel::{
            bitmap::{MsrAccessType, MsrBitmap, MsrOperation},
            ept::{Ept, PT_INDEX_MAX},
            hooks::hook::Hook,
            page::Page,
            vm::box_zeroed,
        },
    },
    alloc::boxed::Box,
    alloc::vec::Vec,
    x86::msr,
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

    /// The hook manager.
    pub hook_manager: Vec<Box<Hook>>,
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
        // msr_bitmap.modify_msr_interception(msr::IA32_LSTAR, MsrAccessType::Read, MsrOperation::Hook);
        #[cfg(feature = "test-windows-uefi-hooks")]
        msr_bitmap.modify_msr_interception(
            msr::IA32_LSTAR,
            MsrAccessType::Write,
            MsrOperation::Hook,
        );

        let mut hook_manager = Vec::new();

        // Pre-Allocated buffer for hooks with PT_INDEX_MAX entries.
        for pt_table_index in 1..PT_INDEX_MAX {
            // Create a pre-allocated shadow page for the hook.
            let shadow_page = unsafe { box_zeroed::<Page>() };

            // Create a new hook and push it to the hook manager.
            let hook = Hook::new(shadow_page, pt_table_index);

            // Save the hook in the hook manager.
            hook_manager.push(hook);
        }

        Ok(Box::new(Self {
            msr_bitmap,
            primary_ept,
            primary_eptp,
            secondary_ept,
            secondary_eptp,
            hook_manager,
        }))
    }
}
