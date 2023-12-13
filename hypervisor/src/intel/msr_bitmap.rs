//! This module provides utilities and structures to manage the MSR Bitmap in VMX.
//! The MSR Bitmap is used to control the behavior of RDMSR and WRMSR instructions
//! in a virtualized environment.

use {
    crate::{error::HypervisorError, utils::alloc::PhysicalAllocator},
    alloc::boxed::Box,
};

/// Represents the MSR Bitmap structure used in VMX.
///
/// In processors that support the 1-setting of the “use MSR bitmaps” VM-execution control,
/// the VM-execution control fields include the 64-bit physical address of four contiguous
/// MSR bitmaps, which are each 1-KByte in size.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.6.9 MSR-Bitmap Address
#[repr(C, align(4096))]
pub struct MsrBitmap {
    /// Read bitmap for low MSRs. Contains one bit for each MSR address in the range 00000000H to 00001FFFH.
    /// Determines whether an execution of RDMSR applied to that MSR causes a VM exit.
    pub read_low_msrs: [u8; 0x400],

    /// Read bitmap for high MSRs. Contains one bit for each MSR address in the range C0000000H to C0001FFFH.
    /// Determines whether an execution of RDMSR applied to that MSR causes a VM exit.
    pub read_high_msrs: [u8; 0x400],

    /// Write bitmap for low MSRs. Contains one bit for each MSR address in the range 00000000H to 00001FFFH.
    /// Determines whether an execution of WRMSR applied to that MSR causes a VM exit.
    pub write_low_msrs: [u8; 0x400],

    /// Write bitmap for high MSRs. Contains one bit for each MSR address in the range C0000000H to C0001FFFH.
    /// Determines whether an execution of WRMSR applied to that MSR causes a VM exit.
    pub write_high_msrs: [u8; 0x400],
}

impl MsrBitmap {
    /// Sets up the MSR Bitmap.
    ///
    /// This function initializes and configures the MSR Bitmap for use in VMX.
    /// It also logs the virtual address of the allocated MSR Bitmap.
    ///
    /// # Arguments
    ///
    /// * `msr_bitmap` - A mutable reference to the MSR Bitmap to be set up.
    ///
    /// # Returns
    ///
    /// A result indicating the success or failure of the setup operation.
    pub fn setup(
        msr_bitmap: &mut Box<MsrBitmap, PhysicalAllocator>,
    ) -> Result<(), HypervisorError> {
        log::info!("Setting up MSR-Bitmap");

        // TODO, if needed

        log::info!("MSR-Bitmap Virtual Address: {:p}", msr_bitmap);

        log::info!("MSR-Bitmap setup successful!");

        Ok(())
    }
}
