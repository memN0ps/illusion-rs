use alloc::boxed::Box;
use bitfield::BitMut;

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
    /// Creates a new MSR bitmap with all bits cleared.
    ///
    /// # Returns
    ///
    /// * A `Result` indicating the success or failure of the setup process.
    pub fn new() -> Box<MsrBitmap> {
        log::trace!("Setting up MSR Bitmap");

        let _instance = Self {
            read_low_msrs: [0; 0x400],
            read_high_msrs: [0; 0x400],
            write_low_msrs: [0; 0x400],
            write_high_msrs: [0; 0x400],
        };

        let msr_bitmap = Box::new(_instance);

        log::trace!("MSR Bitmap setup successfully!");

        msr_bitmap
    }

    /// Masks a specific MSR for interception on read or write operations.
    ///
    /// # Arguments
    ///
    /// * `msr` - The MSR to intercept.
    /// * `is_write` - Specifies whether to intercept write operations. If `false`, read operations are intercepted.
    ///
    /// # Example
    ///
    /// * Enable VM-exit on read operations to LSTAR
    /// `msr_bitmap.mask(IA32_LSTAR, false); // 'false' indicates a read operation`
    //
    /// * Enable VM-exit on write operations to LSTAR
    /// `msr_bitmap.mask(IA32_LSTAR, true); // 'true' indicates a write operation`
    pub fn mask(&mut self, msr: u32, is_write: bool) {
        let msr_low = msr & 0x1FFF;
        let msr_index = (msr_low >> 3) as usize;
        let msr_bit = (msr_low & 7) as u8;

        let bitmap_section = match (msr >= 0xC000_0000, is_write) {
            (true, true) => &mut self.write_high_msrs,
            (true, false) => &mut self.read_high_msrs,
            (false, true) => &mut self.write_low_msrs,
            (false, false) => &mut self.read_low_msrs,
        };

        bitmap_section[msr_index].set_bit(msr_bit as usize, true);
    }
}
