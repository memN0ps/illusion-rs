use bitfield::BitMut;

/// Enum representing the type of MSR access.
///
/// There are two types of MSR access: reading from an MSR and writing to an MSR.
pub enum MsrAccessType {
    /// Read access to an MSR.
    Read,

    /// Write access to an MSR.
    Write,
}

/// Specifies the type of MSR operation: either to hook (mask) or Unhook (unmask).
pub enum MsrOperation {
    /// Mask the MSR to intercept the operation.
    Hook,

    /// Unmask the MSR to allow the operation.
    Unhook,
}

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
    /// Initializes the MSR bitmap by setting all bits to 0.
    pub fn init(&mut self) {
        self.read_low_msrs.iter_mut().for_each(|byte| *byte = 0);
        self.read_high_msrs.iter_mut().for_each(|byte| *byte = 0);
        self.write_low_msrs.iter_mut().for_each(|byte| *byte = 0);
        self.write_high_msrs.iter_mut().for_each(|byte| *byte = 0);
    }

    /// Modifies the interception for a specific MSR based on the specified operation and access type.
    ///
    /// # Arguments
    ///
    /// * `msr` - The MSR to modify.
    /// * `access` - Specifies the access type read or write for the MSR operation.
    /// * `operation` - Specifies the operation hook (mask) or unhook (unmask) to perform on the MSR.
    pub fn modify_msr_interception(&mut self, msr: u32, access: MsrAccessType, operation: MsrOperation) {
        let msr_low = msr & 0x1FFF;
        let msr_index = (msr_low >> 3) as usize;
        let msr_bit = (msr_low & 7) as u8;

        let bitmap_section = match (msr >= 0xC000_0000, access) {
            (true, MsrAccessType::Write) => &mut self.write_high_msrs,
            (true, MsrAccessType::Read) => &mut self.read_high_msrs,
            (false, MsrAccessType::Write) => &mut self.write_low_msrs,
            (false, MsrAccessType::Read) => &mut self.read_low_msrs,
        };

        match operation {
            MsrOperation::Hook => bitmap_section[msr_index].set_bit(msr_bit as usize, true),
            MsrOperation::Unhook => bitmap_section[msr_index].set_bit(msr_bit as usize, false),
        }
    }
}
