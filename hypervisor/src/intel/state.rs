/// Represents the activity state of a logical processor in VMX operation.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GuestActivityState {
    /// The logical processor is executing instructions normally.
    Active = 0x00000000,

    /// The logical processor is inactive because it executed the HLT instruction.
    Hlt = 0x00000001,

    /// The logical processor is inactive because it incurred a triple fault
    /// or some other serious error.
    Shutdown = 0x00000002,

    /// The logical processor is inactive because it is waiting for a startup-IPI (SIPI).
    WaitForSipi = 0x00000003,
}
