//! This module provides utilities and structures to manage event injection in VMX.
//! It handles the representation, manipulation, and injection of various types of events.

#![allow(dead_code)]

use {crate::intel::support::vmwrite, bitfield::bitfield, x86::vmx::vmcs};

bitfield! {
    /// Represents the VM-Entry Interruption-Information Field.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 25-17. Format of the VM-Entry Interruption-Information Field
    pub struct EventInjection(u32);

    impl Debug;

    /// Vector of interrupt or exception
    pub get_vector, set_vector: 7, 0;

    /// Interruption type:
    /// 0: External interrupt
    /// 1: Reserved
    /// 2: Non-maskable interrupt (NMI)
    /// 3: Hardware exception (e.g,. #PF)
    /// 4: Software interrupt (INT n)
    /// 5: Privileged software exception (INT1)
    /// 6: Software exception (INT3 or INTO)
    /// 7: Other event
    pub get_type, set_type: 10, 8;

    /// Deliver error code (0 = do not deliver; 1 = deliver)
    pub get_deliver_error_code, set_deliver_error_code: 11, 11;

    // Reserved: 30:12

    /// Valid
    pub get_valid, set_valid: 31, 31;
}

/// Represents the various types of exceptions and interrupts.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 6-1. Exceptions and Interrupts
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExceptionInterrupt {
    /// Divide Error
    DE = 0,
    /// Debug
    DB = 1,
    /// Non-maskable external interrupt
    NMI = 2,
    /// Breakpoint
    BP = 3,
    /// Overflow
    OF = 4,
    /// BOUND Range Exceeded
    BR = 5,
    /// Invalid Opcode (Undefined Opcode)
    UD = 6,
    /// Device Not Available (No Math Coprocessor)
    NM = 7,
    /// Double Fault
    DF = 8,
    /// CoProcessor Segment Overrun (reserved)
    MF = 9,
    /// Invalid TSS
    TS = 10,
    /// Segment Not Present
    NP = 11,
    /// Stack Segment Fault
    SS = 12,
    /// General Protection
    GP = 13,
    /// Page Fault
    PF = 14,
    // 15 is Reserved
    /// Floating-Point Error (Math Fault)
    MFMath = 16,
    /// Alignment Check
    AC = 17,
    /// Machine Check
    MC = 18,
    /// SIMD Floating-Point Exception
    XM = 19,
    /// Virtualization Exception
    VE = 20,
    /// Control Protection Exception
    CP = 21,
    // 22-31 are Reserved
    // 32-255 are Maskable Interrupts, which can be represented differently if needed
}

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 6-1. Exceptions and Interrupts
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum InterruptionType {
    /// External interrupt.
    ExternalInterrupt = 0,
    /// Reserved value.
    Reserved = 1,
    /// Non-maskable interrupt (NMI).
    NonMaskableInterrupt = 2,
    /// Hardware exception, such as #PF.
    HardwareException = 3,
    /// Software interrupt using the INT n instruction.
    SoftwareInterrupt = 4,
    /// Privileged software exception using the INT1 instruction.
    PrivilegedSoftwareException = 5,
    /// Software exception using the INT3 or INTO instructions.
    SoftwareException = 6,
    /// Represents other types of events not covered by the above categories.
    OtherEvent = 7,
}

const VALID: u32 = 1;
const INVALID: u32 = 0;

/// Provides methods for event injection in VMX.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 27.6 EVENT INJECTION
impl EventInjection {
    /// Inject General Protection (#GP) to the guest (Event Injection).
    pub fn general_protection() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::GP as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_deliver_error_code(1);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Breakpoint (#BP) to the guest (Event Injection).
    pub fn breakpoint() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::BP as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Page Fault (#PF) to the guest (Event Injection).
    pub fn page_fault() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::PF as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        event.0
    }

    /// Injects a general protection fault into the guest.
    ///
    /// This function is used to signal to the guest that a protection violation
    /// has occurred, typically due to accessing a reserved MSR.
    ///
    /// # Arguments
    ///
    /// * `error_code` - The error code to be associated with the fault.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    #[rustfmt::skip]
    pub fn vmentry_inject_gp(error_code: u32) {
        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, error_code);
        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, EventInjection::general_protection());
    }
}
