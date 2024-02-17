//! This module provides utilities and structures to manage event injection in VMX.
//! It handles the representation, manipulation, and injection of various types of events.

#![allow(dead_code)]

use {
    crate::intel::{
        support::vmwrite,
        vmerror::{ExceptionInterrupt, InterruptionType},
    },
    bitfield::bitfield,
    x86::vmx::vmcs,
};

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

const VALID: u32 = 1;
const INVALID: u32 = 0;

/// Provides methods for event injection in VMX.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 27.6 EVENT INJECTION
impl EventInjection {
    /// Inject General Protection (#GP) to the guest (Event Injection).
    fn general_protection() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::GeneralProtectionFault as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_deliver_error_code(1);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Breakpoint (#BP) to the guest (Event Injection).
    fn breakpoint() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::Breakpoint as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Page Fault (#PF) to the guest (Event Injection).
    fn page_fault() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::PageFault as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Undefined Opcode (#UD) to the guest (Event Injection).
    fn undefined_opcode() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::InvalidOpcode as u32);
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
    pub fn vmentry_inject_gp(error_code: u32) {
        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, error_code);
        vmwrite(
            vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            EventInjection::general_protection(),
        );
    }

    /// Injects a page fault into the guest.
    ///
    /// This function is used to signal to the guest that a page fault has occurred.
    /// It's typically used in response to a memory access violation.
    ///
    /// # Arguments
    ///
    /// * `error_code` - The error code to be associated with the page fault.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_pf(error_code: u32) {
        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, error_code);
        vmwrite(
            vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            EventInjection::page_fault(),
        );
    }

    /// Injects a breakpoint exception into the guest.
    ///
    /// This function is used to signal to the guest that a breakpoint exception
    /// has occurred, typically used for debugging purposes.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_bp() {
        vmwrite(
            vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            EventInjection::breakpoint(),
        );
    }

    /// Injects an undefined opcode exception into the guest.
    ///
    /// This function is used to signal to the guest that an invalid or undefined opcode
    /// has been encountered, typically indicating an error in the guest's execution.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_ud() {
        vmwrite(
            vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            EventInjection::undefined_opcode(),
        );
    }
}
