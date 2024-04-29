//! Module handling VM exits due to exceptions or non-maskable interrupts (NMIs).
//! It includes handling for various types of exceptions such as page faults,
//! general protection faults, breakpoints, and invalid opcodes.

use {
    crate::intel::{
        events::EventInjection,
        support::vmread,
        vm::Vm,
        vmerror::{EptViolationExitQualification, ExceptionInterrupt, VmExitInterruptionInformation},
        vmexit::ExitType,
    },
    x86::vmx::vmcs,
};

/// Handles exceptions and NMIs that occur during VM execution.
///
/// This function is called when the VM exits due to an exception or NMI.
/// It determines the type of exception, handles it accordingly, and prepares
/// the VM for resumption.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's register state.
/// * `vmx` - A mutable reference to the Vmx structure representing the current VM.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue after handling the exception
pub fn handle_exception(_vm: &mut Vm) -> ExitType {
    log::debug!("Handling ExceptionOrNmi VM exit...");

    let interruption_info_value = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
    let interruption_error_code_value = vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);

    if let Some(interruption_info) = VmExitInterruptionInformation::from_u32(interruption_info_value as u32) {
        if let Some(exception_interrupt) = ExceptionInterrupt::from_u32(interruption_info.vector.into()) {
            match exception_interrupt {
                ExceptionInterrupt::PageFault => {
                    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);
                    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);
                    log::trace!("Exit Qualification for EPT Violations: {:#?}", ept_violation_qualification);
                    EventInjection::vmentry_inject_pf(interruption_error_code_value as u32);
                }
                ExceptionInterrupt::GeneralProtectionFault => {
                    EventInjection::vmentry_inject_gp(interruption_error_code_value as u32);
                }
                ExceptionInterrupt::Breakpoint => {
                    //handle_breakpoint_exception(guest_registers, vm);
                    EventInjection::vmentry_inject_bp();
                }
                ExceptionInterrupt::InvalidOpcode => {
                    EventInjection::vmentry_inject_ud();
                }
                _ => {
                    panic!("Unhandled exception: {:?}", exception_interrupt);
                }
            }
        } else {
            panic!("Invalid Exception Interrupt Vector: {}", interruption_info.vector);
        }
    } else {
        panic!("Invalid VM Exit Interruption Information");
    }

    log::debug!("Exception Handled successfully!");

    ExitType::Continue
}

/*
/// Handles breakpoint (`#BP`) exceptions specifically.
///
/// When a breakpoint exception occurs, this function checks for a registered hook
/// at the current instruction pointer (RIP). If a hook is found, it transfers control
/// to the hook's handler. Otherwise, it injects a breakpoint exception into the VM.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's current register state.
/// * `vmx` - A mutable reference to the Vmx structure.
fn handle_breakpoint_exception(guest_registers: &mut GuestRegisters, vm: &mut Vm) {
    log::debug!("Breakpoint Exception");

    let hook_manager = vm.hook_manager.as_mut();

    log::trace!("Finding hook for RIP: {:#x}", guest_registers.rip);

    // Find the handler address for the current instruction pointer (RIP) and
    // transfer the execution to it. If we couldn't find a hook, we inject the
    // #BP exception.
    //
    if let Some(Some(handler)) =
        hook_manager
            .find_hook_by_address(guest_registers.rip)
            .map(|hook| {
                log::trace!("Found hook for RIP: {:#x}", guest_registers.rip);
                if let HookType::Function { inline_hook } = &hook.hook_type {
                    log::trace!("Getting handler address");
                    Some(inline_hook.handler_address())
                } else {
                    None
                }
            })
    {
        // Call our hook handle function (it will automatically call trampoline).
        log::trace!("Transferring execution to handler: {:#x}", handler);
        guest_registers.rip = handler;
        vmwrite(vmcs::guest::RIP, guest_registers.rip);

        log::debug!("Breakpoint (int3) hook handled successfully!");
    } else {
        EventInjection::vmentry_inject_bp();
        log::debug!("Breakpoint exception handled successfully!");
    };
}
*/

/// Handles undefined opcode (`#UD`) exceptions.
///
/// This function is invoked when the VM attempts to execute an invalid or undefined
/// opcode. It injects an undefined opcode exception into the VM.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue.
pub fn handle_undefined_opcode_exception() -> ExitType {
    log::debug!("Undefined Opcode Exception");

    EventInjection::vmentry_inject_ud();

    log::debug!("Undefined Opcode Exception handled successfully!");

    ExitType::Continue
}
