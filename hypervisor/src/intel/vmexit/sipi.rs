//! Handles VMX operations related to inter-processor communication.
//!
//! This module specifically deals with the emulation of SIPI signals, facilitating the initialization
//! and startup of Application Processors (APs) in a virtualized environment. Essential for simulating
//! multi-processor startup sequences within a VM, aligning with the MP initialization protocol.
//! Credits to Satoshi Tanada: https://github.com/tandasat/MiniVisorPkg/blob/master/Sources/HostMain.c

use {
    crate::intel::{
        capture::GuestRegisters,
        support::{vmread, vmwrite},
        vmexit::ExitType,
    },
    x86::vmx::vmcs,
};

/// Emulates the effect of a Startup IPI (SIPI) signal within the VM.
///
/// Upon receiving a SIPI, this function adjusts the guest's code segment selector,
/// base, and instruction pointer to reflect the startup vector indicated by the SIPI.
/// It ensures that subsequent SIPI signals, if any, are ignored once the AP is out of
/// the wait-for-SIPI state, following VMX and MP initialization protocols.
///
/// # Arguments
///
/// - `guest_registers`: A mutable reference to the guest's general-purpose registers. Currently unused.
///
/// # Returns
///
/// Returns `ExitType::Continue` to indicate the VM should continue execution.
pub fn handle_sipi_signal(guest_registers: &mut GuestRegisters) -> ExitType {
    let vector = vmread(vmcs::ro::EXIT_QUALIFICATION);

    vmwrite(vmcs::guest::CS_SELECTOR, vector << 8);
    vmwrite(vmcs::guest::CS_BASE, vector << 12);
    guest_registers.rip = 0x0u64;
    vmwrite(vmcs::guest::RIP, guest_registers.rip);

    let vmx_active = 0x0u64;
    vmwrite(vmcs::guest::ACTIVITY_STATE, vmx_active);

    ExitType::Continue
}
