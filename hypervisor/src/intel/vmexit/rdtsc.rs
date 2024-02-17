//! Handles RDTSC virtualization tasks, specifically intercepting and managing
//! the `RDTSC` (Read Time-Stamp Counter) instruction in a VM to ensure appropriate time
//! information is provided to the guest while maintaining the integrity of the hypervisor.

use {
    crate::intel::{capture::GuestRegisters, vmexit::ExitType},
    x86::time::rdtsc,
};

/*
User can add the following later:
- https://secret.club/2020/01/12/battleye-hypervisor-detection.html
- https://github.com/not-matthias/rdtsc_bench/blob/main/src/main.rs
*/

/// Handles the `RDTSC` VM-exit.
///
/// This function is invoked when the guest executes the `RDTSC` instruction.
/// It reads the current value of the host's time-stamp counter and updates the guest's
/// RAX and RDX registers with the low and high 32-bits of the counter, respectively.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's current register state.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `RDTSC` instruction in the VM.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual, Table C-1. Basic Exit Reasons 10.
pub fn handle_rdtsc(guest_registers: &mut GuestRegisters) -> ExitType {
    log::debug!("Handling RDTSC VM exit...");

    // Read the time stamp counter.
    let rdtsc_value: u64 = unsafe { rdtsc() };

    // Update the guest's RAX and RDX registers.
    guest_registers.rax = rdtsc_value & 0xFFFFFFFF; // Low 32 bits
    guest_registers.rdx = rdtsc_value >> 32; // High 32 bits

    log::debug!("RDTSC VMEXIT handled successfully!");

    ExitType::IncrementRIP
}
