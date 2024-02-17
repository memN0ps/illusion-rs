//! Manages INVD VM exits to handle guest VM cache invalidation requests securely.

use crate::{intel::{vmexit::ExitType, capture::GuestRegisters, support::wbinvd}};

/// Manages the INVD instruction VM exit by logging the event, performing a controlled
/// cache invalidation, and advancing the guest's instruction pointer.
///
/// # Arguments
///
/// * `registers` - General-purpose registers of the guest VM at the VM exit.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `INVD` instruction in the VM.
pub fn handle_invd(_guest_registers: &mut GuestRegisters) -> ExitType {
    log::debug!("Handling INVD VM exit...");

    // Perform WBINVD to write back and invalidate the hypervisor's caches.
    // This ensures that any modified data is written to memory before cache lines are invalidated.
    wbinvd();
    // Advances the guest's instruction pointer to the next instruction to be executed.

    log::debug!("INVD VMEXIT handled successfully!");

    ExitType::IncrementRIP
}