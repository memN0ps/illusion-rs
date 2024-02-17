//! Handles VM exits for Intel Virtualization Technology (VT-x),
//! focusing on memory management and guest-host interactions.

use crate::intel::{invept::invept_all_contexts, vmexit::ExitType};

/// Handles the INVEPT VM exit.
///
/// Invalidates all EPT contexts and advances the VM's instruction pointer.
///
/// # Returns
/// * `ExitType::IncrementRIP` - To move past the `INVEPT` instruction in the VM.
pub fn handle_invept() -> ExitType {
    log::debug!("Handling INVEPT VM exit...");

    // Invalidate all EPT contexts to sync guest VM memory accesses with the host.
    invept_all_contexts();

    log::debug!("INVEPT VM exit handled successfully!");

    // Return instruction to increment the VM's instruction pointer.
    ExitType::IncrementRIP
}
