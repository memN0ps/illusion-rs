//! Handles specific VMX exit instructions for virtual machines.
//!
//! This crate provides functionality to handle VM exits caused by specific instructions
//! like `HLT`, facilitating appropriate responses and actions in a virtualized environment.
//! Essential for managing VM execution flow and state in response to guest actions.

use {crate::intel::vmexit::ExitType, log::trace};

/// Handles the VM exit caused by a `HLT` instruction.
///
/// Responds to a `HLT` instruction executed by the guest by incrementing the instruction
/// pointer (RIP) to continue execution after the `HLT`. This ensures the virtual machine
/// does not halt and continues processing subsequent instructions.
///
/// # Returns
///
/// Returns `ExitType::IncrementRIP` to indicate that the VM's instruction pointer should
/// be incremented to continue execution.
pub fn handle_halt() -> ExitType {
    trace!("Handling HLT VM exit...");
    ExitType::IncrementRIP
}
