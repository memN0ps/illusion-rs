use crate::intel::vmexit::ExitType;

/// Handles the `HLT` instruction.
pub fn handle_halt() -> ExitType {
    ExitType::IncrementRIP
}
