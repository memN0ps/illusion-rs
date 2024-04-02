use crate::error::HypervisorError;

/// The guest agent command to initialize the guest agent.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GuestAgentCommand {
    /// Initialize the guest agent.
    Initialize = 0,
    // Add other commands as necessary
}

impl Default for GuestAgentCommand {
    /// Returns the default command number for the guest agent.
    fn default() -> Self {
        GuestAgentCommand::Initialize
    }
}

impl TryFrom<u64> for GuestAgentCommand {
    type Error = HypervisorError;

    /// Attempts to convert a u64 value to a GuestAgentCommand.
    ///
    /// # Arguments
    ///
    /// * `value`: The u64 value to convert.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Self::Error>` - The converted GuestAgentCommand or an error if the value is unknown.
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(GuestAgentCommand::Initialize),
            _ => Err(HypervisorError::UnknownGuestAgentCommand),
        }
    }
}
