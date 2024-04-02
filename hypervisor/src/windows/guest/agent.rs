use {
    crate::windows::guest::{command::GuestAgentCommand, entry::InitialGuestAgentStack},
    log::*,
};

/// The guest agent context for the host.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HostGuestAgentContext {
    /// The original RIP of the guest.
    pub original_guest_rip: u64,

    /// The original RSP of the guest.
    pub original_guest_rsp: u64,

    /// The original RAX of the guest.
    pub original_guest_rax: u64,

    /// The command number for the guest agent.
    pub command_number: GuestAgentCommand,

    /// Padding to ensure the struct has the correct alignment and size.
    pub padding: u64,
}

#[no_mangle]
pub extern "C" fn guest_agent_entry_point(stack: &mut InitialGuestAgentStack) {
    trace!("Guest agent entry point called!");

    // Set the stack frame to the original guest RSP and RIP
    stack.trap_frame.rsp = stack.guest_agent_context.original_guest_rsp;
    stack.trap_frame.rip = stack.guest_agent_context.original_guest_rip;

    // Handle the guest agent command
    match GuestAgentCommand::try_from(stack.guest_agent_context.command_number) {
        Ok(command) => match command {
            GuestAgentCommand::Initialize => handle_initialize_guest_agent(stack),
        },
        Err(e) => error!("Failed to handle guest agent command: {:?}", e),
    }
}

fn handle_initialize_guest_agent(_stack: &mut InitialGuestAgentStack) {
    // Implementation here
    trace!("Handling Initialize guest agent");
}
