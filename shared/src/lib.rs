#![no_std]

/// The password used for authentication with the hypervisor.
pub const PASSWORD: u64 = 0xDEADBEEF;

/// Enumeration of possible commands that can be issued to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
#[allow(dead_code)]
pub enum Command {
    /// Command to enable a kernel EPT hook.
    EnableKernelEptHook = 0,

    /// Command to disable a kernel EPT hook.
    DisableKernelEptHook = 1,

    /// Command to open a process and retrieve its CR3 / directory table base.
    OpenProcess = 2,

    /// Command to read the memory of a process.
    ReadProcessMemory = 3,

    /// Command to write the memory of a process.
    WriteProcessMemory = 4,

    /// Invalid command.
    Invalid,
}

impl Command {
    /// Converts a `u64` value to a `Command` enum variant.
    pub fn from_u64(value: u64) -> Command {
        match value {
            0 => Command::EnableKernelEptHook,
            1 => Command::DisableKernelEptHook,
            2 => Command::OpenProcess,
            3 => Command::ReadProcessMemory,
            4 => Command::WriteProcessMemory,
            _ => Command::Invalid,
        }
    }
}

/// Represents the outcome of a command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    Success,
    Failure,
}

impl CommandStatus {
    /// Converts `CommandStatus` to a u64 for returning in registers.
    pub fn to_u64(self) -> u64 {
        match self {
            CommandStatus::Success => 0x1,
            CommandStatus::Failure => 0x0,
        }
    }

    /// Converts a `u64` value to a `CommandStatus` enum variant.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0x1 => Some(CommandStatus::Success),
            0x0 => Some(CommandStatus::Failure),
            _ => None,
        }
    }
}

/// Structure representing the hook data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookData {
    pub function_hash: u32,
    pub syscall_number: u16,
}

/// Structure representing the memory operation data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessMemoryOperation {
    pub process_id: Option<u64>,
    pub guest_cr3: Option<u64>,
    pub address: Option<u64>,
    pub buffer: u64,
}

/// Enum representing the data that can be sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDataPayload {
    Hook(HookData),
    Memory(ProcessMemoryOperation),
}

/// Structure representing the data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCommand {
    pub command: Command,
    pub payload: ClientDataPayload,
}

impl ClientCommand {
    /// Converts `ClientCommand` to a pointer.
    pub fn as_ptr(&self) -> u64 {
        self as *const ClientCommand as u64
    }

    /// Converts a pointer to `ClientCommand`.
    pub fn from_ptr(ptr: u64) -> &'static ClientCommand {
        unsafe { &*(ptr as *const ClientCommand) }
    }
}
