#![no_std]

/// The password used for authentication with the hypervisor.
pub const PASSWORD: u64 = 0xDEADBEEF;

/// Enumeration of possible commands that can be issued to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
#[allow(dead_code)]
pub enum Commands {
    /// Command to enable a kernel EPT hook.
    EnableKernelEptHook = 0,

    /// Command to disable a kernel EPT hook.
    DisableKernelEptHook = 1,

    /// Command to read the memory of a process.
    ReadProcessMemory = 2,

    /// Command to write the memory of a process.
    WriteProcessMemory = 3,

    /// Invalid command.
    Invalid,
}

impl Commands {
    /// Converts a `u64` value to a `Commands` enum variant.
    ///
    /// # Arguments
    ///
    /// * `value` - The `u64` value to convert.
    ///
    /// # Returns
    ///
    /// * `Commands` - The corresponding `Commands` enum variant.
    pub fn from_u64(value: u64) -> Commands {
        match value {
            0 => Commands::EnableKernelEptHook,
            1 => Commands::DisableKernelEptHook,
            2 => Commands::ReadProcessMemory,
            3 => Commands::WriteProcessMemory,
            _ => Commands::Invalid,
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
    ///
    /// # Returns
    ///
    /// * `u64` - `0x1` for success, `0x0` for failure.
    pub fn to_u64(self) -> u64 {
        match self {
            CommandStatus::Success => 0x1,
            CommandStatus::Failure => 0x0,
        }
    }
}

/// Structure representing the hook data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookData {
    pub function_hash: u32,
    pub syscall_number: u16,
}

/// Structure representing the memory data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryData {
    pub process_id: u64,
    pub address: u64,
    pub buffer: u64,
    pub size: u64,
}

/// Enum representing the data that can be sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDataPayload {
    Hook(HookData),
    Memory(MemoryData),
}

/// Structure representing the data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientData {
    pub command: Commands,
    pub payload: ClientDataPayload,
}

impl ClientData {
    /// Converts `ClientData` to a pointer.
    ///
    /// # Returns
    ///
    /// * `u64` - The pointer to the `ClientData`.
    pub fn as_ptr(&self) -> u64 {
        self as *const ClientData as u64
    }

    /// Converts a pointer to `ClientData`.
    ///
    /// # Arguments
    ///
    /// * `ptr` - The pointer to the `ClientData`.
    ///
    /// # Returns
    ///
    /// * `&'static ClientData` - The reference to the `ClientData`.
    pub fn from_ptr(ptr: u64) -> &'static ClientData {
        unsafe { &*(ptr as *const ClientData) }
    }
}

/// Generates a unique hash using the djb2 algorithm.
///
/// # Arguments
///
/// * `buffer` - The buffer to hash.
///
/// # Returns
///
/// * `u32` - The hash of the buffer.
pub fn djb2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i: usize = 0;
    let mut char: u8;

    while i < buffer.len() {
        char = buffer[i];

        if char == 0 {
            i += 1;
            continue;
        }

        if char >= ('a' as u8) {
            char -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)) + char as u32;
        i += 1;
    }

    hash
}
