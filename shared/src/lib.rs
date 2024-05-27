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

    /// Command to enable a syscall EPT hook.
    EnableSyscallEptHook = 2,

    /// Command to disable a syscall EPT hook.
    DisableSyscallEptHook = 3,

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
            2 => Commands::EnableSyscallEptHook,
            3 => Commands::DisableSyscallEptHook,
            _ => Commands::Invalid,
        }
    }
}

/// Structure representing the data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientData {
    pub command: Commands,
    pub function_hash: Option<u32>,
    pub syscall_number: Option<u16>,
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

    return hash;
}
