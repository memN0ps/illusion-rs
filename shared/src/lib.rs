#![no_std]

/// The password used for authentication with the hypervisor.
pub const PASSWORD: u64 = 0xDEADBEEF;

/// Enumeration of possible commands that can be issued to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
#[allow(dead_code)]
pub enum Commands {
    /// Command to enable a kernel inline hook.
    EnableKernelInlineHook = 0,

    /// Command to enable a syscall inline hook.
    DisableKernelInlineHook = 1,

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
            0 => Commands::EnableKernelInlineHook,
            1 => Commands::DisableKernelInlineHook,
            _ => Commands::Invalid,
        }
    }
}

/// Structure representing the data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientData {
    pub command: Commands,
    pub function_hash: u32,
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

/// Generate a unique hash
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
    for &byte in buffer {
        let char = if byte >= b'a' { byte - 0x20 } else { byte };
        hash = (hash << 5).wrapping_add(hash).wrapping_add(char as u32);
    }
    hash
}
