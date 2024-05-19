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
    EnableSyscallInlineHook = 1,
    /// Command to disable a page hook.
    DisablePageHook = 2,
    /// Invalid command.
    Invalid,
}

/// Structure representing the data sent by the client to the hypervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientData {
    pub command: Commands,
    pub syscall_number: i32,
    pub get_from_win32k: bool,
    pub function_hash: u32,
}
