//! # Hypervisor Communicator
//!
//! This library provides functionality to communicate with a UEFI hypervisor
//! using the CPUID instruction. The communication is password protected to ensure
//! that only authorized requests are processed by the hypervisor.

use std::arch::asm;

/// The password used for authentication with the hypervisor.
pub const PASSWORD: u64 = 0xDEADBEEF;

/// Enumeration of possible commands that can be issued to the hypervisor.
///
/// This enum represents different commands that can be sent to the hypervisor for
/// various operations such as enabling hooks or disabling page hooks.
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

/// Struct to encapsulate the result of a CPUID instruction.
#[derive(Debug)]
pub struct CpuidResult {
    pub eax: u64,
    pub ebx: u64,
    pub ecx: u64,
    pub edx: u64,
}

/// Struct to encapsulate the functionality for communicating with the hypervisor.
pub struct HypervisorCommunicator;

impl HypervisorCommunicator {
    /// Creates a new instance of `HypervisorCommunicator`.
    pub fn new() -> Self {
        Self
    }

    /// Sends a CPUID command with the password directly using inline assembly.
    ///
    /// This function includes the password in the `rax` register and executes the CPUID instruction.
    ///
    /// # Arguments
    ///
    /// * `command_rcx` - The value to be placed in the `rcx` register.
    /// * `command_rdx` - The value to be placed in the `rdx` register.
    /// * `command_r8` - The value to be placed in the `r8` register.
    /// * `command_r9` - The value to be placed in the `r9` register.
    ///
    /// # Returns
    ///
    /// * `CpuidResult` - The result of the CPUID instruction.
    pub fn call_hypervisor(&self, command_rcx: u64, command_rdx: u64, command_r8: u64, command_r9: u64) -> CpuidResult {
        let mut rax = PASSWORD;
        let mut rbx;
        let mut rcx = command_rcx;
        let mut rdx = command_rdx;

        unsafe {
            asm!(
            "mov {0:r}, rbx",
            "cpuid",
            "xchg {0:r}, rbx",
            out(reg) rbx,
            inout("rax") rax,
            inout("rcx") rcx,
            inout("rdx") rdx,
            in("r8") command_r8,
            in("r9") command_r9,
            options(nostack, preserves_flags),
            );
        }

        CpuidResult {
            eax: rax,
            ebx: rbx,
            ecx: rcx,
            edx: rdx,
        }
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
///
/// # Example
///
/// ```
/// let hash = djb2_hash(b"MmIsAddressValid");
/// println!("Hash: {}", hash);
/// ```
#[allow(dead_code)]
pub fn djb2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in buffer {
        let char = if byte >= b'a' { byte - 0x20 } else { byte };
        hash = (hash << 5).wrapping_add(hash).wrapping_add(char as u32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the `call_hypervisor` function for syscall hook.
    ///
    /// This test creates a new `HypervisorCommunicator` instance and sends a CPUID command
    /// to set up a syscall hook with `NtQuerySystemInformation` (syscall number 0x36).
    #[test]
    fn test_call_hypervisor_syscall_hook() {
        let communicator = HypervisorCommunicator::new();
        let syscall_number = 0x36;
        let result = communicator.call_hypervisor(Commands::EnableSyscallInlineHook as u64, syscall_number as u64, 1, 0);
        assert_eq!(result.eax, 1);
    }

    /// Tests the `call_hypervisor` function for kernel hook.
    ///
    /// This test creates a new `HypervisorCommunicator` instance and sends a CPUID command
    /// to set up a kernel inline hook with `MmIsAddressValid`.
    #[test]
    fn test_call_hypervisor_kernel_hook() {
        let communicator = HypervisorCommunicator::new();
        let function_name = b"MmIsAddressValid";
        let function_hash = djb2_hash(function_name);
        let result = communicator.call_hypervisor(Commands::EnableKernelInlineHook as u64, function_hash as u64, 0, 0);
        assert_eq!(result.eax, 1);
    }
}
