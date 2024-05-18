//! # Hypervisor Communicator
//!
//! This library provides functionality to communicate with a UEFI hypervisor
//! using the CPUID instruction. The communication is password protected to ensure
//! that only authorized requests are processed by the hypervisor.

use std::arch::asm;

/// The password used for authentication with the hypervisor.
pub const PASSWORD: u64 = 0xDEADBEEF;

/// The special CPUID leaf value for command execution.
pub const COMMAND_LEAF: u64 = 0xDEADC0DE;

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
    /// This function includes the password in the `rdx` register and executes the CPUID instruction.
    ///
    /// # Arguments
    ///
    /// * `leaf` - The value to be placed in the `rax` register.
    /// * `sub_leaf` - The value to be placed in the `rcx` register.
    /// * `r8` - The value to be placed in the `r8` register.
    /// * `r9` - The value to be placed in the `r9` register.
    ///
    /// # Returns
    ///
    /// * `CpuidResult` - The result of the CPUID instruction.
    ///
    /// # Example
    ///
    /// ```
    /// let communicator = HypervisorCommunicator::new();
    /// let result = communicator.call_hypervisor(COMMAND_LEAF, 0x2, 0x3, 0x4);
    /// assert_eq!(result.eax, 1);
    /// ```
    pub fn call_hypervisor(&self, leaf: u64, sub_leaf: u64, r8: u64, r9: u64) -> CpuidResult {
        let mut eax = leaf;
        let mut ebx;
        let mut ecx = sub_leaf;
        let mut edx;

        unsafe {
            asm!(
            "mov {0:r}, rbx",
            "cpuid",
            "xchg {0:r}, rbx",
            out(reg) ebx,
            inout("rax") eax,
            inout("rcx") ecx,
            lateout("rdx") edx,
            in("rdx") PASSWORD,
            in("r8") r8,
            in("r9") r9,
            options(nostack, preserves_flags),
            );
        }

        CpuidResult { eax, ebx, ecx, edx }
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
        let result = communicator.call_hypervisor(COMMAND_LEAF, 1, syscall_number as u64, 1);
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
        let result = communicator.call_hypervisor(COMMAND_LEAF, 0, function_hash as u64, 0);
        assert_eq!(result.eax, 1);
    }
}
