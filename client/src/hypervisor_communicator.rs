//! # Hypervisor Communicator
//!
//! This library provides functionality to communicate with a UEFI hypervisor
//! using the CPUID instruction. The communication is password protected to ensure
//! that only authorized requests are processed by the hypervisor.

use std::arch::asm;

/// The password used for authentication with the hypervisor.
const PASSWORD: u32 = 0xDEADBEEF;

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
    /// * `rcx` - The value to be placed in the `rcx` register.
    /// * `rdx` - The value to be placed in the `rdx` register.
    /// * `r8` - The value to be placed in the `r8` register.
    /// * `r9` - The value to be placed in the `r9` register.
    ///
    /// # Example
    ///
    /// ```
    /// let communicator = HypervisorCommunicator::new();
    /// communicator.call_hypervisor(0x2, 0x3, 0x4, 0x5);
    /// ```
    pub fn call_hypervisor(&self, rcx: u64, rdx: u64, r8: u64, r9: u64) {
        unsafe {
            asm!(
            "mov rax, {password}",
            "cpuid",
            password = const PASSWORD,
            in("rcx") rcx,
            in("rdx") rdx,
            in("r8") r8,
            in("r9") r9,
            options(noreturn)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the `call_hypervisor` function.
    ///
    /// This test creates a new `HypervisorCommunicator` instance and sends a CPUID command
    /// with `rax` set to the password value and other registers set to provided values.
    /// The function is expected to execute the CPUID instruction with the given values.
    #[test]
    fn test_call_hypervisor() {
        let communicator = HypervisorCommunicator::new();
        communicator.call_hypervisor(0x2, 0x3, 0x4, 0x5);
    }
}
