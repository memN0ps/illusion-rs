//! # Hypervisor Communicator
//!
//! This library provides functionality to communicate with a UEFI hypervisor
//! using the CPUID instruction. The communication is password protected to ensure
//! that only authorized requests are processed by the hypervisor.

use x86::cpuid::cpuid;

/// The password used for authentication with the hypervisor.
const PASSWORD: u32 = 0xDEADBEEF;

/// Struct to encapsulate the functionality for communicating with the hypervisor.
pub struct HypervisorCommunicator;

impl HypervisorCommunicator {
    /// Creates a new instance of `HypervisorCommunicator`.
    pub fn new() -> Self {
        Self
    }

    /// Sends a CPUID command with the specified `eax` and `ecx` values.
    ///
    /// # Arguments
    ///
    /// * `eax` - The value to be placed in the `eax` register.
    /// * `ecx` - The value to be placed in the `ecx` register.
    ///
    /// # Example
    ///
    /// ```
    /// let communicator = HypervisorCommunicator::new();
    /// communicator.send_cpuid_command(0x4000_0001, 0x0);
    /// ```
    pub fn send_cpuid_command(&self, eax: u32, ecx: u32) {
        let result = cpuid!(eax, ecx);

        println!(
            "CPUID with EAX={:#010x}, ECX={:#010x} returned: EAX={:#010x}, EBX={:#010x}, ECX={:#010x}, EDX={:#010x}",
            eax, ecx, result.eax, result.ebx, result.ecx, result.edx
        );
    }

    /// Sends a password-protected CPUID command.
    ///
    /// This function includes the password in the CPUID command by setting the `ecx` register to the password value.
    ///
    /// # Arguments
    ///
    /// * `command` - The value to be placed in the `eax` register.
    ///
    /// # Example
    ///
    /// ```
    /// let communicator = HypervisorCommunicator::new();
    /// communicator.send_protected_cpuid_command(0x4000_0001);
    /// ```
    pub fn send_protected_cpuid_command(&self, command: u32) {
        self.send_cpuid_command(command, PASSWORD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the `send_cpuid_command` function.
    ///
    /// This test creates a new `HypervisorCommunicator` instance and sends a CPUID command
    /// with `eax` set to 0x0 and `ecx` set to 0x0. The function is expected to print the CPUID result.
    #[test]
    fn test_send_cpuid_command() {
        let communicator = HypervisorCommunicator::new();
        communicator.send_cpuid_command(0x0, 0x0);
    }

    /// Tests the `send_protected_cpuid_command` function.
    ///
    /// This test creates a new `HypervisorCommunicator` instance and sends a password-protected CPUID command
    /// with `eax` set to 0x4000_0001 and `ecx` set to the password value. The function is expected to print the CPUID result.
    #[test]
    fn test_send_protected_cpuid_command() {
        let communicator = HypervisorCommunicator::new();
        communicator.send_protected_cpuid_command(0x4000_0001);
    }
}
