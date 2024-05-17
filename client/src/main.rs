//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

use hypervisor_communicator::HypervisorCommunicator;

mod hypervisor_communicator;

/// The main function demonstrating the usage of `HypervisorCommunicator`.
fn main() {
    let communicator = HypervisorCommunicator::new();

    // Example CPUID call
    let command = 0x36; // Example leaf value, specific to the hypervisor

    communicator.send_protected_cpuid_command(command);
}
