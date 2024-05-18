//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

#![feature(asm_const)]

use hypervisor_communicator::HypervisorCommunicator;

mod hypervisor_communicator;

/// The main function demonstrating the usage of `HypervisorCommunicator`.
fn main() {
    let communicator = HypervisorCommunicator::new();
    communicator.call_hypervisor(0x2, 0x3, 0x4, 0x5);
}
