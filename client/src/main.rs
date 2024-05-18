//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

#![feature(asm_const)]

use {
    crate::hypervisor_communicator::{djb2_hash, COMMAND_LEAF},
    hypervisor_communicator::HypervisorCommunicator,
};

mod hypervisor_communicator;

/// The main function demonstrating the usage of `HypervisorCommunicator`.
fn main() {
    let communicator = HypervisorCommunicator::new();
    let syscall_number = 0x36;
    let result = communicator.call_hypervisor(COMMAND_LEAF, 1, syscall_number as u64, 1);
    println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);

    let communicator = HypervisorCommunicator::new();
    let function_name = b"MmIsAddressValid";
    let function_hash = djb2_hash(function_name);
    let result = communicator.call_hypervisor(COMMAND_LEAF, 0, function_hash as u64, 0);
    println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);
}
