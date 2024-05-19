//! # Hypervisor Communicator
//!
//! This library provides functionality to communicate with a UEFI hypervisor
//! using the CPUID instruction. The communication is password protected to ensure
//! that only authorized requests are processed by the hypervisor.

use {shared::PASSWORD, std::arch::asm};

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
    ///
    /// # Returns
    ///
    /// * `CpuidResult` - The result of the CPUID instruction.
    pub fn call_hypervisor(&self, command_rcx: u64) -> CpuidResult {
        let mut rax = PASSWORD;
        let mut rbx;
        let mut rcx = command_rcx;
        let mut rdx;

        unsafe {
            asm!(
            "mov {0:r}, rbx",
            "cpuid",
            "xchg {0:r}, rbx",
            out(reg) rbx,
            inout("rax") rax,
            inout("rcx") rcx,
            lateout("rdx") rdx,
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
