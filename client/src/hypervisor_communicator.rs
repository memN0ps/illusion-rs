//! # Hypervisor Library
//!
//! This library provides a user-friendly interface for interacting with the hypervisor.
//! It allows you to open a process by name and perform memory read/write operations.

#![allow(dead_code)]

use {
    shared::{ClientCommand, ClientDataPayload, Command, ProcessMemoryOperation, PASSWORD},
    std::arch::asm,
};

/// Struct to encapsulate the result of a CPUID instruction.
#[derive(Debug)]
pub struct CpuidResult {
    pub eax: u64,
    pub ebx: u64,
    pub ecx: u64,
    pub edx: u64,
}

/// Struct representing the hypervisor communicator.
pub struct HypervisorCommunicator {
    process_cr3: Option<u64>,
}

impl HypervisorCommunicator {
    /// Creates a new instance of `HypervisorCommunicator`, retrieves the process CR3, and stores it.
    pub fn open_process(process_id: u64) -> Option<Self> {
        let mut communicator = Self { process_cr3: None };

        let command_payload = ClientDataPayload::Memory(ProcessMemoryOperation {
            process_id: Some(process_id),
            guest_cr3: None,
            address: None,
            buffer: &mut communicator.process_cr3 as *mut _ as u64,
        });

        let client_command = ClientCommand {
            command: Command::OpenProcess,
            payload: command_payload,
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            Some(communicator)
        } else {
            None
        }
    }

    /// Sends a command to the hypervisor using CPUID.
    fn call_hypervisor(command_rcx: u64) -> CpuidResult {
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

    /// Reads memory from the opened process using the stored CR3.
    pub fn read_process_memory(&self, address: u64, buffer: &mut [u8]) -> Option<()> {
        let memory_operation = ProcessMemoryOperation {
            process_id: None,
            guest_cr3: self.process_cr3,
            address: Some(address),
            buffer: buffer.as_ptr() as u64,
        };

        let client_command = ClientCommand {
            command: Command::ReadProcessMemory,
            payload: ClientDataPayload::Memory(memory_operation),
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            Some(())
        } else {
            None
        }
    }

    /// Writes memory to the opened process using the stored CR3.
    pub fn write_process_memory(&self, address: u64, buffer: &[u8]) -> Option<()> {
        let memory_operation = ProcessMemoryOperation {
            process_id: None,
            guest_cr3: self.process_cr3,
            address: Some(address),
            buffer: buffer.as_ptr() as u64,
        };

        let client_command = ClientCommand {
            command: Command::WriteProcessMemory,
            payload: ClientDataPayload::Memory(memory_operation),
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            Some(())
        } else {
            None
        }
    }
}
