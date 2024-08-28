//! # Hypervisor Library
//!
//! This library provides a user-friendly interface for interacting with the hypervisor.
//! It allows you to open a process by name and perform memory read/write operations.

#![allow(dead_code)]

use {
    crate::{pemem::djb2_hash, ssn::Syscall},
    shared::{ClientCommand, ClientDataPayload, Command, HookData, ProcessMemoryOperation, PASSWORD},
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
    process_cr3: u64,
}

impl HypervisorCommunicator {
    /// Enables a kernel EPT hook by specifying the function name.
    pub fn enable_ept_kernel_hook(&self, function_name: &str) -> Option<()> {
        self.manage_ept_kernel_hook(function_name, Command::EnableKernelEptHook)
    }

    /// Disables a kernel EPT hook by specifying the function name.
    pub fn disable_ept_kernel_hook(&self, function_name: &str) -> Option<()> {
        self.manage_ept_kernel_hook(function_name, Command::DisableKernelEptHook)
    }

    /// Internal function to manage (enable/disable) kernel EPT hooks.
    fn manage_ept_kernel_hook(&self, function_name: &str, command: Command) -> Option<()> {
        // Lookup the syscall number using the function hash
        let mut syscall = Syscall::new();
        let function_hash = djb2_hash(function_name.as_bytes());
        let syscall_number = syscall.get_ssn_by_hash(function_hash)?;

        log::debug!("Function: {} Syscall number: {}", function_name, syscall_number);

        let hook_data = HookData {
            function_hash,
            syscall_number,
        };

        let client_command = ClientCommand {
            command,
            payload: ClientDataPayload::Hook(hook_data),
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            log::debug!("Successfully managed EPT hook for function: {}", function_name);
            Some(())
        } else {
            log::error!("Failed to manage EPT hook for function: {}", function_name);
            None
        }
    }

    /// Creates a new instance of `HypervisorCommunicator`, retrieves the process CR3, and stores it.
    pub fn open_process(process_id: u64) -> Option<Self> {
        log::debug!("Opening process with ID: {}", process_id);

        let mut communicator = Self { process_cr3: 0 };

        let command_payload = ClientDataPayload::Memory(ProcessMemoryOperation {
            process_id: Some(process_id),
            guest_cr3: None,
            address: None,
            buffer: &mut communicator.process_cr3 as *mut u64 as u64,
            buffer_size: size_of::<u64>() as u64,
        });

        let client_command = ClientCommand {
            command: Command::OpenProcess,
            payload: command_payload,
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            log::debug!("Opened process with CR3: {:#x}", communicator.process_cr3);
            Some(communicator)
        } else {
            log::error!("Failed to open process");
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
        log::debug!("Reading memory from address: {:#x}", address);

        let memory_operation = ProcessMemoryOperation {
            process_id: None,
            guest_cr3: Some(self.process_cr3),
            address: Some(address),
            buffer: buffer.as_ptr() as u64,
            buffer_size: buffer.len() as u64,
        };

        let client_command = ClientCommand {
            command: Command::ReadProcessMemory,
            payload: ClientDataPayload::Memory(memory_operation),
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            log::debug!("Memory read successfully");
            Some(())
        } else {
            log::error!("Failed to read memory");
            None
        }
    }

    /// Writes memory to the opened process using the stored CR3.
    pub fn write_process_memory(&self, address: u64, buffer: &[u8]) -> Option<()> {
        log::debug!("Writing memory to address: {:#x}", address);

        let memory_operation = ProcessMemoryOperation {
            process_id: None,
            guest_cr3: Some(self.process_cr3),
            address: Some(address),
            buffer: buffer.as_ptr() as u64,
            buffer_size: buffer.len() as u64,
        };

        let client_command = ClientCommand {
            command: Command::WriteProcessMemory,
            payload: ClientDataPayload::Memory(memory_operation),
        };

        let result = Self::call_hypervisor(client_command.as_ptr());

        if result.eax == 1 {
            log::debug!("Memory written successfully");
            Some(())
        } else {
            log::error!("Failed to write memory");
            None
        }
    }
}
