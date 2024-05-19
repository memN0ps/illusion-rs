//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

#![feature(asm_const)]

use {
    crate::{
        hypervisor_communicator::HypervisorCommunicator,
        ssn::{pe::djb2_hash, syscall::Syscall},
    },
    clap::{Parser, Subcommand},
    shared::{ClientData, Commands},
};

mod hypervisor_communicator;
mod ssn;

/// Command line arguments for the Hypervisor Communicator.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CommandsArg,
}

#[derive(Subcommand)]
enum CommandsArg {
    /// Sets up a kernel inline hook
    InlineHook {
        /// The name of the function to hook
        #[arg(short, long)]
        function: String,
    },
    /// Sets up a syscall hook
    SyscallHook {
        /// The name of the syscall to hook
        #[arg(short, long)]
        function: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let communicator = HypervisorCommunicator::new();
    let mut syscall = Syscall::new();

    match &cli.command {
        CommandsArg::InlineHook { function } => {
            let function_hash = djb2_hash(function.as_bytes());
            println!("Function: {} Hash: {:#x}", function, function_hash);
            let client_data = ClientData {
                command: Commands::EnableKernelInlineHook,
                syscall_number: 0,
                get_from_win32k: false,
                function_hash,
            };
            let client_data_ptr = &client_data as *const ClientData as u64;
            let result = communicator.call_hypervisor(client_data_ptr);
            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);
            if result.eax == 0 {
                println!("Failed to enable inline hook");
            } else {
                println!("Successfully enabled inline hook");
            }
        }
        CommandsArg::SyscallHook { function } => {
            let function_hash = djb2_hash(function.as_bytes());
            let ssn = syscall.get_ssn_by_hash(function_hash).expect("Failed to get SSN");
            println!("Function: {} SSN: {}", function, ssn);
            let client_data = ClientData {
                command: Commands::EnableSyscallInlineHook,
                syscall_number: ssn as i32,
                get_from_win32k: false,
                function_hash: 0,
            };
            let client_data_ptr = &client_data as *const ClientData as u64;
            let result = communicator.call_hypervisor(client_data_ptr);
            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);
            if result.eax == 0 {
                println!("Failed to enable syscall hook");
            } else {
                println!("Successfully enabled syscall hook");
            }
        }
    }
}
