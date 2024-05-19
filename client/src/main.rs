//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

#![feature(asm_const)]

use {
    crate::hypervisor_communicator::HypervisorCommunicator,
    clap::{Parser, Subcommand},
    shared::{djb2_hash, ClientData, Commands},
};

mod hypervisor_communicator;

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
    /// Unsets a kernel inline hook
    DisableKernelInlineHook {
        /// The name of the function to unhook
        #[arg(short, long)]
        function: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let communicator = HypervisorCommunicator::new();
    match &cli.command {
        CommandsArg::InlineHook { function: function_name } => {
            let function_hash = djb2_hash(function_name.as_bytes());
            println!("Function: {} Hash: {:#x}", function_name, function_hash);

            let client_data = ClientData {
                command: Commands::EnableKernelInlineHook,
                function_hash,
            };

            let client_data_ptr = client_data.as_ptr();
            let result = communicator.call_hypervisor(client_data_ptr);

            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);

            if result.eax == 0 {
                println!("Failed to enable kernel inline hook");
            } else {
                println!("Successfully enabled kernel inline hook");
            }
        }
        CommandsArg::DisableKernelInlineHook { function: function_name } => {
            let function_hash = djb2_hash(function_name.as_bytes());
            println!("Function: {} Hash: {:#x}", function_name, function_hash);

            let client_data = ClientData {
                command: Commands::DisableKernelInlineHook,
                function_hash,
            };

            let client_data_ptr = client_data.as_ptr();
            let result = communicator.call_hypervisor(client_data_ptr);

            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);

            if result.eax == 0 {
                println!("Failed to disable inline hook");
            } else {
                println!("Successfully disabled inline hook");
            }
        }
    }
}
