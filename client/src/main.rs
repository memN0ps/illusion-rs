//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

#![feature(asm_const)]

use {
    crate::hypervisor_communicator::{djb2_hash, Commands, HypervisorCommunicator},
    clap::{Parser, Subcommand},
};
use crate::ssn::syscall::Syscall;

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
    /// Disables a page hook
    DisablePageHook {
        /// The guest virtual address of the page to disable the hook
        #[arg(short, long)]
        address: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let communicator = HypervisorCommunicator::new();
    let mut syscall = Syscall::new();

    match &cli.command {
        CommandsArg::InlineHook { function } => {
            let function_hash = djb2_hash(function.as_bytes());
            let result = communicator.call_hypervisor(Commands::EnableKernelInlineHook as u64, function_hash as u64, 0, 0);
            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);
        }
        CommandsArg::SyscallHook { function } => {
            let function_hash = djb2_hash(function.as_bytes());
            let ssn = syscall
                .get_ssn_by_hash(function_hash)
                .expect(obfstr::obfstr!("Failed to get SSN"));
            println!("Function: {} SSN: {}", function, ssn);
            let result = communicator.call_hypervisor(Commands::EnableSyscallInlineHook as u64, ssn as u64, 0, 0);
            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);
        }
        CommandsArg::DisablePageHook { address } => {
            let address = u64::from_str_radix(address.trim_start_matches("0x"), 16).expect("Invalid address");
            let result = communicator.call_hypervisor(Commands::DisablePageHook as u64, address, 0, 0);
            println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);
        }
    }
}
