//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

#![feature(asm_const)]

use {
    crate::{hypervisor_communicator::HypervisorCommunicator, ssn::syscall::Syscall},
    clap::{Parser, Subcommand},
    shared::{djb2_hash, ClientData, Commands},
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
    /// Sets up a kernel EPT hook
    EnableKernelEptHook {
        /// The name of the function to hook
        #[arg(short, long)]
        function: String,
    },
    /// Unsets a kernel EPT hook
    DisableKernelEptHook {
        /// The name of the function to unhook
        #[arg(short, long)]
        function: String,
    },
    /// Sets up a syscall EPT hook
    EnableSyscallEptHook {
        /// The name of the function to hook
        #[arg(short, long)]
        function: String,
    },
    /// Unsets a syscall EPT hook
    DisableSyscallEptHook {
        /// The name of the function to unhook
        #[arg(short, long)]
        function: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let communicator = HypervisorCommunicator::new();

    match &cli.command {
        CommandsArg::EnableKernelEptHook { function } => {
            handle_kernel_command(&communicator, function, Commands::EnableKernelEptHook);
        }
        CommandsArg::DisableKernelEptHook { function } => {
            handle_kernel_command(&communicator, function, Commands::DisableKernelEptHook);
        }
        CommandsArg::EnableSyscallEptHook { function } => {
            handle_syscall_command(&communicator, function, Commands::EnableSyscallEptHook);
        }
        CommandsArg::DisableSyscallEptHook { function } => {
            handle_syscall_command(&communicator, function, Commands::DisableSyscallEptHook);
        }
    }
}

/// Handles the command to enable or disable kernel hooks.
///
/// This function processes the command and sends the appropriate request to the hypervisor.
///
/// # Arguments
///
/// * `communicator` - The hypervisor communicator instance.
/// * `function_name` - The name of the function to hook or unhook.
/// * `command` - The command to execute.
fn handle_kernel_command(communicator: &HypervisorCommunicator, function_name: &str, command: Commands) {
    let function_hash = djb2_hash(function_name.as_bytes());
    println!("Function: {} Hash: {:#x}", function_name, function_hash);

    let client_data = ClientData {
        command,
        function_hash: Some(function_hash),
        syscall_number: None,
    };
    println!("Client data: {:?}", client_data);

    let client_data_ptr = client_data.as_ptr();
    let result = communicator.call_hypervisor(client_data_ptr);

    println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);

    if result.eax == 0 {
        match command {
            Commands::EnableKernelEptHook => {
                println!("Failed to enable kernel hook");
            }
            Commands::DisableKernelEptHook => {
                println!("Failed to disable kernel hook");
            }
            _ => {}
        }
    } else {
        match command {
            Commands::EnableKernelEptHook => {
                println!("Successfully enabled kernel hook");
            }
            Commands::DisableKernelEptHook => {
                println!("Successfully disabled kernel hook");
            }
            _ => {}
        }
    }
}

/// Handles the command to enable or disable syscall hooks.
///
/// This function processes the command, looks up the syscall number, and sends the appropriate request to the hypervisor.
///
/// # Arguments
///
/// * `communicator` - The hypervisor communicator instance.
/// * `function_name` - The name of the function to hook or unhook.
/// * `command` - The command to execute.
fn handle_syscall_command(communicator: &HypervisorCommunicator, function_name: &str, command: Commands) {
    let mut syscall = Syscall::new();

    let syscall_number = match syscall.get_ssn_by_hash(djb2_hash(function_name.as_bytes())) {
        Some(number) => number,
        None => {
            println!("Failed to find syscall number for function: {}", function_name);
            return;
        }
    };
    println!("Function: {} Syscall number: {}", function_name, syscall_number);

    let client_data = ClientData {
        command,
        function_hash: None,
        syscall_number: Some(syscall_number),
    };
    println!("Client data: {:?}", client_data);

    let client_data_ptr = client_data.as_ptr();
    let result = communicator.call_hypervisor(client_data_ptr);

    println!("Result: {:#x} {:#x} {:#x} {:#x}", result.eax, result.ebx, result.ecx, result.edx);

    if result.eax == 0 {
        match command {
            Commands::EnableSyscallEptHook => {
                println!("Failed to enable syscall hook");
            }
            Commands::DisableSyscallEptHook => {
                println!("Failed to disable syscall hook");
            }
            _ => {}
        }
    } else {
        match command {
            Commands::EnableSyscallEptHook => {
                println!("Successfully enabled syscall hook");
            }
            Commands::DisableSyscallEptHook => {
                println!("Successfully disabled syscall hook");
            }
            _ => {}
        }
    }
}
