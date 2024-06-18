//! # Hypervisor Communicator
//!
//! This demonstrates how to use the `HypervisorCommunicator` library to send
//! password-protected CPUID commands to a UEFI hypervisor.

use {
    crate::{hypervisor_communicator::HypervisorCommunicator, ssn::syscall::Syscall},
    clap::{Parser, Subcommand},
    core_affinity,
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
    /// Get CPUID vendor information for all logical processors
    GetCpuidVendor,
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
        CommandsArg::GetCpuidVendor => {
            execute_cpuid_on_all_logical_processors();
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

    // Lookup the syscall number using the function hash
    let mut syscall = Syscall::new();
    let syscall_number = match syscall.get_ssn_by_hash(function_hash) {
        Some(number) => number,
        None => {
            println!("Failed to find syscall number for function: {}", function_name);
            return;
        }
    };
    println!("Function: {} Syscall number: {}", function_name, syscall_number);

    let client_data = ClientData {
        command,
        function_hash,
        syscall_number,
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

/// Executes CPUID(0x40000000) on all logical processors and prints the vendor information.
fn execute_cpuid_on_all_logical_processors() {
    println!("Executing CPUID(0x40000000) on all logical processors");
    for core_id in core_affinity::get_core_ids().unwrap() {
        assert!(core_affinity::set_for_current(core_id));
        let regs = raw_cpuid::cpuid!(0x4000_0000);
        let mut vec = regs.ebx.to_le_bytes().to_vec();
        vec.extend(regs.ecx.to_le_bytes());
        vec.extend(regs.edx.to_le_bytes());
        println!("CPU{:2}: {}", core_id.id, String::from_utf8_lossy(vec.as_slice()));
    }
}
