use {
    crate::{hypervisor_communicator::HypervisorCommunicator, process::get_process_id_by_name},
    shared::{ClientData, ClientDataPayload, CommandStatus, Commands, MemoryData},
    std::mem::size_of,
};

pub mod hypervisor_communicator;
pub mod process;

fn main() {
    // Initialize the HypervisorCommunicator
    let communicator = HypervisorCommunicator::new();

    // The current process ID (this is just a placeholder, in a real scenario you'd fetch the actual PID)
    // let current_pid = std::process::id() as u64;

    let current_pid = get_process_id_by_name("notepad.exe").unwrap() as u64;

    // Example variable to read (we're setting it to 1337 as a test value)
    let test_var: u64 = 0xBADC0DE;
    let test_address: u64 = &test_var as *const u64 as u64;

    // Buffer to store the result of the memory read (this would normally point to a location in guest memory)
    let mut buffer: u64 = 0;
    let buffer_address: u64 = &mut buffer as *mut u64 as u64;

    // Construct the MemoryData payload
    let memory_data = MemoryData {
        process_id: current_pid,
        address: test_address,
        buffer: buffer_address,
        size: size_of::<u64>() as u64,
    };

    // Construct the ClientData for ReadProcessMemory command
    let client_data = ClientData {
        command: Commands::ReadProcessMemory,
        payload: ClientDataPayload::Memory(memory_data),
    };

    // Send the command to the hypervisor and get the result
    let result = communicator.call_hypervisor(client_data.as_ptr());

    // Check if the command was successful by examining the EAX register
    if result.eax == CommandStatus::Success.to_u64() {
        // If successful, read the value from the buffer address
        println!("Memory read successful!");
        println!("Value at test_var address {:#x}: {:#x}", test_address, buffer);
    } else {
        println!("Memory read failed. Hypervisor returned failure status.");
    }

    // Print the full CPUID result for debugging purposes
    println!("CPUID Result:");
    println!("EAX: {:#x}", result.eax);
    println!("EBX: {:#x}", result.ebx);
    println!("ECX: {:#x}", result.ecx);
    println!("EDX: {:#x}", result.edx);
}
