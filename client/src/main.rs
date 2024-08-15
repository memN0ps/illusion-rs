use {
    crate::hypervisor_communicator::HypervisorCommunicator,
    shared::{ClientData, ClientDataPayload, CommandStatus, Commands, MemoryData},
    std::mem::size_of,
};

pub mod hypervisor_communicator;

fn main() {
    // Initialize the HypervisorCommunicator
    let communicator = HypervisorCommunicator::new();

    // The current process ID (this is just a placeholder, in a real scenario you'd fetch the actual PID)
    let current_pid = std::process::id() as u64;

    // The address you want to read (this is a test address, you'd replace it with the actual address you're interested in)
    let test_address: u64 = 0x1000;

    // Buffer to store the result of the memory read (this would normally point to a location in guest memory)
    let buffer_address: u64 = 0x2000;

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
        let value: u64;
        unsafe {
            value = *(buffer_address as *const u64);
        }

        println!("Memory read successful!");
        println!("Value at address {:#x}: {:#x}", test_address, value);
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
