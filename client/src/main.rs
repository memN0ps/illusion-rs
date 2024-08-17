use crate::{hypervisor_communicator::HypervisorCommunicator, memory::process::process_manager::ProcessManager};

mod hypervisor_communicator;
mod memory;

fn main() {
    let pm = ProcessManager::new();
    let process = pm.get_process_id_by_name("notepad.exe").unwrap() as u64;

    if let Some(hypervisor) = HypervisorCommunicator::open_process(process) {
        // Find a valid base address for reading/writing
        let base_address = match pm.get_module_address_by_name("notepad.exe", process) {
            Ok(addy) => addy as u64,
            Err(e) => {
                println!("Failed to find a valid base address: {:?}", e);
                return;
            }
        };

        // Read memory from the base address
        let mut buffer = [0u8; 1024];
        if hypervisor.read_process_memory(base_address, &mut buffer).is_some() {
            println!("Memory read successfully: {:?}", &buffer);
        } else {
            println!("Failed to read memory");
        }

        // Write data to the base address
        let data_to_write = [1u8, 2, 3, 4];
        if hypervisor.write_process_memory(base_address, &data_to_write).is_some() {
            println!("Memory written successfully");
        } else {
            println!("Failed to write memory");
        }
    } else {
        println!("Failed to open process");
    }
}
