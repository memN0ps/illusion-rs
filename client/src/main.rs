use crate::{hvapi::HypervisorCommunicator, memory::process::process_manager::ProcessManager};

pub mod hvapi;
mod memory;
mod pemem;
mod ssn;

fn main() {
    let pm = ProcessManager::new();
    let process = pm.get_process_id_by_name("notepad.exe").unwrap() as u64;

    // Open the process using the hypervisor
    if let Some(hypervisor) = HypervisorCommunicator::open_process(process) {
        // Find a valid base address for reading/writing
        let base_address = match pm.get_module_address_by_name("notepad.exe", process) {
            Ok(addy) => addy as u64,
            Err(e) => {
                log::debug!("Failed to find a valid base address: {:?}", e);
                return;
            }
        };

        // Read memory from the base address
        let mut buffer = [0u8; 1024];
        if hypervisor.read_process_memory(base_address, &mut buffer).is_some() {
            log::debug!("Memory read successfully: {:?}", &buffer);
        } else {
            log::debug!("Failed to read memory");
        }

        // Write data to the base address
        let data_to_write = [1u8, 2, 3, 4];
        if hypervisor.write_process_memory(base_address, &data_to_write).is_some() {
            log::debug!("Memory written successfully");
        } else {
            log::debug!("Failed to write memory");
        }

        // This will cause a crash if we're hiding UEFI memory in uefi\hide.rs (hide_uefi_memory) and if we're hiding hypervisor memory in hypervisor\vmm.rs (hide_hv_with_ept)
        /*
        // Enable EPT kernel hook for NtCreateFile
        if hypervisor.enable_ept_kernel_hook("NtCreateFile").is_some() {
            log::debug!("Successfully enabled EPT kernel hook for NtCreateFile");
        } else {
            log::debug!("Failed to enable EPT kernel hook for NtCreateFile");
        }

        // Disable EPT kernel hook for NtCreateFile
        if hypervisor.disable_ept_kernel_hook("NtCreateFile").is_some() {
            log::debug!("Successfully disabled EPT kernel hook for NtCreateFile");
        } else {
            log::debug!("Failed to disable EPT kernel hook for NtCreateFile");
        }

         */
    } else {
        log::debug!("Failed to open process");
    }
}
