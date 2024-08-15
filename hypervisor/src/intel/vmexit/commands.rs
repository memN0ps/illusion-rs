use {
    crate::{
        intel::{
            addresses::PhysicalAddress,
            hooks::{
                hook_manager::{EptHookType, SHARED_HOOK_MANAGER},
                inline::InlineHookType,
            },
            vm::Vm,
        },
        windows::process_info::ProcessInformation,
    },
    log::{debug, error},
    shared::{ClientData, ClientDataPayload, Commands, HookData, MemoryData},
};

/// Handles guest commands sent to the hypervisor.
///
/// This function processes the commands sent from the guest and performs the
/// corresponding actions such as setting up hooks or reading/writing process memory.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the command was handled successfully, or `None` if an error occurred.
pub fn handle_guest_commands(vm: &mut Vm) -> Option<()> {
    debug!("Handling commands");

    // Convert guest RCX register value to a physical address pointer to `ClientData`.
    let client_data_ptr = match PhysicalAddress::pa_from_va_with_current_cr3(vm.guest_registers.rcx) {
        Ok(pa) => pa,
        Err(e) => {
            error!("Failed to convert guest RCX to pointer: {:?}", e);
            return None;
        }
    };

    debug!("Client data pointer: {:#x}", client_data_ptr);

    // Convert the pointer to `ClientData`.
    let client_data = ClientData::from_ptr(client_data_ptr);
    debug!("Client data: {:#x?}", client_data);

    // Handle the command based on the command type and payload
    match client_data.command {
        Commands::EnableKernelEptHook | Commands::DisableKernelEptHook => {
            if let ClientDataPayload::Hook(hook) = client_data.payload {
                handle_hook_command(vm, client_data.command, hook)
            } else {
                error!("Expected HookData for hook command, but found MemoryData.");
                None
            }
        }
        Commands::ReadProcessMemory | Commands::WriteProcessMemory => {
            if let ClientDataPayload::Memory(memory) = client_data.payload {
                match client_data.command {
                    Commands::ReadProcessMemory => handle_read_memory(vm, memory),
                    Commands::WriteProcessMemory => handle_write_memory(vm, memory),
                    _ => None,
                }
            } else {
                error!("Expected MemoryData for memory command, but found HookData.");
                None
            }
        }
        Commands::Invalid => {
            error!("Invalid command received");
            None
        }
    }
}

/// Handles hook commands such as enabling or disabling kernel EPT hooks.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `command` - The command to handle (either enabling or disabling hooks).
/// * `hook` - The `HookData` containing details about the hook.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the hook command was handled successfully, or `None` if an error occurred.
fn handle_hook_command(vm: &mut Vm, command: Commands, hook: HookData) -> Option<()> {
    let enable = command == Commands::EnableKernelEptHook;

    // Lock the shared hook manager
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    // Manage the kernel EPT hook
    if let Err(e) =
        hook_manager.manage_kernel_ept_hook(vm, hook.function_hash, hook.syscall_number, EptHookType::Function(InlineHookType::Vmcall), enable)
    {
        let action = if enable { "setup" } else { "disable" };
        error!("Failed to {} kernel EPT hook: {:?}", action, e);
        return None;
    }

    Some(())
}

/// Handles the reading of process memory from a guest.
///
/// This function locates the target process, retrieves its directory table base (CR3), and reads the
/// requested memory region. The result is then written back to a buffer accessible by the guest client.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `MemoryData` struct containing details about the memory read operation.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the memory was read successfully, or `None` if an error occurred.
fn handle_read_memory(_vm: &mut Vm, memory: MemoryData) -> Option<()> {
    debug!("Reading memory from process ID: {:#x}, address: {:#x}, buffer: {:#x}", memory.process_id, memory.address, memory.buffer);

    // Step 1: Find the process CR3 by the process ID.
    let guest_process_cr3 = ProcessInformation::get_directory_table_base_by_process_id(memory.process_id)?;
    debug!("Guest process CR3: {:#x}", guest_process_cr3);

    // Step 2: Read the memory from the process using the CR3 of the target process.
    let value = PhysicalAddress::read_guest_virt_with_explicit_cr3(memory.address as *const u64, guest_process_cr3)?;
    debug!("Read value: {:#x}", value);

    // Step 3: Write the memory to the buffer to be returned to the guest client (user-mode application).
    PhysicalAddress::write_guest_virt_with_current_cr3(memory.buffer as *mut u64, value)?;

    Some(())
}

/// Handles the writing of process memory from a guest.
///
/// This function locates the target process, retrieves its directory table base (CR3), and writes the
/// provided memory content to the specified address within the target process.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `MemoryData` struct containing details about the memory write operation.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the memory was written successfully, or `None` if an error occurred.
fn handle_write_memory(_vm: &mut Vm, memory: MemoryData) -> Option<()> {
    debug!("Writing memory to process ID: {:#x}, address: {:#x}, buffer: {:#x}", memory.process_id, memory.address, memory.buffer);

    // Step 1: Find the process CR3 by the process ID.
    let guest_process_cr3 = ProcessInformation::get_directory_table_base_by_process_id(memory.process_id)?;

    // Step 2: Read the value to be written from the guest buffer.
    let value = PhysicalAddress::read_guest_virt_with_current_cr3(memory.buffer as *const u64)?;
    debug!("Write value: {:#x}", value);

    // Step 3: Write the value to the specified memory address in the target process.
    PhysicalAddress::write_guest_virt_with_explicit_cr3(memory.address as *mut u64, value, guest_process_cr3)?;

    Some(())
}
