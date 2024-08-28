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
        windows::eprocess::ProcessInformation,
    },
    log::{debug, error},
    shared::{ClientCommand, ClientDataPayload, Command, HookData, ProcessMemoryOperation},
};

/// Handles guest commands sent to the hypervisor.
///
/// This function processes commands issued by the guest, such as opening a process,
/// reading or writing memory, and enabling or disabling kernel EPT hooks.
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

    // Convert guest RCX register value to a physical address pointer to `ClientCommand`.
    let client_command_ptr = PhysicalAddress::pa_from_va_with_current_cr3(vm.guest_registers.rcx).ok()?;
    let client_command = ClientCommand::from_ptr(client_command_ptr);

    // Match the command and handle accordingly
    match client_command.command {
        Command::OpenProcess => {
            if let ClientDataPayload::Memory(memory) = client_command.payload {
                handle_open_process(vm, memory)
            } else {
                error!("Expected ProcessMemoryOperation for OpenProcess command.");
                None
            }
        }
        Command::ReadProcessMemory => {
            if let ClientDataPayload::Memory(memory) = client_command.payload {
                handle_read_memory(vm, memory)
            } else {
                error!("Expected Memory for ReadProcessMemory command.");
                None
            }
        }
        Command::WriteProcessMemory => {
            if let ClientDataPayload::Memory(memory) = client_command.payload {
                handle_write_memory(vm, memory)
            } else {
                error!("Expected Memory for WriteProcessMemory command.");
                None
            }
        }
        Command::EnableKernelEptHook | Command::DisableKernelEptHook => {
            if let ClientDataPayload::Hook(hook) = client_command.payload {
                handle_hook_command(vm, client_command.command, hook)
            } else {
                error!("Expected HookData for hook command.");
                None
            }
        }
        Command::Invalid => {
            error!("Invalid command received");
            None
        }
    }
}

/// Handles the `OpenProcess` command.
///
/// This function retrieves the guest CR3 (directory table base) of the specified process
/// and writes it to the buffer provided by the user mode client.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `ProcessMemoryOperation` containing details about the process to open.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the process was opened successfully, or `None` if an error occurred.
fn handle_open_process(_vm: &mut Vm, memory: ProcessMemoryOperation) -> Option<()> {
    debug!("Opening process with ID: {}", memory.process_id?);

    // Retrieve the guest CR3 for the process ID
    let target_process_cr3 = ProcessInformation::get_directory_table_base_by_process_id(memory.process_id?)?;
    debug!("Obtained process CR3: {:#x}", target_process_cr3);

    // Write the CR3 to the buffer provided by the user mode client
    PhysicalAddress::write_guest_virt_with_current_cr3(memory.buffer as *mut u64, target_process_cr3)?;

    Some(())
}

/// Handles the `ReadProcessMemory` command.
///
/// This function reads a block of memory from the guest target process identified by the stored CR3
/// and writes the read data to the buffer provided by the user mode client.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `ProcessMemoryOperation` containing details about the memory read operation, including the target address and the buffer to store the read data.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the memory was read successfully, or `None` if an error occurred.
fn handle_read_memory(_vm: &mut Vm, memory: ProcessMemoryOperation) -> Option<()> {
    debug!("Reading memory from process, address: {:#x} with CR3: {:#x}", memory.address?, memory.guest_cr3?);

    // Read the memory from the specified address in the target process
    let data =
        PhysicalAddress::read_guest_virt_slice_with_explicit_cr3(memory.address? as *const u8, memory.buffer_size as usize, memory.guest_cr3?)?;

    // Write the read data to the buffer provided by the user mode client
    PhysicalAddress::write_guest_virt_slice_with_current_cr3(memory.buffer as *mut u8, data)?;

    Some(())
}

/// Handles the `WriteProcessMemory` command.
///
/// This function writes a block of memory to the guest target process identified by the stored CR3
/// using the data provided in the user mode client's buffer.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `ProcessMemoryOperation` containing details about the memory write operation, including the target address and the buffer containing the data to be written.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the memory was written successfully, or `None` if an error occurred.
fn handle_write_memory(_vm: &mut Vm, memory: ProcessMemoryOperation) -> Option<()> {
    debug!("Writing memory to process, address: {:#x} with CR3: {:#x}", memory.address?, memory.guest_cr3?);

    // Write the data from the buffer provided by the user mode client to the specified address in the target process
    let data = PhysicalAddress::read_guest_virt_slice_with_current_cr3(memory.buffer as *const u8, memory.buffer_size as usize)?;
    PhysicalAddress::write_guest_virt_slice_with_explicit_cr3(memory.address? as *mut u8, data, memory.guest_cr3?)?;

    Some(())
}

/// Handles commands related to enabling or disabling kernel EPT hooks.
///
/// This function manages the setup or removal of kernel EPT hooks based on the provided command.
/// It enables or disables the hooks for specific functions based on the function hash and syscall number provided.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `command` - The command indicating whether to enable or disable the hook.
/// * `hook` - The `HookData` containing details about the hook, including the function hash and syscall number.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the hook command was handled successfully, or `None` if an error occurred.
fn handle_hook_command(vm: &mut Vm, command: Command, hook: HookData) -> Option<()> {
    let enable = command == Command::EnableKernelEptHook;
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    hook_manager
        .manage_kernel_ept_hook(vm, hook.function_hash, hook.syscall_number, EptHookType::Function(InlineHookType::Vmcall), enable)
        .ok()?;
    Some(())
}
