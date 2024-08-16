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
/// and stores it in the buffer provided by the user mode.
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
    debug!("Opening process with ID: {:#x}", memory.process_id?);

    // Retrieve the guest CR3 for the process ID
    let guest_process_cr3 = ProcessInformation::get_directory_table_base_by_process_id(memory.process_id?)?;
    debug!("Obtained process CR3: {:#x}", guest_process_cr3);

    // Return the CR3 to the guest by writing it to the buffer provided by the user mode
    PhysicalAddress::write_guest_virt_with_current_cr3(memory.buffer as *mut u64, guest_process_cr3)?;

    Some(())
}

/// Handles the `ReadProcessMemory` command.
///
/// This function reads memory from the guest target process identified by the stored CR3 and returns
/// the read value to the guest.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `ProcessMemoryOperation` containing details about the memory read operation.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the memory was read successfully, or `None` if an error occurred.
fn handle_read_memory(_vm: &mut Vm, memory: ProcessMemoryOperation) -> Option<()> {
    debug!("Reading memory from process, address: {:#x}", memory.address?);

    // Read the memory from the specified address
    let value = PhysicalAddress::read_guest_virt_with_current_cr3(memory.address? as *const u64)?;

    // Return the read value to the guest
    PhysicalAddress::write_guest_virt_with_current_cr3(memory.buffer as *mut u64, value)?;
    Some(())
}

/// Handles the `WriteProcessMemory` command.
///
/// This function writes memory to the guest target process identified by the stored CR3 using the provided buffer.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `memory` - The `ProcessMemoryOperation` containing details about the memory write operation.
///
/// # Returns
///
/// * `Option<()>` - Returns `Some(())` if the memory was written successfully, or `None` if an error occurred.
fn handle_write_memory(_vm: &mut Vm, memory: ProcessMemoryOperation) -> Option<()> {
    debug!("Writing memory to process, address: {:#x}", memory.address?);

    // Read the value to be written from the guest buffer
    let value = PhysicalAddress::read_guest_virt_with_current_cr3(memory.buffer as *const u64)?;

    // Write the value to the specified address in the target process
    PhysicalAddress::write_guest_virt_with_current_cr3(memory.address? as *mut u64, value)?;
    Some(())
}

/// Handles commands related to enabling or disabling kernel EPT hooks.
///
/// This function manages the setup or removal of kernel EPT hooks based on the provided command.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `command` - The command indicating whether to enable or disable the hook.
/// * `hook` - The `HookData` containing details about the hook.
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
