use {
    crate::intel::{
        addresses::PhysicalAddress,
        hooks::{
            hook_manager::{EptHookType, SHARED_HOOK_MANAGER},
            inline::InlineHookType,
        },
        vm::Vm,
    },
    log::{debug, error},
    shared::{ClientData, Commands},
};

/// Handles guest commands sent to the hypervisor.
///
/// This function processes the commands sent from the guest and performs the
/// corresponding actions such as setting up hooks or disabling page hooks.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
///
/// # Returns
///
/// * `bool` - `true` if the command was handled successfully, `false` otherwise.
pub fn handle_guest_commands(vm: &mut Vm) -> bool {
    debug!("Handling commands");

    // Convert guest RCX register value to a pointer to ClientData
    let client_data_ptr = match PhysicalAddress::pa_from_va(vm.guest_registers.rcx) {
        Ok(pa) => pa,
        Err(e) => {
            error!("Failed to convert guest RCX to pointer: {:?}", e);
            return false;
        }
    };

    debug!("Client data pointer: {:#x}", client_data_ptr);

    // Convert the pointer to ClientData
    let client_data = ClientData::from_ptr(client_data_ptr);
    debug!("Client data: {:#x?}", client_data);

    // Handle the command
    let result = match client_data.command {
        Commands::EnableKernelEptHook | Commands::DisableKernelEptHook => {
            let enable = client_data.command == Commands::EnableKernelEptHook;

            // Lock the shared hook manager
            let mut hook_manager = SHARED_HOOK_MANAGER.lock();

            // Manage the kernel EPT hook
            let result = hook_manager.manage_kernel_ept_hook(
                vm,
                client_data.function_hash,
                client_data.syscall_number,
                EptHookType::Function(InlineHookType::Vmcall),
                enable,
            );

            match result {
                Ok(_) => true,
                Err(e) => {
                    let action = if enable { "setup" } else { "disable" };
                    error!("Failed to {} kernel EPT hook: {:?}", action, e);
                    false
                }
            }
        }
        Commands::Invalid => {
            error!("Invalid command received");
            false
        }
    };

    result
}
