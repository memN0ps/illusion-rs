use {
    crate::intel::{
        addresses::PhysicalAddress,
        hooks::{hook_manager::EptHookType, inline::InlineHookType},
        vm::Vm,
    },
    log::*,
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
    let client_data_ptr = PhysicalAddress::pa_from_va(vm.guest_registers.rcx);
    debug!("Client data pointer: {:#x}", client_data_ptr);

    // Convert the pointer to ClientData
    let client_data = ClientData::from_ptr(client_data_ptr);
    debug!("Client data: {:?}", client_data);

    // Handle the command
    let result = match client_data.command {
        Commands::EnableKernelEptHook | Commands::DisableKernelEptHook => {
            let enable = client_data.command == Commands::EnableKernelEptHook;
            if let Some(mut kernel_hook) = vm.hook_manager.kernel_hook.take() {
                let result = kernel_hook.manage_kernel_ept_hook(
                    vm,
                    client_data.function_hash,
                    client_data.syscall_number,
                    EptHookType::Function(InlineHookType::Vmcall),
                    enable,
                );

                // Put the kernel hook back in the box
                vm.hook_manager.kernel_hook = Some(kernel_hook);

                match result {
                    Ok(_) => true,
                    Err(e) => {
                        let action = if enable { "setup" } else { "disable" };
                        error!("Failed to {} kernel EPT hook: {:?}", action, e);
                        false
                    }
                }
            } else {
                error!("KernelHook is missing");
                false
            }
        }
        Commands::Invalid => {
            error!("Invalid command received");
            false
        }
    };

    result
}
