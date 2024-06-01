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
            if let Some(function_hash) = client_data.function_hash {
                handle_kernel_hook(vm, Some(function_hash), None, client_data.command == Commands::EnableKernelEptHook, false)
            } else {
                error!("Function hash is missing for kernel hook");
                false
            }
        }
        Commands::EnableSyscallEptHook | Commands::DisableSyscallEptHook => {
            if let Some(syscall_number) = client_data.syscall_number {
                if let Some(function_hash) = client_data.function_hash {
                    handle_kernel_hook(vm, Some(function_hash), Some(syscall_number), client_data.command == Commands::EnableSyscallEptHook, true)
                } else {
                    error!("Function hash is missing for syscall hook");
                    false
                }
            } else {
                error!("Syscall number is missing for syscall hook");
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

/// Handles kernel and syscall hooks.
///
/// This function sets up or removes kernel and syscall hooks based on the provided parameters.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
/// * `function_hash` - An optional hash of the function to hook or unhook.
/// * `syscall_number` - An optional number of the syscall to hook or unhook.
/// * `enable` - A boolean flag to enable or disable the hook.
/// * `is_syscall` - A boolean flag to indicate if the hook is for a syscall.
///
/// # Returns
///
/// * `bool` - `true` if the hook was handled successfully, `false` otherwise.
fn handle_kernel_hook(vm: &mut Vm, function_hash: Option<u32>, syscall_number: Option<u16>, enable: bool, is_syscall: bool) -> bool {
    if let Some(mut kernel_hook) = vm.hook_manager.kernel_hook.take() {
        let result = if enable {
            if is_syscall {
                kernel_hook.enable_syscall_ept_hook(
                    vm,
                    function_hash.unwrap(),
                    syscall_number.unwrap(),
                    EptHookType::Function(InlineHookType::Vmcall),
                )
            } else {
                kernel_hook.enable_kernel_ept_hook(vm, function_hash.unwrap(), EptHookType::Function(InlineHookType::Vmcall))
            }
        } else {
            if is_syscall {
                kernel_hook.disable_syscall_ept_hook(vm, syscall_number.unwrap(), EptHookType::Function(InlineHookType::Vmcall))
            } else {
                kernel_hook.disable_kernel_ept_hook(vm, function_hash.unwrap(), EptHookType::Function(InlineHookType::Vmcall))
            }
        };

        // Put the kernel hook back in the box
        vm.hook_manager.kernel_hook = Some(kernel_hook);

        match result {
            Ok(_) => true,
            Err(e) => {
                let action = if enable { "setup" } else { "disable" };
                let hook_type = if is_syscall { "syscall" } else { "kernel" };
                error!("Failed to {} {} EPT hook: {:?}", action, hook_type, e);
                false
            }
        }
    } else {
        let hook_type = if is_syscall { "SyscallHook" } else { "KernelHook" };
        error!("{} is missing", hook_type);
        false
    }
}
