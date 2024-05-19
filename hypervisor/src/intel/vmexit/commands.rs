use {
    crate::intel::{
        addresses::PhysicalAddress,
        ept::AccessType,
        hooks::{hook_manager::EptHookType, inline::InlineHookType},
        vm::Vm,
    },
    log::*,
    shared::{ClientData, Commands},
    x86::bits64::paging::PAddr,
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

    // Convert the command value to the Commands enum
    let command = Commands::from_u64(client_data.command as _);
    debug!("Command: {:?}", command);

    match command {
        Commands::EnableKernelInlineHook => {
            debug!("Hook command received");
            let mut kernel_hook = vm.hook_manager.kernel_hook.clone();
            let function_hash = client_data.function_hash;

            if kernel_hook
                .setup_kernel_inline_hook(vm, function_hash, EptHookType::Function(InlineHookType::Vmcall))
                .is_ok()
            {
                true
            } else {
                error!("Failed to setup kernel inline hook");
                false
            }
        }
        Commands::EnableSyscallInlineHook => {
            let mut kernel_hook = vm.hook_manager.kernel_hook.clone();
            let syscall_number = client_data.syscall_number;
            let get_from_win32k = client_data.get_from_win32k;

            if kernel_hook
                .setup_kernel_ssdt_hook(vm, syscall_number, get_from_win32k, EptHookType::Function(InlineHookType::Vmcall))
                .is_ok()
            {
                true
            } else {
                error!("Failed to setup syscall inline hook");
                false
            }
        }
        Commands::DisablePageHook => {
            let guest_pa = PAddr::from(PhysicalAddress::pa_from_va(vm.guest_registers.rdx));
            let guest_page_pa = guest_pa.align_down_to_base_page();

            if let Some(pre_alloc_pt) = vm.hook_manager.memory_manager.get_page_table_as_mut(guest_page_pa.as_u64()) {
                if vm
                    .primary_ept
                    .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)
                    .is_ok()
                {
                    true
                } else {
                    error!("Failed to swap page");
                    false
                }
            } else {
                error!("Page table not found");
                false
            }
        }
        Commands::Invalid => {
            error!("Invalid command received");
            false
        }
    }
}
