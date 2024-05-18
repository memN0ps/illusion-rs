use {
    crate::intel::{
        addresses::PhysicalAddress,
        ept::AccessType,
        hooks::{hook_manager::EptHookType, inline::InlineHookType},
        vm::Vm,
    },
    log::*,
    x86::bits64::paging::PAddr,
};

/// Enumeration of possible commands that can be issued to the hypervisor.
///
/// This enum represents different commands that can be sent to the hypervisor for
/// various operations such as enabling hooks or disabling page hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Commands {
    /// Command to enable a kernel inline hook.
    EnableKernelInlineHook,
    /// Command to enable a syscall inline hook.
    EnableSyscallInlineHook,
    /// Command to disable a page hook.
    DisablePageHook,
    /// Invalid command.
    Invalid,
}

impl Commands {
    /// Converts a `u64` value to a `Commands` enum variant.
    ///
    /// # Arguments
    ///
    /// * `value` - The `u64` value to convert.
    ///
    /// # Returns
    ///
    /// * `Commands` - The corresponding `Commands` enum variant.
    pub fn from_u64(value: u64) -> Commands {
        match value {
            0 => Commands::EnableKernelInlineHook,
            1 => Commands::EnableSyscallInlineHook,
            2 => Commands::DisablePageHook,
            _ => Commands::Invalid,
        }
    }
}

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
    let command = Commands::from_u64(vm.guest_registers.rcx);
    debug!("Command: {:?}", command);

    match command {
        Commands::EnableKernelInlineHook => {
            debug!("Hook command received");
            let mut kernel_hook = vm.hook_manager.as_mut().kernel_hook;
            let function_hash = vm.guest_registers.rdx as u32;

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
            let mut kernel_hook = vm.hook_manager.as_mut().kernel_hook;
            let syscall_number = vm.guest_registers.rdx as i32;
            let get_from_win32k = vm.guest_registers.r8 == 1;

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
