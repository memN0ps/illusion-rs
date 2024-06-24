use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            hooks::hook_manager::{EptHookType, HookManager},
            vm::Vm,
        },
        windows::{
            nt::pe::{get_export_by_hash, get_image_base_address, get_size_of_image},
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    log::*,
};

/// Represents a hook into the Windows kernel, allowing redirection of functions and syscalls.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KernelHook {
    /// The base virtual address of ntoskrnl.exe.
    ntoskrnl_base_va: u64,

    /// The base physical address of ntoskrnl.exe.
    ntoskrnl_base_pa: u64,

    /// The size of ntoskrnl.exe.
    ntoskrnl_size: u64,
}

impl KernelHook {
    /// Creates a new instance of `KernelHook`.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - The new instance of `KernelHook`.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing kernel hook");
        Ok(Self {
            ntoskrnl_base_va: 0,
            ntoskrnl_base_pa: 0,
            ntoskrnl_size: 0,
        })
    }

    /// Sets the base address and size of the Windows kernel.
    ///
    /// # Arguments
    ///
    /// * `guest_va` - The virtual address of the guest.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The kernel base and size were set successfully.
    pub fn set_kernel_base_and_size(&mut self, guest_va: u64) -> Result<(), HypervisorError> {
        // Get the base address of ntoskrnl.exe.
        self.ntoskrnl_base_va = unsafe { get_image_base_address(guest_va).ok_or(HypervisorError::FailedToGetImageBaseAddress)? };

        // Get the physical address of ntoskrnl.exe using GUEST_CR3 and the virtual address.
        self.ntoskrnl_base_pa = PhysicalAddress::pa_from_va(self.ntoskrnl_base_va);

        // Get the size of ntoskrnl.exe.
        self.ntoskrnl_size = unsafe { get_size_of_image(self.ntoskrnl_base_pa as _).ok_or(HypervisorError::FailedToGetKernelSize)? } as u64;

        Ok(())
    }

    /// Manages an EPT hook for a kernel function, enabling or disabling it.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to install/remove the hook on.
    /// * `function_hash` - The hash of the function to hook/unhook.
    /// * `syscall_number` - The syscall number to use if `get_export_by_hash` fails.
    /// * `ept_hook_type` - The type of EPT hook to use.
    /// * `enable` - A boolean indicating whether to enable (true) or disable (false) the hook.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was managed successfully.
    /// * `Err(HypervisorError)` - If the hook management fails.
    pub fn manage_kernel_ept_hook(
        &mut self,
        vm: &mut Vm,
        function_hash: u32,
        syscall_number: u16,
        ept_hook_type: EptHookType,
        enable: bool,
    ) -> Result<(), HypervisorError> {
        let action = if enable { "Enabling" } else { "Disabling" };
        debug!("{} EPT hook for function: {}", action, function_hash);

        let function_va = unsafe {
            if let Some(va) = get_export_by_hash(self.ntoskrnl_base_pa as _, self.ntoskrnl_base_va as _, function_hash) {
                va
            } else {
                let ssdt_function_address =
                    SsdtHook::find_ssdt_function_address(syscall_number as _, false, self.ntoskrnl_base_pa as _, self.ntoskrnl_size as _);
                match ssdt_function_address {
                    Ok(ssdt_hook) => ssdt_hook.guest_function_va as *mut u8,
                    Err(_) => return Err(HypervisorError::FailedToGetExport),
                }
            }
        };

        if enable {
            HookManager::ept_hook_function(vm, function_va as _, function_hash, ept_hook_type)?;
        } else {
            HookManager::ept_unhook_function(vm, function_va as _, ept_hook_type)?;
        }

        Ok(())
    }
}
