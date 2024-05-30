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

    /// The base virtual address of win32k.sys.
    win32k_base_va: u64,

    /// The base physical address of win32k.sys.
    win32k_base_pa: u64,

    /// The size of win32k.sys.
    win32k_size: u64,
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
            win32k_base_va: 0,
            win32k_base_pa: 0,
            win32k_size: 0,
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

    /// Sets the base address and size of the Win32k kernel.
    ///
    /// # Arguments
    ///
    /// * `guest_va` - The virtual address of the guest.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The kernel base and size were set successfully.
    pub fn set_win32k_base_and_size(&mut self, guest_va: u64) -> Result<(), HypervisorError> {
        // Get the base address of win32k.sys.
        self.win32k_base_va = unsafe { get_image_base_address(guest_va).ok_or(HypervisorError::FailedToGetImageBaseAddress)? };

        // Get the physical address of win32k.sys using GUEST_CR3 and the virtual address.
        self.win32k_base_pa = PhysicalAddress::pa_from_va(self.win32k_base_va);

        // Get the size of win32k.sys.
        self.win32k_size = unsafe { get_size_of_image(self.win32k_base_pa as _).ok_or(HypervisorError::FailedToGetKernelSize)? } as u64;

        Ok(())
    }

    /// Enables an EPT hook for a kernel function.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to install the hook on.
    /// * `function_hash` - The hash of the function to hook.
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was installed successfully.
    /// * `Err(HypervisorError)` - If the hook installation fails.
    pub fn enable_kernel_ept_hook(&mut self, vm: &mut Vm, function_hash: u32, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        debug!("Setting up EPT hook for function: {}", function_hash);

        let function_va = unsafe {
            get_export_by_hash(self.ntoskrnl_base_pa as _, self.ntoskrnl_base_va as _, function_hash)
                .or_else(|| get_export_by_hash(self.win32k_base_pa as _, self.win32k_base_va as _, function_hash))
                .ok_or(HypervisorError::FailedToGetExport)?
        };

        HookManager::ept_hook_function(vm, function_va as _, function_hash, ept_hook_type)?;

        Ok(())
    }

    /// Disables an EPT hook for a kernel function.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to remove the hook from.
    /// * `function_hash` - The hash of the function to unhook.
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was removed successfully.
    /// * `Err(HypervisorError)` - If the hook removal fails.
    pub fn disable_kernel_ept_hook(&mut self, vm: &mut Vm, function_hash: u32, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        debug!("Disabling EPT hook for function: {}", function_hash);

        let function_va = unsafe {
            get_export_by_hash(self.ntoskrnl_base_pa as _, self.ntoskrnl_base_va as _, function_hash)
                .or_else(|| get_export_by_hash(self.win32k_base_pa as _, self.win32k_base_va as _, function_hash))
                .ok_or(HypervisorError::FailedToGetExport)?
        };

        HookManager::ept_unhook_function(vm, function_va as _, ept_hook_type)?;

        Ok(())
    }

    /// Enables an EPT hook for a syscall.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to install the hook on.
    /// * `syscall_number` - The number of the syscall to hook.
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was installed successfully.
    /// * `Err(HypervisorError)` - If the hook installation fails.
    pub fn enable_syscall_ept_hook(
        &mut self,
        vm: &mut Vm,
        function_hash: u32,
        syscall_number: u16,
        ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
        debug!("Setting up EPT hook for syscall: {}", syscall_number);

        let ssdt = SsdtHook::find_ssdt_function_address(syscall_number as _, false, self.ntoskrnl_base_pa as _, self.ntoskrnl_size as _)
            .or_else(|_| SsdtHook::find_ssdt_function_address(syscall_number as _, true, self.ntoskrnl_base_pa as _, self.ntoskrnl_size as _))
            .map_err(|_| HypervisorError::FailedToGetExport)?;

        let function_va = ssdt.guest_function_va as u64;

        HookManager::ept_hook_function(vm, function_va as _, function_hash, ept_hook_type)?;

        Ok(())
    }

    /// Disables an EPT hook for a syscall.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to remove the hook from.
    /// * `syscall_number` - The number of the syscall to unhook.
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was removed successfully.
    /// * `Err(HypervisorError)` - If the hook removal fails.
    pub fn disable_syscall_ept_hook(&mut self, vm: &mut Vm, syscall_number: u16, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        debug!("Disabling EPT hook for syscall: {}", syscall_number);

        let ssdt = SsdtHook::find_ssdt_function_address(syscall_number as _, false, self.ntoskrnl_base_pa as _, self.ntoskrnl_size as _)
            .or_else(|_| SsdtHook::find_ssdt_function_address(syscall_number as _, true, self.ntoskrnl_base_pa as _, self.ntoskrnl_size as _))
            .map_err(|_| HypervisorError::FailedToGetExport)?;

        let function_va = ssdt.guest_function_va as u64;

        HookManager::ept_unhook_function(vm, function_va as _, ept_hook_type)?;

        Ok(())
    }
}
