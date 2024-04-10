use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            hooks::hook::{EptHook, EptHookType},
            vm::Vm,
        },
        windows::{
            nt::pe::{dbj2_hash, get_export_by_hash, get_image_base_address, get_size_of_image},
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    log::*,
};

/// Represents a hook into the Windows kernel, allowing redirection of functions and syscalls.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelHook {
    /// The base virtual address of ntoskrnl.exe.
    ntoskrnl_base_va: u64,

    /// The size of ntoskrnl.exe.
    kernel_size: u64,
}

impl KernelHook {
    /// Creates a new instance of `KernelHook`.
    ///
    /// # Arguments
    ///
    /// * `guest_va` - The virtual address of the guest.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - The new instance of `KernelHook`.
    pub fn new(guest_va: u64) -> Result<Self, HypervisorError> {
        // Get the base address of ntoskrnl.exe.
        let ntoskrnl_base_va = unsafe {
            get_image_base_address(guest_va).ok_or(HypervisorError::FailedToGetImageBaseAddress)?
        };

        // Get the physical address of ntoskrnl.exe using GUEST_CR3 and the virtual address.
        let ntoskrnl_base_pa = PhysicalAddress::pa_from_va(ntoskrnl_base_va);

        // Get the size of ntoskrnl.exe.
        let kernel_size = unsafe {
            get_size_of_image(ntoskrnl_base_pa as _)
                .ok_or(HypervisorError::FailedToGetKernelSize)?
        } as u64;

        Ok(Self {
            ntoskrnl_base_va,
            kernel_size,
        })
    }

    /// Sets up a hook for a function in the Windows kernel.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to install the hook on.
    /// * `function_name` - The name of the function to hook.
    /// * `hook_handler` - The handler to call when the function is invoked.
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was installed successfully.
    pub fn setup_kernel_inline_hook(
        &mut self,
        vm: &mut Vm,
        function_name: &str,
        hook_handler: *const (),
        ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
        trace!("Setting up hook for function: {}", function_name);

        let function_va = unsafe {
            get_export_by_hash(
                PhysicalAddress::pa_from_va(self.ntoskrnl_base_va) as _,
                self.ntoskrnl_base_va as _,
                dbj2_hash(function_name.as_bytes()),
            )
            .ok_or(HypervisorError::FailedToGetExport)?
        };

        trace!("Function address: {:#x}", function_va as u64);

        EptHook::ept_hook(vm, function_va as u64, hook_handler, ept_hook_type)?;

        info!("Windows kernel inline hook installed successfully");

        Ok(())
    }

    /// Sets up a hook for a syscall in the Windows kernel SSDT.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to install the hook on.
    /// * `syscall_number` - The syscall number to hook.
    /// * `get_from_win32k` - Whether to get the function from the Win32k table instead of the NT table.
    /// * `hook_handler` - The handler to call when the syscall is invoked.
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was installed successfully.
    pub fn setup_kernel_ssdt_hook(
        &mut self,
        vm: &mut Vm,
        syscall_number: i32,
        get_from_win32k: bool,
        hook_handler: *const (),
        ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
        trace!("Setting up hook for syscall: {}", syscall_number);

        let ssdt_hook = SsdtHook::find_ssdt_function_address(
            syscall_number,
            get_from_win32k,
            PhysicalAddress::pa_from_va(self.ntoskrnl_base_va) as _,
            self.kernel_size as _,
        )?;

        trace!(
            "Function address: {:#x}",
            ssdt_hook.guest_function_va as u64
        );

        EptHook::ept_hook(
            vm,
            ssdt_hook.guest_function_va as u64,
            hook_handler,
            ept_hook_type,
        )?;

        info!("Windows kernel ssdt hook installed successfully");

        Ok(())
    }
}
