use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            hooks::hook_manager::{EptHookType, HookManager},
            vm::Vm,
        },
        windows::{
            nt::{
                pe::{djb2_hash, get_export_by_hash, get_image_base_address, get_nt_headers, get_size_of_image},
                types::{IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_EXPORT_DIRECTORY},
            },
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    core::{ffi::CStr, slice::from_raw_parts},
    heapless::LinearMap,
    log::*,
};

/// The maximum number of functions that can be exported by the kernel. Change this value as needed. Rounded up to 4000 for now but exports are not that many, currently around 3064.
const MAX_FUNCTION_EXPORTS: usize = 4000;

/// The maximum number of NT syscall entries. Change this value as needed. Rounded up to 600 for now but syscalls are not that many, currently around 506.
/// https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/nt.csv
const MAX_NT_SYSCALL_ENTRIES: usize = 600;

/// The maximum number of syscall entries. Change this value as needed. Rounded up to 2000 for now but syscalls are not that many, currently around 1713.
/// https://github.com/j00ru/windows-syscalls/blob/master/x64/csv/win32k.csv
const MAX_WIN32K_SYSCALL_ENTRIES: usize = 2000;

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

    /// The nt function hash to export address mapping for ntoskrnl.exe.
    nt_export_map: LinearMap<u32, u64, MAX_FUNCTION_EXPORTS>,

    /// The win32k function hash to export address mapping for win32k.sys.
    win32k_export_map: LinearMap<u32, u64, MAX_FUNCTION_EXPORTS>,

    /// The nt syscall number to function address mapping for ntoskrnl.exe.
    nt_syscall_map: LinearMap<u64, u16, MAX_NT_SYSCALL_ENTRIES>,

    /// The win32k syscall number to function address mapping for win32k.sys.
    win32k_syscall_map: LinearMap<u64, u16, MAX_WIN32K_SYSCALL_ENTRIES>,
}

impl KernelHook {
    /// Creates a new instance of `KernelHook`.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - The new instance of `KernelHook`.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing kernel hook");

        let nt_export_map = LinearMap::<u32, u64, MAX_FUNCTION_EXPORTS>::new();
        let win32k_export_map = LinearMap::<u32, u64, MAX_FUNCTION_EXPORTS>::new();
        let nt_syscall_map = LinearMap::<u64, u16, MAX_NT_SYSCALL_ENTRIES>::new();
        let win32k_syscall_map = LinearMap::<u64, u16, MAX_WIN32K_SYSCALL_ENTRIES>::new();

        trace!("Kernel hook initialized");

        Ok(Self {
            ntoskrnl_base_va: 0,
            ntoskrnl_base_pa: 0,
            ntoskrnl_size: 0,
            win32k_base_va: 0,
            win32k_base_pa: 0,
            win32k_size: 0,
            nt_export_map,
            win32k_export_map,
            nt_syscall_map,
            win32k_syscall_map,
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
    #[allow(dead_code)]
    pub fn set_win32k_base_and_size(&mut self, guest_va: u64) -> Result<(), HypervisorError> {
        // Get the base address of win32k.sys.
        self.win32k_base_va = unsafe { get_image_base_address(guest_va).ok_or(HypervisorError::FailedToGetImageBaseAddress)? };

        // Get the physical address of win32k.sys using GUEST_CR3 and the virtual address.
        self.win32k_base_pa = PhysicalAddress::pa_from_va(self.win32k_base_va);

        // Get the size of win32k.sys.
        self.win32k_size = unsafe { get_size_of_image(self.win32k_base_pa as _).ok_or(HypervisorError::FailedToGetKernelSize)? } as u64;

        Ok(())
    }

    /// Populates the export map with the exports of the specified module.
    ///
    /// # Arguments
    ///
    /// * `module_base_pa` - The base physical address of the module.
    /// * `module_base_va` - The base virtual address of the module.
    /// * `export_map` - The export map to populate.
    ///
    /// # Returns
    ///
    /// * `Some(())` - The exports were populated successfully.
    /// * `None` - If populating the exports fails.
    unsafe fn populate_exports(
        module_base_pa: *mut u8,
        module_base_va: *mut u8,
        export_map: &mut LinearMap<u32, u64, MAX_FUNCTION_EXPORTS>,
    ) -> Option<()> {
        let nt_headers = get_nt_headers(module_base_pa as _)?;

        let export_directory = (module_base_pa as usize
            + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
            as PIMAGE_EXPORT_DIRECTORY;

        let names = from_raw_parts(
            (module_base_pa as usize + (*export_directory).AddressOfNames as usize) as *const u32,
            (*export_directory).NumberOfNames as _,
        );

        let functions = from_raw_parts(
            (module_base_pa as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
            (*export_directory).NumberOfFunctions as _,
        );

        let ordinals = from_raw_parts(
            (module_base_pa as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
            (*export_directory).NumberOfNames as _,
        );

        debug!("(*export_directory).NumberOfNames: {:#x}", (*export_directory).NumberOfNames);

        for i in 0..(*export_directory).NumberOfNames {
            let name_addr = (module_base_pa as usize + names[i as usize] as usize) as *const i8;

            if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
                let ordinal = ordinals[i as usize] as usize;
                let function_hash = djb2_hash(name.as_bytes());
                if export_map
                    .insert(function_hash, module_base_va as u64 + functions[ordinal] as u64)
                    .is_err()
                {
                    error!("Failed to insert export: {}", name);
                    return None;
                }
            }
        }

        Some(())
    }

    /// Populates the export map for ntoskrnl.exe.
    ///
    /// # Returns
    ///
    /// * `Some(())` - The exports were populated successfully.
    /// * `None` - If populating the exports fails.
    pub fn populate_ntoskrnl_exports(&mut self) -> Option<()> {
        unsafe { Self::populate_exports(self.ntoskrnl_base_pa as _, self.ntoskrnl_base_va as _, &mut self.nt_export_map) }
    }

    /// Populates the export map for win32k.sys.
    ///
    /// # Returns
    ///
    /// * `Some(())` - The exports were populated successfully.
    /// * `None` - If populating the exports fails.
    pub fn populate_win32k_exports(&mut self) -> Option<()> {
        unsafe { Self::populate_exports(self.win32k_base_pa as _, self.win32k_base_va as _, &mut self.win32k_export_map) }
    }

    /// Sets up a hook for a function in the Windows kernel.
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
    pub fn setup_kernel_inline_hook(&mut self, vm: &mut Vm, function_hash: u32, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        trace!("Setting up hook for function: {}", function_hash);

        let function_va = unsafe {
            get_export_by_hash(self.ntoskrnl_base_pa as _, self.ntoskrnl_base_va as _, function_hash).ok_or(HypervisorError::FailedToGetExport)?
        };

        trace!("Function address: {:#x}", function_va as u64);

        HookManager::ept_hook_function(vm, function_va as u64, ept_hook_type)?;

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
    /// * `ept_hook_type` - The type of EPT hook to use.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was installed successfully.
    /// * `Err(HypervisorError)` - If the hook installation fails.
    pub fn setup_kernel_ssdt_hook(
        &mut self,
        vm: &mut Vm,
        syscall_number: i32,
        get_from_win32k: bool,
        ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
        trace!("Setting up hook for syscall: {}", syscall_number);

        let ssdt_hook = SsdtHook::find_ssdt_function_address(
            syscall_number,
            get_from_win32k,
            PhysicalAddress::pa_from_va(self.ntoskrnl_base_va) as _,
            self.ntoskrnl_size as _,
        )?;

        trace!("Function address: {:#x}", ssdt_hook.guest_function_va as u64);

        HookManager::ept_hook_function(vm, ssdt_hook.guest_function_va as u64, ept_hook_type)?;

        trace!("Windows Kernel SSDT hook installed successfully");

        Ok(())
    }
}
