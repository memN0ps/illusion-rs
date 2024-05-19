use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            hooks::hook_manager::{EptHookType, HookManager},
            vm::Vm,
        },
        windows::nt::{
            pe::{djb2_hash, get_image_base_address, get_nt_headers, get_size_of_image},
            types::{IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_EXPORT_DIRECTORY},
        },
    },
    core::{ffi::CStr, slice::from_raw_parts},
    heapless::{LinearMap, String, Vec},
    log::*,
};

/// The maximum number of functions that can be exported by the kernel. Change this value as needed. Rounded up to 4000 for now but exports are not that many, currently around 3064.
const MAX_FUNCTION_EXPORTS: usize = 4000;

/// The maximum length of a function name. Change this value as needed. Rounded up to 64 for now but function names are not that long, currently around 53.
const MAX_FUNCTION_NAME_LENGTH: usize = 64;

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

    /// The ntoskrnl function name to export address mapping.
    ntoskrnl_export_map: LinearMap<String<MAX_FUNCTION_NAME_LENGTH>, u64, MAX_FUNCTION_EXPORTS>,

    /// The ntoskrnl Nt sorted function name to export address mapping for ntoskrnl.exe.
    ntoskrnl_sorted_map: Vec<(String<MAX_FUNCTION_NAME_LENGTH>, u64), MAX_NT_SYSCALL_ENTRIES>,

    /// The win32k function name to export address mapping.
    win32k_export_map: LinearMap<String<MAX_FUNCTION_NAME_LENGTH>, u64, MAX_FUNCTION_EXPORTS>,

    /// The win32k Nt sorted function name to export address mapping for win32k.sys.
    win32k_sorted_map: Vec<(String<MAX_FUNCTION_NAME_LENGTH>, u64), MAX_WIN32K_SYSCALL_ENTRIES>,

    /// Pre-allocated string for populating exports.
    temp_string_buffer: String<MAX_FUNCTION_NAME_LENGTH>,
}

impl KernelHook {
    /// Creates a new instance of `KernelHook`.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - The new instance of `KernelHook`.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing kernel hook");

        let ntoskrnl_export_map = LinearMap::<String<MAX_FUNCTION_NAME_LENGTH>, u64, MAX_FUNCTION_EXPORTS>::new();
        let ntoskrnl_sorted_map = Vec::<(String<MAX_FUNCTION_NAME_LENGTH>, u64), MAX_NT_SYSCALL_ENTRIES>::new();
        let win32k_export_map = LinearMap::<String<MAX_FUNCTION_NAME_LENGTH>, u64, MAX_FUNCTION_EXPORTS>::new();
        let win32k_sorted_map = Vec::<(String<MAX_FUNCTION_NAME_LENGTH>, u64), MAX_WIN32K_SYSCALL_ENTRIES>::new();
        let temp_string_buffer = String::<MAX_FUNCTION_NAME_LENGTH>::new();

        trace!("Kernel hook initialized");

        Ok(Self {
            ntoskrnl_base_va: 0,
            ntoskrnl_base_pa: 0,
            ntoskrnl_size: 0,
            win32k_base_va: 0,
            win32k_base_pa: 0,
            win32k_size: 0,
            ntoskrnl_export_map,
            ntoskrnl_sorted_map,
            win32k_export_map,
            win32k_sorted_map,
            temp_string_buffer,
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
        export_map: &mut LinearMap<String<MAX_FUNCTION_NAME_LENGTH>, u64, MAX_FUNCTION_EXPORTS>,
        pre_allocated_name: &mut String<MAX_FUNCTION_NAME_LENGTH>,
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

        debug!("NumberOfNames: {}", (*export_directory).NumberOfNames);

        for i in 0..(*export_directory).NumberOfNames {
            let name_addr = (module_base_pa as usize + names[i as usize] as usize) as *const i8;

            if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
                pre_allocated_name.clear();
                if pre_allocated_name.push_str(name).is_err() {
                    error!("Failed to convert name to heapless::String: {}", name);
                    return None;
                }

                let ordinal = ordinals[i as usize] as usize;
                let function_va = module_base_va as u64 + functions[ordinal] as u64;

                if export_map.insert(pre_allocated_name.clone(), function_va).is_err() {
                    error!("Failed to insert export: {}", name);
                    return None;
                }
            }
        }

        Some(())
    }

    /// Replaces all function names starting with "Zw" with "Nt" in the export map,
    /// and sorts the keys by their corresponding values in ascending order.
    fn replace_zw_with_nt_and_sort<const N: usize>(
        export_map: &LinearMap<String<MAX_FUNCTION_NAME_LENGTH>, u64, MAX_FUNCTION_EXPORTS>,
        sorted_map: &mut Vec<(String<MAX_FUNCTION_NAME_LENGTH>, u64), N>,
        temp_string_buffer: &mut String<MAX_FUNCTION_NAME_LENGTH>,
    ) {
        trace!("Replacing Zw with Nt and sorting exports");
        sorted_map.clear();

        // Find and replace "Zw" with "Nt" in the keys
        for (name, &addr) in export_map.iter() {
            trace!("Checking name: {}", name);
            if name.starts_with("Zw") {
                trace!("Replacing Zw with Nt: {}", name);
                temp_string_buffer.clear();
                temp_string_buffer.push_str("Nt").unwrap();
                temp_string_buffer.push_str(&name[2..]).unwrap();

                trace!("Pushing to sorted map: {} - {:#x}", temp_string_buffer, addr);
                sorted_map.push((temp_string_buffer.clone(), addr)).unwrap();
            }
        }

        // Perform insertion sort on the buffer
        trace!("Sorting exports");
        let len = sorted_map.len();
        for i in 1..len {
            let mut j = i;
            while j > 0 && sorted_map[j - 1].1 > sorted_map[j].1 {
                sorted_map.swap(j - 1, j);
                j -= 1;
            }
        }
    }

    /// Populates the export map for ntoskrnl.exe.
    ///
    /// # Returns
    ///
    /// * `Some(())` - The exports were populated successfully.
    /// * `None` - If populating the exports fails.
    pub fn populate_ntoskrnl_exports(&mut self) -> Option<()> {
        if unsafe {
            Self::populate_exports(
                self.ntoskrnl_base_pa as _,
                self.ntoskrnl_base_va as _,
                &mut self.ntoskrnl_export_map,
                &mut self.temp_string_buffer,
            )
        }
        .is_some()
        {
            let export_map = &self.ntoskrnl_export_map;
            let sorted_map = &mut self.ntoskrnl_sorted_map;
            let temp_string_buffer = &mut self.temp_string_buffer;
            Self::replace_zw_with_nt_and_sort(export_map, sorted_map, temp_string_buffer);
            Some(())
        } else {
            None
        }
    }

    /// Populates the export map for win32k.sys.
    ///
    /// # Returns
    ///
    /// * `Some(())` - The exports were populated successfully.
    /// * `None` - If populating the exports fails.
    pub fn populate_win32k_exports(&mut self) -> Option<()> {
        if unsafe {
            Self::populate_exports(self.win32k_base_pa as _, self.win32k_base_va as _, &mut self.win32k_export_map, &mut self.temp_string_buffer)
        }
        .is_some()
        {
            let export_map = &self.win32k_export_map;
            let sorted_map = &mut self.win32k_sorted_map;
            let temp_string_buffer = &mut self.temp_string_buffer;
            Self::replace_zw_with_nt_and_sort(export_map, sorted_map, temp_string_buffer);
            Some(())
        } else {
            None
        }
    }

    /// Retrieves the syscall number by hashing the function name and comparing it to the sorted exports.
    ///
    /// # Arguments
    ///
    /// * `function_hash` - The hash of the function name.
    ///
    /// # Returns
    ///
    /// * `Option<u16>` - The syscall number if found, otherwise `None`.
    fn get_ssn_by_hash<const N: usize>(&self, function_hash: u32, sorted_map: &Vec<(String<MAX_FUNCTION_NAME_LENGTH>, u64), N>) -> Option<u16> {
        let mut syscall_number: u16 = 0;

        for (name, _) in sorted_map {
            if function_hash == djb2_hash(name.as_bytes()) {
                return Some(syscall_number);
            }
            syscall_number += 1;
        }

        None
    }

    /// Gets the function virtual address (VA) from the export maps.
    ///
    /// # Arguments
    ///
    /// * `function_hash` - The hash of the function name.
    ///
    /// # Returns
    ///
    /// * `Some(u64)` - The virtual address of the function if found.
    /// * `None` - If the function is not found.
    fn get_function_va(&self, function_hash: u32) -> Option<u64> {
        for (name, &va) in self.ntoskrnl_export_map.iter().chain(self.win32k_export_map.iter()) {
            if djb2_hash(name.as_bytes()) == function_hash {
                return Some(va);
            }
        }
        None
    }

    /// Sets up a hook for a function in the Windows kernel or SSDT.
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
    pub fn kernel_ept_hook(&mut self, vm: &mut Vm, function_hash: u32, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        trace!("Setting up EPT hook for function: {}", function_hash);

        if let Some(function_va) = self.get_function_va(function_hash) {
            let function_pa = PhysicalAddress::pa_from_va(function_va);
            trace!("Function VA: {:#x} PA: {:#x}", function_va, function_pa);

            // Check and log syscall number for ntoskrnl
            if let Some(ssn) = self.get_ssn_by_hash(function_hash, &self.ntoskrnl_sorted_map) {
                trace!("ntoskrnl syscall number: {}", ssn);
            }
            // Check and log syscall number for win32k
            else if let Some(ssn) = self.get_ssn_by_hash(function_hash, &self.win32k_sorted_map) {
                trace!("win32k syscall number: {}", ssn);
            }

            HookManager::ept_hook_function(vm, function_va, ept_hook_type)?;

            info!("Windows kernel EPT hook installed successfully");
            Ok(())
        } else {
            error!("Failed to find function for hash: {}", function_hash);
            Err(HypervisorError::FailedToGetExport)
        }
    }
}
