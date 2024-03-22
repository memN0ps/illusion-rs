#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::error::HypervisorError;
use bstr::ByteSlice;
use core::ffi::c_void;
use core::ptr::null_mut;
use wdk_sys::ntddk::{ExAllocatePool, ExFreePool};
use wdk_sys::_POOL_TYPE::NonPagedPool;
use wdk_sys::{NTSTATUS, NT_SUCCESS, PULONG, PVOID, ULONG};

pub struct Sysinfo {
    /// Pointer to the module information.
    pub module_info: *mut SystemModuleInformation,
}

impl Sysinfo {
    /// Creates a new instance of `SystemModuleInfo` and fetches module information.
    ///
    /// # Returns
    ///
    /// A result containing the module information if successful, or an error if not.
    pub fn new() -> Result<Sysinfo, HypervisorError> {
        let mut bytes = 0;

        // First call to ZwQuerySystemInformation to get buffer size
        let _status = unsafe {
            ZwQuerySystemInformation(
                SystemInformationClass::SystemModuleInformation,
                null_mut(),
                0,
                &mut bytes,
            )
        };

        // Error checking omitted as it's intentional to get the buffer size

        // Allocate memory for module information
        let module_info =
            unsafe { ExAllocatePool(NonPagedPool, bytes as _) as *mut SystemModuleInformation };

        if module_info.is_null() {
            unsafe { ExFreePool(module_info as _) };
            return Err(HypervisorError::ExAllocatePoolFailed);
        }

        // Zero out the memory
        unsafe { RtlZeroMemory(module_info as *mut c_void, bytes as usize) };

        // Second call to ZwQuerySystemInformation to fetch data
        let status = unsafe {
            ZwQuerySystemInformation(
                SystemInformationClass::SystemModuleInformation,
                module_info as *mut c_void,
                bytes,
                &mut bytes,
            )
        };

        if !NT_SUCCESS(status) {
            unsafe { ExFreePool(module_info as _) };
            return Err(HypervisorError::NtQuerySystemInformationFailed);
        }

        Ok(Self { module_info })
    }

    /// Gets the base address and size of a module by its name.
    ///
    /// # Arguments
    ///
    /// * `module_name` - The name of the module to get the base address of.
    ///
    /// # Returns
    ///
    /// A tuple with the base address and size of the module if found, or `None` if not found.
    pub fn get_module_base(&mut self, module_name: &str) -> Option<(*mut c_void, u32)> {
        let module_info = unsafe { &mut *self.module_info };

        for i in 0..module_info.modules_count as usize {
            let module = module_info.modules[i];
            let image_name = module.image_name;
            let image_base = module.image_base;

            log::info!(
                "[+] Module name: {:?} and module base: {:?}",
                image_name.as_bstr(),
                image_base
            );

            if let Some(_) = image_name.find(module_name) {
                return Some((module.image_base, module.size));
            }
        }

        None
    }
}

impl Drop for Sysinfo {
    fn drop(&mut self) {
        unsafe { ExFreePool(self.module_info as _) };
    }
}

#[link(name = "ntoskrnl")]
extern "system" {
    /// https://learn.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation
    /// Retrieves the specified system information.
    pub fn ZwQuerySystemInformation(
        SystemInformationClass: SystemInformationClass,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

    pub fn RtlZeroMemory(Destination: *mut c_void, Length: usize);
}

#[repr(C)]
pub enum SystemInformationClass {
    SystemModuleInformation = 11,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemModuleInformation {
    pub modules_count: u32,
    pub modules: [SystemModule; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemModule {
    pub section: *mut c_void,
    pub mapped_base: *mut c_void,
    pub image_base: *mut c_void,
    pub size: u32,
    pub flags: u32,
    pub index: u8,
    pub name_length: u8,
    pub load_count: u8,
    pub path_length: u8,
    pub image_name: [u8; 256],
}
