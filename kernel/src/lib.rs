#![no_std]
#![no_main]
#![allow(dead_code)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

extern crate alloc;

pub mod windows;

use {
    crate::windows::{
        hooks::{
            ept::{
                hook::{Hook, HookType},
                inline::InlineHookType,
                manager::HookManager,
            },
            ssdt::ssdt_hook::SsdtHook,
        },
        nt::types::{
            FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, HANDLE,
            IO_STATUS_BLOCK, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
            NTSTATUS, OBJECT_ATTRIBUTES,
        },
    },
    alloc::boxed::Box,
    alloc::vec,
    core::{
        ffi::c_void,
        mem, ptr,
        sync::atomic::{AtomicPtr, Ordering},
    },
    hypervisor::{error::HypervisorError, intel::ept::Ept},
};

/// A test function to demonstrate how to install an inline EPT hook on a Windows kernel function.
///
/// # Arguments
///
/// * original_va - The virtual address of the function to be hooked.
/// * hook_handler - The handler function to be called when the hooked function is executed.
/// * hook_type - The type of hook to be installed.
///
/// # Returns
///
/// Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
fn test_windows_kernel_inline_ept_hook(
    original_va: u64,
    hook_handler: *const (),
    hook_type: InlineHookType,
) -> Result<(), HypervisorError> {
    // Example 1: Normal EPT Hook MmIsAddressValid

    let mm_is_address_valid = Hook::hook_function(original_va, hook_handler, hook_type)
        .ok_or(HypervisorError::HookError)?;

    if let HookType::Function { ref inline_hook } = mm_is_address_valid.hook_type {
        MM_IS_ADDRESS_VALID_ORIGINAL.store(inline_hook.trampoline_address(), Ordering::Relaxed);
    }

    // Create a new hook manager and add the `mm_is_address_valid` hook to it.
    // Must be stored in a global variable to prevent it from being dropped. maybe in `SharedData` from vmexit handler or after returning from there.
    let hook_manager = HookManager::new(vec![mm_is_address_valid]);

    Ok(())
}

/// A test function to demonstrate how to install an syscall inline EPT hook on a Windows kernel function.
///
/// # Arguments
///
/// * `api_number` - The API number of the function to hook.
/// * `get_from_win32k` - Whether to get the function from the Win32k table instead of the NT table.
/// * `kernel_base` - The base address of the kernel in memory.
/// * `kernel_size` - The size of the kernel memory space.
///
/// # Returns
///
/// Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
fn test_windows_kernel_syscall_inline_ept_hook(
    api_number: i32,
    get_from_win32k: bool,
    kernel_base: *const u8,
    kernel_size: usize,
) -> Result<(), HypervisorError> {
    // Example 2: Syscall EPT Hook NtCreateFile via SSDT Function Entry

    let ssdt_nt_create_file_addy = SsdtHook::find_ssdt_function_address(
        api_number,
        get_from_win32k,
        kernel_base,
        kernel_size,
    )?;

    let nt_create_file_syscall_hook = Hook::hook_function_ptr(
        ssdt_nt_create_file_addy.function_address as _,
        test_nt_create_file as *const (),
    )
    .ok_or(HypervisorError::HookError)?;

    if let HookType::Function { ref inline_hook } = nt_create_file_syscall_hook.hook_type {
        NT_CREATE_FILE_ORIGINAL.store(inline_hook.trampoline_address(), Ordering::Relaxed);
    }

    // Create a new hook manager and add the `nt_create_file_syscall_hook` hook to it.
    // Must be stored in a global variable to prevent it from being dropped. maybe in `SharedData` from vmexit handler or after returning from there.
    let hook_manager = HookManager::new(vec![nt_create_file_syscall_hook]);
}

/// A global atomic pointer to hold the original `mm_is_address_valid` function.
/// It's initialized to a null mutable pointer and will be set during runtime to the actual function.
pub static MM_IS_ADDRESS_VALID_ORIGINAL: AtomicPtr<u64> = AtomicPtr::new(ptr::null_mut());

/// The type of the `MmIsAddressValid` function.
type MmIsAddressValidType = extern "C" fn(virtualaddress: *const c_void) -> bool;

/// A safe wrapper around the `MmIsAddressValid` function.
///
/// # Arguments
///
/// * `ptr`: The pointer to check for validity.
///
/// # Returns
/// * Returns `true` if the address is valid, `false` otherwise.
///
/// # Safety
/// This function assumes that the original `MmIsAddressValid` function is correctly set and points to a valid function.
/// The caller must ensure this is the case to avoid undefined behavior.
pub extern "C" fn test_mm_is_address_valid(virtual_address: u64) -> bool {
    // Log the address from which `MmIsAddressValid` was called.
    log::debug!("MmIsAddressValid called from hook handler");
    log::debug!("First Parameter Value: {:x}", virtual_address);

    // Load the original function pointer from the global atomic pointer.
    let fn_ptr = MM_IS_ADDRESS_VALID_ORIGINAL.load(Ordering::Relaxed); // Using relaxed ordering for atomic loading.

    // Transmute the function pointer to the expected function type.
    let fn_ptr = unsafe { mem::transmute::<_, MmIsAddressValidType>(fn_ptr) };

    // Call the original `MmIsAddressValid` function with the provided pointer.
    fn_ptr(virtual_address as _)
}

/// A global atomic pointer to hold the original `nt_create_file` function.
/// It's initialized to a null mutable pointer and will be set during runtime to the actual function.
pub static NT_CREATE_FILE_ORIGINAL: AtomicPtr<u64> = AtomicPtr::new(ptr::null_mut());

type NtCreateFileType = extern "system" fn(
    filehandle: *mut HANDLE,
    desiredaccess: FILE_ACCESS_RIGHTS,
    objectattributes: *const OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    allocationsize: *const i64,
    fileattributes: FILE_FLAGS_AND_ATTRIBUTES,
    shareaccess: FILE_SHARE_MODE,
    createdisposition: NTCREATEFILE_CREATE_DISPOSITION,
    createoptions: NTCREATEFILE_CREATE_OPTIONS,
    eabuffer: *const c_void,
    ealength: u32,
) -> NTSTATUS;

/// A safe wrapper around the `NtCreateFile` function.
///
/// # Arguments
///
/// * `filehandle`: The handle to the file object.
/// * `desiredaccess`: The desired access rights for the file.
/// * `objectattributes`: The attributes of the file object.
/// * `iostatusblock`: The I/O status block for the file operation.
/// * `allocationsize`: The size to allocate for the file.
/// * `fileattributes`: The attributes of the file.
/// * `shareaccess`: The sharing mode for the file.
/// * `createdisposition`: The disposition of the file creation.
/// * `createoptions`: The options for creating the file.
/// * `eabuffer`: The extended attributes buffer.
/// * `ealength`: The length of the extended attributes buffer.
///
/// # Returns
///
/// Returns the status of the file creation operation.
pub extern "C" fn test_nt_create_file(
    filehandle: *mut HANDLE,
    desiredaccess: FILE_ACCESS_RIGHTS,
    objectattributes: *const OBJECT_ATTRIBUTES,
    iostatusblock: *mut IO_STATUS_BLOCK,
    allocationsize: *const i64,
    fileattributes: FILE_FLAGS_AND_ATTRIBUTES,
    shareaccess: FILE_SHARE_MODE,
    createdisposition: NTCREATEFILE_CREATE_DISPOSITION,
    createoptions: NTCREATEFILE_CREATE_OPTIONS,
    eabuffer: *const c_void,
    ealength: u32,
) -> NTSTATUS {
    log::debug!("NtCreateFile called from hook handler");
    log::debug!("First Parameter Value: {:x}", filehandle);

    // Load the original function pointer from the global atomic pointer.
    let fn_ptr = NT_CREATE_FILE_ORIGINAL.load(Ordering::Relaxed); // Using relaxed ordering for atomic loading.

    // Transmute the function pointer to the expected function type.
    let fn_ptr = unsafe { mem::transmute::<_, NtCreateFileType>(fn_ptr) };

    // Call the original `NtCreateFile` function with the provided pointer.
    fn_ptr(
        filehandle,
        desiredaccess,
        objectattributes,
        iostatusblock,
        allocationsize,
        fileattributes,
        shareaccess,
        createdisposition,
        createoptions,
        eabuffer,
        ealength,
    )
}
