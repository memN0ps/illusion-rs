#![cfg(feature = "test-windows-uefi-hooks")]
#![allow(dead_code)]

use {
    crate::{
        error::HypervisorError,
        intel::{
            bitmap::{MsrAccessType, MsrOperation},
            hooks::hook::{Hook, HookType},
            hooks::inline::InlineHookType,
            hooks::manager::HookManager,
            paging::PageTables,
            vm::Vm,
        },
        windows::{
            nt::{
                functions::get_image_base_address,
                types::{
                    FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, HANDLE,
                    IO_STATUS_BLOCK, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
                    NTSTATUS, OBJECT_ATTRIBUTES,
                },
            },
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    alloc::vec,
    core::{
        ffi::c_void,
        mem, ptr,
        sync::atomic::{AtomicPtr, Ordering},
    },
    x86::msr,
};

pub fn test_windows_kernel_ept_hooks(vm: &mut Vm, msr_value: u64) -> Result<(), HypervisorError> {
    // Get the guest CR3 value to use for translating guest virtual addresses.
    let guest_cr3 = PageTables::get_guest_cr3();

    let ntoskrnl_base = get_image_base_address(msr_value, guest_cr3)
        .ok_or(HypervisorError::FailedToGetImageBaseAddress)?;
    log::trace!("ntoskrnl.exe base address: {:#x}", ntoskrnl_base);

    // Unhook (unmask) MSR now that we have the base address of ntoskrnl.exe.
    unsafe {
        vm.shared_data.as_mut().msr_bitmap.modify_msr_interception(
            msr::IA32_LSTAR,
            MsrAccessType::Write,
            MsrOperation::Unhook,
        );
    }

    // Parse ntoskrnl.exe to get function address and test hook here:

    let api_number = 0;
    let get_from_win32k = false;
    let kernel_base = ntoskrnl_base as *const u8;
    let kernel_size = 0;

    let ssdt_nt_create_file_addy = SsdtHook::find_ssdt_function_address(
        api_number,
        get_from_win32k,
        kernel_base,
        kernel_size,
    )?;

    let test_nt_create_file_hook = test_create_ept_hook(
        ssdt_nt_create_file_addy.function_address as u64,
        test_nt_create_file as *const (),
        InlineHookType::Jmp,
    )?;

    let hook_manager = HookManager::new(vec![test_nt_create_file_hook]);

    unsafe { vm.shared_data.as_mut().hook_manager = Some(hook_manager) };

    Ok(())
}

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
fn test_create_ept_hook(
    original_va: u64,
    hook_handler: *const (),
    hook_type: InlineHookType,
) -> Result<Hook, HypervisorError> {
    // Example 1: Normal EPT Hook MmIsAddressValid

    let hook = Hook::hook_function(original_va, hook_handler, hook_type)
        .ok_or(HypervisorError::HookError)?;

    if let HookType::Function { ref inline_hook } = hook.hook_type {
        MM_IS_ADDRESS_VALID_ORIGINAL.store(inline_hook.trampoline_address(), Ordering::Relaxed);
    }

    Ok(hook)
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
    log::debug!("First Parameter Value: {:x}", filehandle as u64);

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
