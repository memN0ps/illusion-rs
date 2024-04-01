#![cfg(feature = "test-windows-uefi-hooks")]
#![allow(dead_code)]

use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            bitmap::{MsrAccessType, MsrOperation},
            hooks::hook::HookType,
            hooks::inline::InlineHookType,
            paging::PageTables,
            vm::Vm,
        },
        windows::{
            nt::{
                functions::get_image_base_address,
                pe::{dbj2_hash, get_export_by_hash, get_size_of_image},
                types::{
                    FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, HANDLE,
                    IO_STATUS_BLOCK, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
                    NTSTATUS, OBJECT_ATTRIBUTES,
                },
            },
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    core::{
        ffi::c_void,
        mem, ptr,
        sync::atomic::{AtomicPtr, Ordering},
    },
    x86::msr,
};

pub fn test_windows_kernel_ept_hooks(vm: &mut Vm, msr_value: u64) -> Result<(), HypervisorError> {
    // Get the guest CR3 value.
    let guest_cr3 = PageTables::get_guest_cr3();

    // Get the base address of ntoskrnl.exe.
    let ntoskrnl_base_va = get_image_base_address(msr_value, guest_cr3)
        .ok_or(HypervisorError::FailedToGetImageBaseAddress)?;
    log::trace!("ntoskrnl.exe base address: {:#x}", ntoskrnl_base_va);

    let ntoskrnl_base_pa = PhysicalAddress::pa_from_va(ntoskrnl_base_va);
    log::trace!(
        "ntoskrnl.exe base physical address: {:#x}",
        ntoskrnl_base_pa
    );

    // Unhook the MSR_IA32_LSTAR register.
    unsafe {
        vm.shared_data.as_mut().msr_bitmap.modify_msr_interception(
            msr::IA32_LSTAR,
            MsrAccessType::Write,
            MsrOperation::Unhook,
        );
    }
    log::trace!("Unhooked MSR_IA32_LSTAR");

    // Get the address of the MmIsAddressValid function in ntoskrnl.exe.
    let mm_is_address_valid_va = unsafe {
        get_export_by_hash(
            ntoskrnl_base_pa as _,
            ntoskrnl_base_va as _,
            dbj2_hash("MmIsAddressValid".as_bytes()),
        )
        .unwrap()
    };
    log::trace!(
        "MmIsAddressValid address: {:#x}",
        mm_is_address_valid_va as u64
    );

    // Get the physical address of the MmIsAddressValid function.
    let mm_is_address_valid_pa = PhysicalAddress::pa_from_va(mm_is_address_valid_va as _);
    log::trace!(
        "MmIsAddressValid physical address: {:#x}",
        mm_is_address_valid_pa
    );

    // Create a hook for the MmIsAddressValid function.
    test_create_ept_hook(
        vm,
        mm_is_address_valid_va as u64,
        mm_is_address_valid_pa,
        test_mm_is_address_valid as *const (),
        InlineHookType::Jmp,
        &MM_IS_ADDRESS_VALID_ORIGINAL,
    )?;

    log::trace!("MmIsAddressValid hook installed");

    /* NtCreateFile Hook
    // Get the size of ntoskrnl.exe.
    let kernel_size = unsafe { get_size_of_image(ntoskrnl_base_pa as _).unwrap() };
    log::trace!("ntoskrnl.exe size: {:#x}", kernel_size);

    // Find the address of the NtCreateFile function in the SSDT.
    let ssdt_nt_create_file_addy = SsdtHook::find_ssdt_function_address(
        0x0055,
        false,
        ntoskrnl_base_pa as _,
        kernel_size as usize,
    )?;
    log::trace!(
        "NtCreateFile address: {:#x}",
        ssdt_nt_create_file_addy.function_address as u64
    );

    // Create a hook for the NtCreateFile function.
    let test_nt_create_file_hook = test_create_ept_hook(
        ssdt_nt_create_file_addy.function_address as u64,
        test_nt_create_file as *const (),
        InlineHookType::Jmp,
        &NT_CREATE_FILE_ORIGINAL,
    )?;
    log::trace!("NtCreateFile hook installed");

    // Create a hook manager with the hooks we want to install.
    let hook_manager = HookManager::new(vec![
        test_mm_is_address_valid_hook,
        test_nt_create_file_hook,
    ]);
    log::trace!("Hook manager created");
    */

    log::info!("Windows kernel hooks installed successfully");

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
    vm: &mut Vm,
    original_va: u64,
    original_pa: u64,
    hook_handler: *const (),
    hook_type: InlineHookType,
    original_function: &AtomicPtr<u64>,
) -> Result<(), HypervisorError> {
    log::trace!("Creating EPT hook for function at {:#x}", original_va);

    // keep track of the hook index
    let hook = unsafe { &mut vm.shared_data.as_mut().hook_manager }
        .get_mut(0)
        .unwrap();

    hook.hook_function_uefi(original_pa, hook_handler, hook_type)
        .ok_or(HypervisorError::HookError)?;

    if let HookType::Function { ref inline_hook } = hook.hook_type {
        original_function.store(inline_hook.trampoline_address(), Ordering::Relaxed);
    }

    Ok(())
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
