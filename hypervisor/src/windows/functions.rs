use {
    crate::windows::nt::types::{
        FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, HANDLE, IO_STATUS_BLOCK,
        NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NTSTATUS, OBJECT_ATTRIBUTES,
    },
    core::{
        ffi::c_void,
        mem, ptr,
        sync::atomic::{AtomicPtr, Ordering},
    },
};
/// A global atomic pointer to hold the original `mm_is_address_valid` function.
/// It's initialized to a null mutable pointer and will be set during runtime to the actual function.
pub static MM_IS_ADDRESS_VALID_ORIGINAL: AtomicPtr<u64> = AtomicPtr::new(ptr::null_mut());

/// The type of the `MmIsAddressValid` function.
pub type MmIsAddressValidType = extern "C" fn(virtualaddress: *const c_void) -> bool;

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

pub type NtCreateFileType = extern "system" fn(
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
