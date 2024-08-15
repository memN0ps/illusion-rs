//! Provides utilities for accessing and manipulating PE (Portable Executable) format images.
//! Supports operations like finding DOS and NT headers, exports by hash, and image size.

use {
    crate::{
        error::HypervisorError,
        intel::addresses::PhysicalAddress,
        windows::nt::types::{
            IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS64,
        },
    },
    core::slice::from_raw_parts,
};

/// Get a pointer to IMAGE_DOS_HEADER
///
/// # Arguments
///
/// * `module_base` - The base address of the module.
///
/// # Returns
///
/// * `Option<PIMAGE_DOS_HEADER>` - The pointer to the IMAGE_DOS_HEADER.
pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<PIMAGE_DOS_HEADER> {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    return Some(dos_header);
}

/// Get a pointer to IMAGE_NT_HEADERS64 x86_64
///
/// # Arguments
///
/// * `module_base` - The base address of the module.
///
/// # Returns
///
/// * `Option<PIMAGE_NT_HEADERS64>` - The pointer to the IMAGE_NT_HEADERS64.
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<PIMAGE_NT_HEADERS64> {
    let dos_header = get_dos_header(module_base)?;

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Get the address of an export by hash
///
/// # Arguments
///
/// * `module_base` - The base address of the module.
/// * `export_hash` - The hash of the export.
///
/// # Returns
///
/// * `Option<*mut u8>` - The address of the export.
pub unsafe fn get_export_by_hash(module_base_pa: *mut u8, module_base_va: u64, export_hash: u32) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base_pa)?;
    let export_directory = (module_base_pa as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as PIMAGE_EXPORT_DIRECTORY;

    let names =
        from_raw_parts((module_base_pa as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = from_raw_parts(
        (module_base_pa as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = from_raw_parts(
        (module_base_pa as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base_pa as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_hash == djb2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return Some((module_base_va as usize + functions[ordinal] as usize) as *mut u8);
        }
    }

    return None;
}

/// Get the size of an image
///
/// # Arguments
///
/// * `module_base` - The base address of the module.
///
/// # Returns
///
/// * `Option<u32>` - The size of the image.
pub unsafe fn get_size_of_image(module_base: *mut u8) -> Option<u32> {
    let nt_headers = get_nt_headers(module_base as _)?;
    Some((*nt_headers).OptionalHeader.SizeOfImage)
}

/// Get the length of a C String
///
/// # Arguments
///
/// * `pointer` - The pointer to the C String.
///
/// # Returns
///
/// * `usize` - The length of the C String.
pub unsafe fn get_cstr_len(pointer: *const u8) -> usize {
    let mut tmp: u64 = pointer as u64;

    while *(tmp as *const u8) != 0 {
        tmp += 1;
    }

    (tmp - pointer as u64) as _
}

/// Generate a unique hash
///
/// # Arguments
///
/// * `buffer` - The buffer to hash.
///
/// # Returns
///
/// * `u32` - The hash of the buffer.
pub fn djb2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i: usize = 0;
    let mut char: u8;

    while i < buffer.len() {
        char = buffer[i];

        if char == 0 {
            i += 1;
            continue;
        }

        if char >= ('a' as u8) {
            char -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)) + char as u32;
        i += 1;
    }

    return hash;
}

/// Finds the base virtual address of an image by scanning memory for the 'MZ' signature, starting
/// from a specified address and scanning backwards. This function is typically used to locate
/// the base address of system modules like ntoskrnl.exe in a Windows.
///
/// # Arguments
///
/// * `start_address` - The guest virtual address from where the backward scanning begins.
///
/// # Returns
///
/// * `Option<u64>` - The base virtual address of the image if found, otherwise `None`.
///
/// # Credits
///
/// To Jessie (jessiep_) and Satoshi: https://gist.github.com/tandasat/bf0189952f113518f75c4f008c1e8d04#file-guestagent-c-L134-L161
pub unsafe fn get_image_base_address(start_va: u64) -> Result<u64, HypervisorError> {
    // Align the start address down to the nearest page boundary.
    let mut guest_va = start_va & !0xFFF;

    loop {
        // Attempt to read the potential DOS signature at the current address.
        match *(PhysicalAddress::pa_from_va_with_current_cr3(guest_va)? as *const u16) {
            IMAGE_DOS_SIGNATURE => return Ok(guest_va), // Found the 'MZ' signature.
            _ => {
                if guest_va == 0 {
                    break; // Prevent underflow and ensure the loop eventually terminates.
                }
                guest_va -= 0x1000; // Move to the previous page.
            }
        }
    }

    Err(HypervisorError::FailedToGetImageBaseAddress) // The 'MZ' signature was not found in the scanned range.
}
