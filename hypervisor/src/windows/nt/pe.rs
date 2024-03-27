use {
    crate::windows::nt::types::{
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PIMAGE_DOS_HEADER,
        PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS64,
    },
    core::slice::from_raw_parts,
};

/// Get a pointer to IMAGE_DOS_HEADER
pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<PIMAGE_DOS_HEADER> {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    return Some(dos_header);
}

/// Get a pointer to IMAGE_NT_HEADERS64 x86_64
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<PIMAGE_NT_HEADERS64> {
    let dos_header = get_dos_header(module_base)?;

    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Get the address of an export by hash
pub unsafe fn get_export_by_hash(module_base: *mut u8, export_hash: u32) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as PIMAGE_EXPORT_DIRECTORY;

    let names = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    let functions = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_hash == dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return Some((module_base as usize + functions[ordinal] as usize) as *mut u8);
        }
    }

    return None;
}

/// Get the size of an image
pub unsafe fn get_size_of_image(module_base: *mut u8) -> Option<u32> {
    let nt_headers = get_nt_headers(module_base as _)?;
    Some((*nt_headers).OptionalHeader.SizeOfImage)
}

/// Get the length of a C String
pub unsafe fn get_cstr_len(pointer: *const u8) -> usize {
    let mut tmp: u64 = pointer as u64;

    while *(tmp as *const u8) != 0 {
        tmp += 1;
    }

    (tmp - pointer as u64) as _
}

/// Generate a unique hash
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
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
