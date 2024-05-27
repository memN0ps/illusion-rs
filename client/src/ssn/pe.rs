use {
    core::{arch::asm, slice::from_raw_parts},
    ntapi::{
        ntldr::PLDR_DATA_TABLE_ENTRY,
        ntpebteb::{PPEB, PTEB},
        ntpsapi::PPEB_LDR_DATA,
        winapi::um::winnt::{
            IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS64,
        },
    },
    shared::djb2_hash,
    std::{collections::BTreeMap, ffi::CStr},
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

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    return Some(nt_headers);
}

/// Get a pointer to the Thread Environment Block (TEB)
pub unsafe fn get_teb() -> PTEB {
    let teb: PTEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> PPEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

/// Get loaded module by hash
pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as PPEB_LDR_DATA;
    let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as PLDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == djb2_hash(dll_name_slice) {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as PLDR_DATA_TABLE_ENTRY;
    }

    return None;
}

/// Get the address of an export by name
pub unsafe fn get_exports_by_name(module_base: *mut u8) -> Option<BTreeMap<String, usize>> {
    let mut exports = BTreeMap::new();
    let nt_headers = get_nt_headers(module_base)?;

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as PIMAGE_EXPORT_DIRECTORY;

    let names =
        from_raw_parts((module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);

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

        if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(name.to_string(), module_base as usize + functions[ordinal] as usize);
        }
    }

    return Some(exports);
}
