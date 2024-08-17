#![allow(dead_code)]

use {
    alloc::vec::Vec,
    std::{collections::BTreeMap, ffi::CStr},
    windows_sys::Win32::System::SystemServices::{IMAGE_IMPORT_BY_NAME, IMAGE_ORDINAL_FLAG64},
};

extern crate alloc;

use {
    core::{arch::asm, mem::size_of, slice::from_raw_parts},
    windows_sys::Win32::System::{
        Diagnostics::Debug::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
            IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
        },
        Threading::{PEB, TEB},
        WindowsProgramming::{IMAGE_THUNK_DATA64, LDR_DATA_TABLE_ENTRY},
    },
};

/// Get a pointer to IMAGE_DOS_HEADER
pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<*mut IMAGE_DOS_HEADER> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    Some(dos_header)
}

/// Get a pointer to IMAGE_NT_HEADERS64 x86_64
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header = get_dos_header(module_base)?;

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }

    Some(nt_headers)
}

/// Get a pointer to the Thread Environment Block (TEB)
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

/// Get loaded module by hash
pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr;
    let mut module_list = (*peb_ldr_data_ptr).InMemoryOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).FullDllName.Buffer;
        let dll_length = (*module_list).FullDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == djb2_hash(dll_name_slice) {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InMemoryOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    None
}

/// Get section header by hash
pub unsafe fn get_section_header_by_hash(module_base: *mut u8, section_hash: u32) -> Option<*mut IMAGE_SECTION_HEADER> {
    let nt_headers = get_nt_headers(module_base)?;
    let section_header =
        (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections as usize {
        let section_name = (*section_header.add(i)).Name;

        if section_hash == djb2_hash(&section_name) {
            return Some(section_header);
        }
    }

    None
}

/// Get the address of an export by hash
pub unsafe fn get_export_by_hash(module_base: *mut u8, export_hash: u32) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

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
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_hash == djb2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return Some((module_base as usize + functions[ordinal] as usize) as *mut u8);
        }
    }

    None
}

/// Get the address of an export by name
pub unsafe fn get_exports_by_name(module_base: *mut u8) -> Option<BTreeMap<String, usize>> {
    let mut exports = BTreeMap::new();
    let nt_headers = get_nt_headers(module_base)?;

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

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

    Some(exports)
}

/// Process image relocations (rebase image)
pub unsafe fn rebase_image(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;

    // Calculate the difference between remote allocated memory region where the image will be loaded and preferred ImageBase (delta)
    let delta = module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

    // Return early if delta is 0
    if delta == 0 {
        return Some(true);
    }

    // Resolve the imports of the newly allocated memory region

    // Get a pointer to the first _IMAGE_BASE_RELOCATION
    let mut base_relocation = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize)
        as *mut IMAGE_BASE_RELOCATION;

    if base_relocation.is_null() {
        return Some(false);
    }

    // Get the end of _IMAGE_BASE_RELOCATION
    let base_relocation_end =
        base_relocation as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;

    while (*base_relocation).VirtualAddress != 0u32
        && (*base_relocation).VirtualAddress as usize <= base_relocation_end
        && (*base_relocation).SizeOfBlock != 0u32
    {
        // Get the VirtualAddress, SizeOfBlock and entries count of the current _IMAGE_BASE_RELOCATION block
        let address = (module_base as usize + (*base_relocation).VirtualAddress as usize) as isize;
        let item = (base_relocation as usize + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
        let count = ((*base_relocation).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();

        for i in 0..count {
            // Get the Type and Offset from the Block Size field of the _IMAGE_BASE_RELOCATION block
            let type_field = (item.offset(i as isize).read() >> 12) as u32;
            let offset = item.offset(i as isize).read() & 0xFFF;

            //IMAGE_REL_BASED_DIR32 does not exist
            //#define IMAGE_REL_BASED_DIR64   10
            if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        // Get a pointer to the next _IMAGE_BASE_RELOCATION
        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize) as *mut IMAGE_BASE_RELOCATION;
    }

    Some(true)
}

/// Process image import table (resolve imports)
pub unsafe fn resolve_imports(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;
    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_IMPORT_DESCRIPTOR;

    if import_directory.is_null() {
        return Some(false);
    }

    while (*import_directory).Name != 0x0 {
        // Get the name of the dll in the current _IMAGE_IMPORT_DESCRIPTOR
        let dll_name = (module_base as usize + (*import_directory).Name as usize) as *const u8;
        // Load the DLL in the in the address space of the process by calling the function pointer LoadLibraryA
        let dll_handle = LoadLibraryA(dll_name);

        // Get a pointer to the Original Thunk or First Thunk via OriginalFirstThunk or FirstThunk
        let mut original_thunk = if (module_base as usize + (*import_directory).FirstThunk as usize) != 0 {
            let orig_thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            orig_thunk
        } else {
            let thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            thunk
        };

        let mut thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

        while (*original_thunk).u1.Function != 0 {
            // #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0) or #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
            let snap_result = (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0;

            if snap_result {
                // #define IMAGE_ORDINAL64	(Ordinal) (Ordinal & 0xffff) or #define  IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
                let fn_ordinal = ((*original_thunk).u1.Ordinal & 0xffff) as _;
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by ordinal
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_ordinal)? as _;
            } else {
                // Get a pointer to _IMAGE_IMPORT_BY_NAME
                let thunk_data = (module_base as usize + (*original_thunk).u1.AddressOfData as usize) as *mut IMAGE_IMPORT_BY_NAME;
                // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
                let fn_name = (*thunk_data).Name.as_ptr() as *const u8;
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by name
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_name)? as _;
            }

            // Increment and get a pointer to the next Thunk and Original Thunk
            thunk = thunk.add(1);
            original_thunk = original_thunk.add(1);
        }

        // Increment and get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory = (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as _;
    }

    Some(true)
}

/// Generate a unique hash
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

    hash
}

/// Get the length of a C String
pub unsafe fn get_cstr_len(pointer: *const u8) -> usize {
    let mut tmp: u64 = pointer as u64;

    while *(tmp as *const u8) != 0 {
        tmp += 1;
    }

    (tmp - pointer as u64) as _
}

/// Checks to see if the architecture x86 or x86_64
pub fn is_wow64() -> bool {
    // A usize is 4 bytes on 32 bit and 8 bytes on 64 bit
    if size_of::<usize>() == 4 {
        return false;
    }

    true
}

/// Convert a combo pattern to bytes without wildcards
pub fn get_bytes_as_hex(pattern: &str) -> Result<Vec<Option<u8>>, ()> {
    let mut pattern_bytes = Vec::new();

    for x in pattern.split_whitespace() {
        match x {
            "?" => pattern_bytes.push(None),
            _ => pattern_bytes.push(u8::from_str_radix(x, 16).map(Some).map_err(|_| ())?),
        }
    }

    Ok(pattern_bytes)
}

/// Pattern or Signature scan a region of memory
pub fn pattern_scan(data: &[u8], pattern: &str) -> Result<Option<usize>, ()> {
    let pattern_bytes = get_bytes_as_hex(pattern)?;

    let offset = data.windows(pattern_bytes.len()).position(|window| {
        window
            .iter()
            .zip(&pattern_bytes)
            .all(|(byte, pattern_byte)| pattern_byte.map_or(true, |b| *byte == b))
    });

    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cstr_len() {
        assert_eq!(unsafe { get_cstr_len("test".as_ptr()) }, 4);
    }

    #[test]
    fn test_dbj2_hash_uppercase_lowercase_numbers() {
        assert_eq!(djb2_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes()), 0xd6989ec4);
        assert_eq!(djb2_hash("abcdefghijklmnopqrstuvwxyz".as_bytes()), 0xd6989ec4);
        assert_eq!(djb2_hash("0123456789".as_bytes()), 0x3b5a4652);
    }

    #[test]
    fn test_is_wow64() {
        assert!(is_wow64());
    }

    #[test]
    fn test_get_peb_and_teb() {
        assert_eq!(unsafe { get_peb() }.is_null(), false);
        assert_eq!(unsafe { get_teb() }.is_null(), false);
    }

    #[test]
    fn test_get_dos_and_nt_headers() {
        let peb = unsafe { get_peb() };
        let module_base = unsafe { (*peb).Reserved3[2] }; // ImageBaseAddress

        assert!(unsafe { get_dos_header(module_base as _) }.is_some());
        assert!(unsafe { get_nt_headers(module_base as _) }.is_some());
    }

    #[test]
    fn test_get_section_header_by_hash() {
        let peb = unsafe { get_peb() };
        let module_base = unsafe { (*peb).Reserved3[2] }; // ImageBaseAddress

        assert!(unsafe { get_section_header_by_hash(module_base as _, 0xb65d0ad) }.is_some());
    }

    #[test]
    fn test_get_loaded_module_and_export_by_hash() {
        // kernel32.dll hash
        let kernel32 = unsafe { get_loaded_module_by_hash(0x6ddb9555) };
        assert!(kernel32.is_some());

        // OpenProcess hash
        assert!(unsafe { get_export_by_hash(kernel32.unwrap(), 0x8b21e0b6) }.is_some());
    }

    #[test]
    fn test_pattern_scan() {
        // kernelbase.dll hash
        let kernelbase = unsafe { get_loaded_module_by_hash(0x3ebb38b).unwrap() };
        let nt_headers = unsafe { get_nt_headers(kernelbase as _).unwrap() };

        let image_base = unsafe { (*nt_headers).OptionalHeader.ImageBase } as usize;
        let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage };
        let kernelbase_slice = unsafe { from_raw_parts(kernelbase as _, image_size as _) };

        /*
            Address of signature = KERNELBASE.dll + 0x00032230
            "\x4C\x8B\x00\x48\x83\xEC\x00\x49\x83\x63\xC0", "xx?xxx?xxxx"
            "4C 8B ? 48 83 EC ? 49 83 63 C0"
        */

        // OpenProcess hash
        let open_process_address_via_get_exports_by_hash = unsafe { get_export_by_hash(kernelbase, 0x8b21e0b6).unwrap() as usize };
        let open_process_offset = pattern_scan(kernelbase_slice, "4C 8B ? 48 83 EC ? 49 83 63 C0").unwrap().unwrap();

        let open_process_address_via_pattern_scan = image_base + open_process_offset;

        assert_eq!(open_process_address_via_pattern_scan, open_process_address_via_get_exports_by_hash);
    }
}
