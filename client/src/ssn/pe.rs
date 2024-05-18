use {
    core::{arch::asm, mem::size_of, slice::from_raw_parts},
    ntapi::{
        ntldr::PLDR_DATA_TABLE_ENTRY,
        ntpebteb::{PPEB, PTEB},
        ntpsapi::PPEB_LDR_DATA,
        winapi::um::{
            libloaderapi::{GetProcAddress, LoadLibraryA},
            winnt::{
                IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
                IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL64, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
                IMAGE_SNAP_BY_ORDINAL64, PIMAGE_BASE_RELOCATION, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_IMPORT_BY_NAME,
                PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER, PIMAGE_THUNK_DATA64,
            },
        },
    },
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

/// Get section header by hash
pub unsafe fn get_section_header_by_hash(module_base: *mut u8, section_hash: u32) -> Option<PIMAGE_SECTION_HEADER> {
    let nt_headers = get_nt_headers(module_base)?;
    let section_header =
        (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as PIMAGE_SECTION_HEADER;

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
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_hash == djb2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return Some((module_base as usize + functions[ordinal] as usize) as *mut u8);
        }
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
        as PIMAGE_BASE_RELOCATION;

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
        let count = ((*base_relocation).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>() as usize;

        for i in 0..count {
            // Get the Type and Offset from the Block Size field of the _IMAGE_BASE_RELOCATION block
            let type_field = (item.offset(i as isize).read() >> 12) as u32;
            let offset = item.offset(i as isize).read() & 0xFFF;

            //IMAGE_REL_BASED_DIR32 does not exist
            //#define IMAGE_REL_BASED_DIR64   10
            if type_field == IMAGE_REL_BASED_DIR64 as u32 || type_field == IMAGE_REL_BASED_HIGHLOW as u32 {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        // Get a pointer to the next _IMAGE_BASE_RELOCATION
        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize) as PIMAGE_BASE_RELOCATION;
    }

    return Some(true);
}

/// Process image import table (resolve imports)
pub unsafe fn resolve_imports(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;
    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize)
        as PIMAGE_IMPORT_DESCRIPTOR;

    if import_directory.is_null() {
        return Some(false);
    }

    while (*import_directory).Name != 0x0 {
        // Get the name of the dll in the current _IMAGE_IMPORT_DESCRIPTOR
        let dll_name = (module_base as usize + (*import_directory).Name as usize) as *const i8;
        // Load the DLL in the in the address space of the process by calling the function pointer LoadLibraryA
        let dll_handle = LoadLibraryA(dll_name);

        // Get a pointer to the Original Thunk or First Thunk via OriginalFirstThunk or FirstThunk
        let mut original_thunk = if (module_base as usize + *(*import_directory).u.OriginalFirstThunk() as usize) != 0 {
            let orig_thunk = (module_base as usize + *(*import_directory).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA64;
            orig_thunk
        } else {
            let thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as PIMAGE_THUNK_DATA64;
            thunk
        };

        let mut thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as PIMAGE_THUNK_DATA64;

        while *(*original_thunk).u1.Function() != 0 {
            // #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0) or #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
            let snap_result = IMAGE_SNAP_BY_ORDINAL64(*(*original_thunk).u1.Ordinal());

            if snap_result {
                let fn_ordinal = IMAGE_ORDINAL64(*(*original_thunk).u1.Ordinal()) as _;
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by ordinal
                *(*thunk).u1.Function_mut() = GetProcAddress(dll_handle, fn_ordinal) as _;
            } else {
                // Get a pointer to _IMAGE_IMPORT_BY_NAME
                let thunk_data = (module_base as usize + *(*original_thunk).u1.AddressOfData() as usize) as PIMAGE_IMPORT_BY_NAME;
                // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
                let fn_name = (*thunk_data).Name.as_ptr();
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in IMAGE_THUNK_DATA by calling function pointer GetProcAddress by name
                *(*thunk).u1.Function_mut() = GetProcAddress(dll_handle, fn_name) as _;
            }

            // Increment and get a pointer to the next Thunk and Original Thunk
            thunk = thunk.add(1);
            original_thunk = original_thunk.add(1);
        }

        // Increment and get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory = (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
    }

    return Some(true);
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

    return hash;
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

    return true;
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
