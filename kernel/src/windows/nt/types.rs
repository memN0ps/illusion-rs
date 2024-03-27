use core::ffi::c_void;

pub const IMAGE_DOS_SIGNATURE: u16 = 23117u16;
pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: IMAGE_DIRECTORY_ENTRY = 0u16;
pub const SystemModuleInformation: SYSTEM_INFORMATION_CLASS = 11;

pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;
pub type PIMAGE_NT_HEADERS64 = *mut IMAGE_NT_HEADERS64;
pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;
pub type IMAGE_FILE_MACHINE = u16;
pub type IMAGE_FILE_CHARACTERISTICS = u16;
pub type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
pub type IMAGE_SUBSYSTEM = u16;
pub type IMAGE_DLL_CHARACTERISTICS = u16;
pub type IMAGE_DIRECTORY_ENTRY = u16;
pub type PHYSICAL_ADDRESS = _LARGE_INTEGER;
pub type SYSTEM_INFORMATION_CLASS = u32;
pub type HANDLE = isize;
pub type FILE_ACCESS_RIGHTS = u32;
pub type PWSTR = *mut u16;
pub type NTSTATUS = i32;
pub type FILE_FLAGS_AND_ATTRIBUTES = u32;
pub type FILE_SHARE_MODE = u32;
pub type NTCREATEFILE_CREATE_DISPOSITION = u32;
pub type NTCREATEFILE_CREATE_OPTIONS = u32;

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *const c_void,
    pub SecurityQualityOfService: *const c_void,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Anonymous: IO_STATUS_BLOCK_0,
    pub Information: usize,
}

#[repr(C)]
pub union IO_STATUS_BLOCK_0 {
    pub Status: NTSTATUS,
    pub Pointer: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RTL_PROCESS_MODULES {
    pub NumberOfModules: u32,
    pub Modules: [RTL_PROCESS_MODULE_INFORMATION; 1],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RTL_PROCESS_MODULE_INFORMATION {
    pub Section: *mut c_void,
    pub MappedBase: *mut c_void,
    pub ImageBase: *mut c_void,
    pub ImageSize: u32,
    pub Flags: u32,
    pub LoadOrderIndex: u16,
    pub InitOrderIndex: u16,
    pub LoadCount: u16,
    pub OffsetToFileName: u16,
    pub FullPathName: [u8; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union _LARGE_INTEGER {
    pub __bindgen_anon_1: _LARGE_INTEGER__bindgen_ty_1,
    pub u: _LARGE_INTEGER__bindgen_ty_2,
    pub QuadPart: i64,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct _LARGE_INTEGER__bindgen_ty_1 {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct _LARGE_INTEGER__bindgen_ty_2 {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}
