use {
    crate::intel::addresses::PhysicalAddress,
    alloc::string::{String, ToString},
    core::ffi::CStr,
    x86::{bits64::vmx::vmread, vmx::vmcs},
};

/// Constants for offsets in the process structures
const GS_BASE_OFFSET: u64 = 0x188;
const THREAD_PROCESS_OFFSET: u64 = 0xB8;
const UNIQUE_PROCESS_ID_OFFSET: u64 = 0x440;
const IMAGE_FILE_NAME_OFFSET: u64 = 0x5a8;
const IMAGE_FILE_NAME_LENGTH: usize = 15;
const DIRECTORY_TABLE_BASE_OFFSET: u64 = 0x28;

/// Struct representing process information
#[derive(Debug)]
pub struct ProcessInformation {
    /// The image file name of the process.
    pub image_file_name: String,

    /// The unique process ID of the process.
    pub unique_process_id: u64,

    /// The directory table base of the process (CR3).
    pub directory_table_base: u64,
}

impl ProcessInformation {
    /// Retrieves information about the current process.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to retrieve the process information from.
    ///
    /// # Returns
    ///
    /// The process information of the current process, or `None` if the information could not be retrieved.
    ///
    /// # Example
    ///
    /// struct _EPROCESS
    ///     struct _KPROCESS Pcb;                                                   //0x0
    ///     VOID* UniqueProcessId;                                                  //0x440
    ///     UCHAR ImageFileName[15];                                                //0x5a8
    ///
    /// struct _KPROCESS
    ///     ULONGLONG DirectoryTableBase;                                           //0x28
    ///
    /// # Credits
    ///
    /// @wcscpy and @vmctx
    ///
    /// # References
    ///
    /// https://www.vergiliusproject.com/kernels/x64/windows-11/23h2
    pub fn get_current_process_info() -> Option<Self> {
        // Retrieve the physical address of the current process (_EPROCESS structure).
        let process = Self::ps_get_current_process()?;
        let process = PhysicalAddress::pa_from_va(process).ok()?;

        // Read the unique process ID from the _EPROCESS structure.
        let unique_process_id = unsafe { core::ptr::read((process + UNIQUE_PROCESS_ID_OFFSET) as *const u64) };

        // Read the image file name from the _EPROCESS structure.
        let image_file_name_bytes = unsafe { core::slice::from_raw_parts((process + IMAGE_FILE_NAME_OFFSET) as *const u8, IMAGE_FILE_NAME_LENGTH) };
        let image_name = unsafe { CStr::from_bytes_with_nul_unchecked(image_file_name_bytes) }
            .to_str()
            .ok()?
            .to_string();

        // Read the directory table base (CR3) from the _KPROCESS structure within _EPROCESS.
        let directory_table_base = unsafe { core::ptr::read((process + DIRECTORY_TABLE_BASE_OFFSET) as *const u64) };

        // Check if the image name, unique process ID, and directory table base are valid.
        if image_name.is_empty() || unique_process_id == 0 || directory_table_base == 0 {
            return None;
        }

        log::trace!(
            "Retrieved process information: image_file_name={}, unique_process_id={:#x}, directory_table_base={:#x}",
            image_name,
            unique_process_id,
            directory_table_base
        );

        // Return the populated ProcessInformation struct.
        Some(Self {
            image_file_name: image_name,
            unique_process_id,
            directory_table_base,
        })
    }

    /// Manually implemented version of the `PsGetCurrentProcess` function.
    ///
    /// This function mimics the behavior of the Windows `PsGetCurrentProcess` function,
    /// returning the physical address of the current `_EPROCESS` structure.
    ///
    /// # Returns
    ///
    /// The physical address of the current `_EPROCESS` structure, or `None` if it could not be retrieved.
    ///
    /// # Example
    ///
    /// ; _KPROCESS *PsGetCurrentProcess()
    /// public PsGetCurrentProcess
    /// PsGetCurrentProcess proc near
    /// mov     rax, gs:188h    ; IoGetCurrentProcess
    /// mov     rax, [rax+0B8h]
    /// retn
    /// PsGetCurrentProcess endp
    ///
    /// # Credits
    ///
    /// @wcscpy and @vmctx
    ///
    /// # References
    ///
    /// https://www.vergiliusproject.com/kernels/x64/windows-11/23h2
    fn ps_get_current_process() -> Option<u64> {
        // Read the GS base address.
        let gs = unsafe { vmread(vmcs::guest::GS_BASE).ok()? };

        if gs == 0 {
            return None;
        }

        // Compute the address of the current thread.
        let gs_value = PhysicalAddress::pa_from_va(gs + GS_BASE_OFFSET).ok()?;
        let current_thread = unsafe { core::ptr::read(gs_value as *const u64) };

        if current_thread == 0 {
            return None;
        }

        // Compute the address of the _EPROCESS structure.
        let current_thread = PhysicalAddress::pa_from_va(current_thread).ok()?;
        let process = unsafe { core::ptr::read((current_thread + THREAD_PROCESS_OFFSET) as *const u64) };

        if process == 0 {
            return None;
        }

        Some(process)
    }
}
