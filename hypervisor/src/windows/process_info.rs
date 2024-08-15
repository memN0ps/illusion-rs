use {
    crate::{
        intel::addresses::PhysicalAddress,
        windows::nt::types::{UNICODE_STRING, _LIST_ENTRY},
    },
    alloc::string::String,
    widestring::U16CStr,
    x86::{bits64::vmx::vmread, vmx::vmcs},
};

/// Constants for offsets in the process structures
const THREAD_OFFSET: u64 = 0x188;
const THREAD_PROCESS_OFFSET: u64 = 0xB8;
const UNIQUE_PROCESS_ID_OFFSET: u64 = 0x440;
const IMAGE_FILE_POINTER_OFFSET: u64 = 0x5a0;
const IMAGE_FILE_NAME_OFFSET: u64 = 0x58;
const DIRECTORY_TABLE_BASE_OFFSET: u64 = 0x28;
const ACTIVE_PROCESS_LINKS_OFFSET: u64 = 0x448;

/// Struct representing process information
#[derive(Debug)]
pub struct ProcessInformation {
    /// The image file name of the process.
    pub file_name: String,

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
    ///     struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    ///
    /// struct _KPROCESS
    ///     ULONGLONG DirectoryTableBase;                                           //0x28
    ///
    /// struct _FILE_OBJECT
    ///     struct _UNICODE_STRING FileName;                                        //0x58
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

        // Read the image file pointer from the _EPROCESS structure.
        let image_file_pointer = PhysicalAddress::read_guest_virt((process + IMAGE_FILE_POINTER_OFFSET) as *const u64)?;

        if image_file_pointer == 0 {
            return None;
        }

        // Read the image file name from the _FILE_OBJECT structure.
        let image_file_name =
            unsafe { &*(PhysicalAddress::pa_from_va_with_current_cr3(image_file_pointer + IMAGE_FILE_NAME_OFFSET).ok()? as *const UNICODE_STRING) };

        // Read the image file name bytes from the UNICODE_STRING structure.
        let image_file_name_buffer = PhysicalAddress::read_guest_slice(image_file_name.Buffer, image_file_name.MaximumLength as usize / 2)?;

        // Convert the image file name bytes to a string.
        let file_name = U16CStr::from_slice_truncate(image_file_name_buffer).ok()?.to_string().ok()?;

        // Read the directory table base (CR3) from the _KPROCESS structure within _EPROCESS.
        let directory_table_base = PhysicalAddress::read_guest_virt((process + DIRECTORY_TABLE_BASE_OFFSET) as *const u64)?;

        if directory_table_base == 0 {
            return None;
        }

        // Read the unique process ID from the _EPROCESS structure.
        let unique_process_id = PhysicalAddress::read_guest_virt((process + UNIQUE_PROCESS_ID_OFFSET) as *const u64)?;

        // Return the populated ProcessInformation struct.
        Some(Self {
            file_name,
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
        let current_thread = PhysicalAddress::read_guest_virt((gs + THREAD_OFFSET) as *const u64)?;

        if current_thread == 0 {
            return None;
        }

        // Compute the address of the _EPROCESS structure.
        let current_process = PhysicalAddress::read_guest_virt((current_thread + THREAD_PROCESS_OFFSET) as *const u64)?;

        if current_process == 0 {
            return None;
        }

        Some(current_process)
    }

    /// Retrieves the process ID of a process by its process ID.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The process ID of the process to retrieve.
    ///
    /// # Example
    ///
    /// struct _EPROCESS
    ///     struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    ///
    /// # Returns
    ///
    /// * `Option<u64>` - The physical address of the `_EPROCESS` structure of the specified process, or `None` if not found.
    fn get_process_by_process_id(process_id: u64) -> Option<u64> {
        // Retrieve the physical address of the current process (_EPROCESS structure).
        let start_process = Self::ps_get_current_process()?;
        let mut current_process = start_process;

        loop {
            // Read the unique process ID from the _EPROCESS structure.
            let unique_process_id = PhysicalAddress::read_guest_virt((current_process + UNIQUE_PROCESS_ID_OFFSET) as *const u64)?;

            // Check if the current process ID matches the specified process ID
            if unique_process_id == process_id {
                return Some(current_process);
            }

            // Move to the next process in the list by following the Flink pointer.
            let next_process_links = PhysicalAddress::read_guest_virt((current_process + ACTIVE_PROCESS_LINKS_OFFSET) as *const _LIST_ENTRY)?;
            current_process = next_process_links.Flink as u64 - ACTIVE_PROCESS_LINKS_OFFSET;

            // If we've looped back to the starting process, exit the loop.
            if current_process == start_process {
                break;
            }
        }

        None
    }

    /// Retrieves the directory table base (CR3) of a process by its process ID.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The process ID of the process to retrieve the directory table base from.
    ///
    /// # Returns
    ///
    /// * `Option<u64>` - The directory table base (CR3) of the process, or `None` if not found.
    pub fn get_directory_table_base_by_process_id(process_id: u64) -> Option<u64> {
        // Retrieve the physical address of the process by its process ID.
        let process = Self::get_process_by_process_id(process_id)?;

        // Read the directory table base (CR3) from the _KPROCESS structure within _EPROCESS.
        PhysicalAddress::read_guest_virt((process + DIRECTORY_TABLE_BASE_OFFSET) as *const u64)
    }
}
