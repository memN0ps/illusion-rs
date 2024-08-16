use {
    crate::memory::process::error::ProcessError,
    std::{ffi::CStr, mem::size_of},
    windows_sys::Win32::{
        Foundation::{GetLastError, INVALID_HANDLE_VALUE},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next, MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
    },
};

/// A struct to manage processes and modules within a Windows system.
pub struct ProcessManager;

impl ProcessManager {
    /// Creates a new instance of the ProcessManager.
    pub fn new() -> Self {
        ProcessManager
    }

    /// Retrieves the process ID by the process name.
    ///
    /// # Arguments
    ///
    /// * `process_name` - A string slice that holds the name of the process.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - The process ID if found.
    /// * `Err(ProcessError)` - If there was an error during the operation.
    pub fn get_process_id_by_name(&self, process_name: &str) -> Result<u32, ProcessError> {
        let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        if h_snapshot == INVALID_HANDLE_VALUE {
            return Err(ProcessError::FailedToCreateSnapshot(get_last_error()));
        }

        let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
            return Err(ProcessError::FailedToGetFirstProcess(get_last_error()));
        }

        loop {
            let process_name_in_snapshot = unsafe { CStr::from_ptr(process_entry.szExeFile.as_ptr()) }.to_string_lossy().into_owned();

            if process_name_in_snapshot.to_lowercase() == process_name.to_lowercase() {
                return Ok(process_entry.th32ProcessID);
            }

            if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
                return Err(ProcessError::FailedToGetNextProcess(get_last_error()));
            }
        }
    }

    /// Retrieves the base address of a module inside a process by the module name.
    ///
    /// # Arguments
    ///
    /// * `module_name` - A string slice that holds the name of the module.
    /// * `process_id` - The process ID to search within.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The base address of the module if found.
    /// * `Err(ProcessError)` - If there was an error during the operation.
    pub fn get_module_address_by_name(&self, module_name: &str, process_id: u64) -> Result<usize, ProcessError> {
        let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id as _) };

        if h_snapshot == INVALID_HANDLE_VALUE {
            return Err(ProcessError::FailedToCreateSnapshot(get_last_error()));
        }

        let mut module_entry: MODULEENTRY32 = unsafe { std::mem::zeroed::<MODULEENTRY32>() };
        module_entry.dwSize = size_of::<MODULEENTRY32>() as u32;

        if unsafe { Module32First(h_snapshot, &mut module_entry) } == 0 {
            return Err(ProcessError::FailedToGetFirstModule(get_last_error()));
        }

        loop {
            let module_name_in_snapshot = unsafe { CStr::from_ptr(module_entry.szModule.as_ptr()) }.to_string_lossy().into_owned();

            if module_name_in_snapshot.to_lowercase() == module_name.to_lowercase() {
                return Ok(module_entry.modBaseAddr as usize);
            }

            if unsafe { Module32Next(h_snapshot, &mut module_entry) } == 0 {
                return Err(ProcessError::FailedToGetNextModule(get_last_error()));
            }
        }
    }
}

fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}
