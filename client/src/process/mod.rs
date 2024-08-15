use {
    crate::process::error::Error,
    std::mem::size_of,
    windows_sys::Win32::{
        Foundation::{GetLastError, INVALID_HANDLE_VALUE},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next, MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
    },
};

pub mod error;

pub fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Gets the process ID by name, take process name as a parameter
pub fn get_process_id_by_name(process_name: &str) -> Result<u32, Error> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(Error::FailedToCreateSnapshot(get_last_error()));
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Err(Error::FailedToGetFirstProcess(get_last_error()));
    }

    loop {
        if convert_c_array_to_rust_string(process_entry.szExeFile.to_vec()).to_lowercase() == process_name.to_lowercase() {
            break;
        }

        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Err(Error::FailedToGetNextProcess(get_last_error()));
        }
    }

    Ok(process_entry.th32ProcessID)
}

/// Gets the base address of a module inside a process by name, take module name and process ID as a parameter.
pub fn get_module_address_by_name(module_name: &str, process_id: u32) -> Result<usize, Error> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(Error::FailedToCreateSnapshot(get_last_error()));
    }

    let mut module_entry: MODULEENTRY32 = unsafe { std::mem::zeroed::<MODULEENTRY32>() };
    module_entry.dwSize = size_of::<MODULEENTRY32>() as u32;

    if unsafe { Module32First(h_snapshot, &mut module_entry) } == 0 {
        return Err(Error::FailedToGetFirstModule(get_last_error()));
    }

    loop {
        if convert_c_array_to_rust_string(module_entry.szModule.to_vec()).to_lowercase() == module_name.to_lowercase() {
            break;
        }

        if unsafe { Module32Next(h_snapshot, &mut module_entry) } == 0 {
            return Err(Error::FailedToGetNextModule(get_last_error()));
        }
    }

    Ok(module_entry.modBaseAddr as _)
}

/// Converts a C null terminated String to a Rust String
pub fn convert_c_array_to_rust_string(buffer: Vec<i8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}
