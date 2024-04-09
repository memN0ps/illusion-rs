//! This crate provides functionality for hooking into the System Service Dispatch Table (SSDT)
//! of Windows operating systems. It allows for the interception and potential modification
//! of system calls made by applications, which can be useful for debugging, monitoring,
//! or altering system behavior for specialized purposes such as in the context of hypervisors
//! or security tools.

use {
    crate::{error::HypervisorError, windows::ssdt::ssdt_find::SsdtFind},
    log::*,
};

/// Represents the layout of the System Service Dispatch Table (SSDT).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SSDTStruct {
    /// Pointer to the service table containing addresses of system call functions.
    p_service_table: *const i32,

    /// Pointer to the counter table, which might be used for statistics or limits.
    p_counter_table: *const u8,

    /// The number of services or system calls available in this SSDT.
    number_of_services: u64,

    /// Pointer to the argument table, detailing the arguments each system call expects.
    p_argument_table: *const u8,
}

/// Describes a hook into the SSDT, allowing redirection of system calls.
pub struct SsdtHook {
    /// The original function address before hooking.
    pub function_address: *const u8,

    /// The API number in the SSDT that is being hooked.
    pub api_number: i32,
}

impl SsdtHook {
    /// Finds the address of a function in the SSDT and creates a hook for it.
    ///
    /// # Arguments
    ///
    /// * `api_number` - The API number of the function to hook.
    /// * `get_from_win32k` - Whether to get the function from the Win32k table instead of the NT table.
    /// * `kernel_base` - The base address of the kernel in memory.
    /// * `kernel_size` - The size of the kernel memory space.
    ///
    /// # Returns
    ///
    /// * `Ok(SsdtHook)` - A hook structure containing the address of the original function and its API number.
    /// * `Err(HypervisorError)` - An error occurred while finding the SSDT or the function within it.
    pub fn find_ssdt_function_address(
        mut api_number: i32,
        get_from_win32k: bool,
        kernel_base: *const u8,
        kernel_size: usize,
    ) -> Result<Self, HypervisorError> {
        debug!("Finding SSDT function address");

        let ssdt = SsdtFind::find_ssdt(kernel_base, kernel_size)?;

        trace!("NT SSDT address: {:?}", ssdt);

        // Determine the correct SSDT structure based on whether we are hooking an NT or Win32k function.
        let ssdt = if !get_from_win32k {
            unsafe { &*(ssdt.nt_table as *const SSDTStruct) }
        } else {
            // Adjust the API number for Win32k syscalls, which start from 0x1000.
            api_number = api_number - 0x1000;
            unsafe { &*(ssdt.win32k_table as *const SSDTStruct) }
        };

        trace!("SSDT structure: {:?}", ssdt);

        let ssdt_base = ssdt.p_service_table as *mut u8;

        if ssdt_base.is_null() {
            return Err(HypervisorError::SsdtNotFound);
        }

        info!("SSDT base address: {:p}", ssdt_base);

        // Calculate the offset to the target function within the SSDT.
        let offset = unsafe { ssdt.p_service_table.add(api_number as usize).read() as usize >> 4 };

        // Compute the function's address by adding its offset to the base address.
        let function_address = unsafe { ssdt_base.add(offset) as *const u8 };

        info!("SSDT function address: {:p}", function_address);

        Ok(Self {
            function_address,
            api_number,
        })
    }
}
