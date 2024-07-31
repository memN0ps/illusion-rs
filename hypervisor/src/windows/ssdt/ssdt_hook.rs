//! This crate provides functionality for hooking into the System Service Dispatch Table (SSDT)
//! of Windows operating systems. It allows for the interception and potential modification
//! of system calls made by applications, which can be useful for debugging, monitoring,
//! or altering system behavior for specialized purposes such as in the context of hypervisors
//! or security tools.

use {
    crate::{error::HypervisorError, intel::addresses::PhysicalAddress, windows::ssdt::ssdt_find::SsdtFind},
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
    pub guest_function_va: *const u8,

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
        trace!("Finding SSDT function address");

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

        let ssdt_base_va = ssdt.p_service_table as *mut u8;

        if ssdt_base_va.is_null() {
            return Err(HypervisorError::SsdtNotFound);
        }

        trace!("SSDT base address: {:p}", ssdt_base_va);

        // Get a pointer to the target offset within the SSDT.
        // let offset = unsafe { ssdt.p_service_table.add(api_number as usize).read() as usize >> 4 }; // We can't do this because it's a guest VA.
        //
        let offset_ptr_va = unsafe { ssdt.p_service_table.add(api_number as usize) };
        let offset_ptr_pa = PhysicalAddress::pa_from_va(offset_ptr_va as u64)? as *const i32;
        let offset = unsafe { offset_ptr_pa.read() as usize >> 4 };
        trace!("SSDT function offset: {:#x}", offset);

        // Compute the function's address by adding its offset to the base address.
        let guest_function_va = unsafe { ssdt_base_va.add(offset) as *const u8 };
        trace!("SSDT function address: {:p}", guest_function_va);

        Ok(Self {
            guest_function_va,
            api_number,
        })
    }
}
