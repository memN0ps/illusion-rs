use {
    crate::{
        hooks::ssdt::ssdt_find::SsdtFind
    },
    hypervisor::error::HypervisorError,
};

#[repr(C)]
struct SSDTStruct {
    p_service_table: *const i32,
    p_counter_table: *const u8,
    number_of_services: u64,
    p_argument_table: *const u8,
}

pub struct SsdtHook {
    /// The original function address.
    pub function_address: *const u8,

    /// The hook function address
    pub api_number: i32,
}

/// Find entry from SSDT table of Nt functions and Win32k syscalls
impl SsdtHook {
    pub fn find_ssdt_function_address(
        mut api_number: i32,
        get_from_win32k: bool,
    ) -> Result<Self, HypervisorError> {
        log::debug!("Finding SSDT function address");

        let ssdt = SsdtFind::find_ssdt()?;

        // Index of the function to hook
        let ssdt = if !get_from_win32k {
            unsafe { &*(ssdt.nt_table as *const SSDTStruct) }
        } else {
            // Win32k APIs start from 0x1000
            api_number = api_number - 0x1000;
            unsafe { &*(ssdt.win32k_table as *const SSDTStruct) }
        };

        let ssdt_base = ssdt.p_service_table as *mut u8;

        if ssdt_base.is_null() {
            return Err(HypervisorError::SsdtNotFound);
        }

        log::info!("SSDT base address: {:p}", ssdt_base);

        // Calculate offset
        let offset = unsafe { ssdt.p_service_table.add(api_number as usize).read() as usize >> 4 };

        // Add offset to base address
        let function_address = unsafe { ssdt_base.add(offset) as *const u8 };

        log::info!("SSDT function address: {:p}", function_address);

        Ok(Self {
            function_address,
            api_number,
        })
    }
}
