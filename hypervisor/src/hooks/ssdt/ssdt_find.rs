use {
    hypervisor::error::HypervisorError,
    alloc::vec::Vec,
    crate::hooks::ssdt::ssdt_info::Sysinfo,
};

pub struct SsdtFind {
    pub nt_table: *const u64,
    pub win32k_table: *const u64,
}

impl SsdtFind {
    pub fn find_ssdt() -> Result<Self, HypervisorError> {
        let (kernel_base, kernel_size) = Self::get_kernel_base()?;
        log::debug!("Kernel base address: {:p}", kernel_base);
        log::debug!("Kernel size: {}", kernel_size);

        /*
           14042ba50  uint64_t KiSystemServiceStart(int64_t arg1, int64_t arg2, uint64_t arg3, int64_t arg4, int32_t arg5 @ rax, uint64_t arg6 @ rbx, int128_t* arg7 @ rbp, uint64_t arg8 @ ssp)

           14042ba50  4889a390000000     mov     qword [rbx+0x90], rsp {__return_addr}
           14042ba57  8bf8               mov     edi, eax
           14042ba59  c1ef07             shr     edi, 0x7
           14042ba5c  83e720             and     edi, 0x20
           14042ba5f  25ff0f0000         and     eax, 0xfff

           14042ba64  4c8d15555e9d00     lea     r10, [rel KeServiceDescriptorTable]
           14042ba6b  4c8d1d8e368f00     lea     r11, [rel KeServiceDescriptorTableShadow]
        */
        let ki_service_system_start_pattern = "8B F8 C1 EF 07 83 E7 20 25 FF 0F 00 00";
        let signature_size = 13;

        // Read Windows Kernel (ntoskrnl.exe) from memory
        let ntoskrnl_data =
            unsafe { core::slice::from_raw_parts(kernel_base as *const u8, kernel_size as usize) };

        // Find the KiServiceSystemStart signature
        let offset = Self::pattern_scan(ntoskrnl_data, ki_service_system_start_pattern)?
            .ok_or(HypervisorError::PatternNotFound)?;

        // Calculate the address of KiServiceSystemStart using .add(),
        // which is, `14042ba57  8bf8               mov     edi, eax` in this case.
        let ki_service_system_start = unsafe { kernel_base.add(offset) };
        log::info!(
            "KiServiceSystemStart address: {:p}",
            ki_service_system_start
        );

        // Address of the 'lea r10, [rel KeServiceDescriptorTable]' instruction
        let lea_r10_address = unsafe { ki_service_system_start.add(signature_size) };

        // Address of the 'lea r11, [rel KeServiceDescriptorTableShadow]' instruction
        let lea_r11_address = unsafe { lea_r10_address.add(7) }; // 7 bytes after lea r10

        // Reading the 4-byte relative offset for KeServiceDescriptorTableShadow
        let relative_offset = unsafe { *(lea_r11_address.add(3) as *const i32) }; // 3 bytes after the opcode

        log::info!("Relative offset: {:x}", relative_offset);

        // Compute the absolute address of KeServiceDescriptorTableShadow
        let ke_service_descriptor_table_shadow =
            unsafe { lea_r11_address.add(7).offset(relative_offset as isize) };

        // Extracting nt!KiServiceTable and win32k!W32pServiceTable addresses
        let shadow = ke_service_descriptor_table_shadow;

        // NtTable Address of Nt Syscall Table
        let nt_table = shadow as *const u64;

        // Win32kTable Address of Win32k Syscall Table
        let win32k_table = unsafe { shadow.offset(0x20) as *const u64 };

        log::info!("NtTable address: {:p}", nt_table);
        log::info!("Win32kTable address: {:p}", win32k_table);

        Ok(Self {
            nt_table,
            win32k_table,
        })
    }

    /// Gets the base address and size of the kernel module.
    ///
    /// # Returns
    ///
    /// A tuple with the base address and size of the kernel module.
    pub fn get_kernel_base() -> Result<(*mut u8, u32), HypervisorError> {
        let mut sys_info = Sysinfo::new()?;

        let (kernel_base, kernel_size) = sys_info
            .get_module_base("ntoskrnl.exe\0")
            .ok_or(HypervisorError::GetKernelBaseFailed)?;

        Ok((kernel_base as _, kernel_size))
    }

    /// Convert a combo pattern to bytes without wildcards
    pub fn get_bytes_as_hex(pattern: &str) -> Result<Vec<Option<u8>>, HypervisorError> {
        let mut pattern_bytes = Vec::new();

        for x in pattern.split_whitespace() {
            match x {
                "?" => pattern_bytes.push(None),
                _ => pattern_bytes.push(
                    u8::from_str_radix(x, 16)
                        .map(Some)
                        .map_err(|_| HypervisorError::HexParseError)?,
                ),
            }
        }

        Ok(pattern_bytes)
    }

    /// Pattern or Signature scan a region of memory
    pub fn pattern_scan(data: &[u8], pattern: &str) -> Result<Option<usize>, HypervisorError> {
        let pattern_bytes = Self::get_bytes_as_hex(pattern)?;

        let offset = data.windows(pattern_bytes.len()).position(|window| {
            window
                .iter()
                .zip(&pattern_bytes)
                .all(|(byte, pattern_byte)| pattern_byte.map_or(true, |b| *byte == b))
        });

        Ok(offset)
    }
}
