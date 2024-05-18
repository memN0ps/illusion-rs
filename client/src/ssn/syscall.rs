use {crate::ssn::pe, obfstr::obfstr, std::collections::BTreeMap};

const NTDLL_HASH: u32 = 0x1edab0ed; // ntdll.dll hash

/// Represents a system call utility to interact with ntdll.dll exports.
pub struct Syscall {
    nt_exports: Vec<(String, usize)>,
}

impl Syscall {
    /// Creates a new `Syscall` instance and initializes it with sorted ntdll exports.
    pub fn new() -> Self {
        let nt_exports = Self::get_sorted_nt_exports();
        Self { nt_exports }
    }

    /// Retrieves the syscall number by hashing the function name and comparing it to the sorted exports.
    ///
    /// # Arguments
    ///
    /// * `function_hash` - The hash of the function name.
    ///
    /// # Returns
    ///
    /// * `Option<u16>` - The syscall number if found, otherwise `None`.
    pub fn get_ssn_by_hash(&mut self, function_hash: u32) -> Option<u16> {
        let mut syscall_number: u16 = 0;

        for exports in &self.nt_exports {
            if function_hash == pe::djb2_hash(exports.0.as_bytes()) {
                return Some(syscall_number);
            }
            syscall_number += 1;
        }

        None
    }

    /// Sorts the exports by address and returns a vector of tuples containing the name and address.
    ///
    /// # Returns
    ///
    /// * `Vec<(String, usize)>` - A vector of sorted exports with their names and addresses.
    pub fn get_sorted_nt_exports() -> Vec<(String, usize)> {
        let ntdll_base = unsafe { pe::get_loaded_module_by_hash(NTDLL_HASH).expect(obfstr!("[-] Failed to get module base")) };

        let mut nt_exports = BTreeMap::new();

        for (name, addr) in unsafe { pe::get_exports_by_name(ntdll_base).expect(obfstr!("[-] Failed to get exports by name")) } {
            if name.starts_with(obfstr!("Zw")) {
                nt_exports.insert(name.replace(obfstr!("Zw"), obfstr!("Nt")), addr);
            }
        }

        let mut nt_exports_vec: Vec<(String, usize)> = Vec::from_iter(nt_exports);
        nt_exports_vec.sort_by_key(|k| k.1);

        nt_exports_vec
    }

    /// Gets the address of the syscall instruction in ntdll.dll.
    ///
    /// # Arguments
    ///
    /// * `function_hash` - The hash of the function name.
    ///
    /// # Returns
    ///
    /// * `Option<*mut u8>` - The address of the syscall instruction if found, otherwise `None`.
    pub fn get_syscall_instruction_address(&self, function_hash: u32) -> Option<*mut u8> {
        let mut address: *mut u8 = std::ptr::null_mut();
        for export in &self.nt_exports {
            if function_hash == pe::djb2_hash(export.0.as_bytes()) {
                address = export.1 as _;
            }
        }

        unsafe {
            for x in 0..25 {
                if address.add(x).read() == 0x0f && address.add(x + 1).read() == 0x05 && address.add(x + 2).read() == 0xc3 {
                    return Some(address.add(x) as _);
                }
            }
        }

        None
    }
}
