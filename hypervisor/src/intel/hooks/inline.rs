use {core::ptr::copy_nonoverlapping, log::*};

/// Enum to define the types of inline hooks we support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineHookType {
    Int3,
    Cpuid,
    Vmcall,
    AbsoluteJmp,
}

/// Structure representing our hook configuration.
#[derive(Debug, Clone, Copy)]
pub struct InlineHook {
    /// The physical address of the shadow function.
    pub shadow_function_pa: *mut u8,

    /// The virtual address of the guest function.
    pub guest_function_va: *mut u8,

    /// The address of the hook handler.
    pub hook_handler: *mut u8,

    /// The type of hook we are using.
    pub hook_type: InlineHookType,

    /// The pre-allocated trampoline page for the hook.
    pub trampoline_page: *mut u8,
}

impl InlineHook {
    /// Creates a new hook configuration.
    ///
    /// # Arguments
    ///
    /// * `shadow_function_pa` - The physical address of the shadow function.
    /// * `hook_type` - The type of hook we are using.
    /// * `trampoline_page` - The pre-allocated trampoline page for the hook.
    ///
    /// # Returns
    ///
    /// * `Self` - The new hook configuration.
    pub fn new(
        shadow_function_pa: *mut u8,
        guest_function_va: *mut u8,
        hook_handler: *mut u8,
        hook_type: InlineHookType,
        trampoline_page: *mut u8,
    ) -> Self {
        trace!("Creating a new hook configuration");

        Self {
            shadow_function_pa,
            guest_function_va,
            hook_type,
            hook_handler,
            trampoline_page,
        }
    }

    /// Performs a detour or hook, from the source to the destination function, by overwriting it with either int3, cpuid, or vmcall instructions.
    pub fn detour64(&mut self) {
        trace!("Hook Type: {:?}", self.hook_type);

        let shellcode: &mut [u8] = match self.hook_type {
            // int3 instruction
            InlineHookType::Int3 => &mut [0xCC],

            // cpuid instruction
            InlineHookType::Cpuid => &mut [0x0F, 0xA2],

            // vmcall instruction
            InlineHookType::Vmcall => &mut [0x0F, 0x01, 0xC1],

            // mov rax, <immediate 64>
            // jmp rax
            InlineHookType::AbsoluteJmp => &mut [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0],
        };

        if self.hook_type == InlineHookType::AbsoluteJmp {
            unsafe {
                copy_nonoverlapping(
                    self.hook_handler as *const u8,
                    shellcode.as_mut_ptr().offset(2),
                    8,
                );
            }
        }

        unsafe {
            // First, backup the original bytes to the trampoline page
            copy_nonoverlapping(
                self.shadow_function_pa,
                self.trampoline_page,
                shellcode.len(),
            );

            // Then, overwrite the target location with the hook
            copy_nonoverlapping(shellcode.as_ptr(), self.shadow_function_pa, shellcode.len());
        }

        trace!("The hook has been installed successfully");
    }

    /// Setup a trampoline by appending a JMP back to the original function after the hook.
    ///
    /// # Arguments
    ///
    /// * `original_instruction_address` - The address of the original instruction.
    pub fn setup_trampoline(&self, original_instruction_address: u64) {
        trace!(
            "Appending JMP back to original instruction at: 0x{:X}",
            original_instruction_address
        );
        let jmp_instruction: [u8; 2] = [0x48, 0xB8]; // mov rax, <immediate 64>
        let jmp_to_rax: [u8; 2] = [0xFF, 0xE0]; // jmp rax

        unsafe {
            let trampoline_end = self.trampoline_page.offset(self.hook_size() as isize);
            copy_nonoverlapping(
                jmp_instruction.as_ptr(),
                trampoline_end,
                jmp_instruction.len(),
            );
            copy_nonoverlapping(
                &original_instruction_address as *const u64 as *const u8,
                trampoline_end.offset(jmp_instruction.len() as isize),
                8,
            );
            copy_nonoverlapping(
                jmp_to_rax.as_ptr(),
                trampoline_end.offset(jmp_instruction.len() as isize + 8),
                jmp_to_rax.len(),
            );
        }
    }

    /// Returns the size of the hook code in bytes based on the hook type.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the hook code in bytes.
    pub fn hook_size(&self) -> usize {
        match self.hook_type {
            InlineHookType::Int3 => 1,         // int3 is 1 byte
            InlineHookType::Cpuid => 2,        // cpuid is 2 bytes
            InlineHookType::Vmcall => 3,       // vmcall is 3 bytes
            InlineHookType::AbsoluteJmp => 13, // mov rax, <immediate 64> + jmp rax is 13 bytes
        }
    }

    /// Returns the address of the trampoline page.
    ///
    /// # Returns
    ///
    /// * `*mut u8` - The address of the trampoline page.
    pub fn trampoline_address(&self) -> *mut u8 {
        self.trampoline_page
    }
}
