use core::ptr::copy_nonoverlapping;
use log::trace;

/// Length in bytes of the shellcode used to perform a jump (JMP) inline hook.
pub const JMP_SIZE: usize = 14;

/// Length in bytes of the shellcode for a breakpoint (INT3) inline hook.
pub const INT3_SIZE: usize = 1;

/// Types of inline hooks that can be created by this library.
#[derive(Debug, Copy, Clone)]
pub enum InlineHookType {
    /// Jump-based inline hook, which redirects execution flow to a custom handler.
    Jmp,

    /// Breakpoint-based inline hook, utilizing the INT3 instruction to trigger a breakpoint exception.
    Breakpoint,
}

/// Represents an inline hook, which can be used to redirect execution flow to a custom handler.
pub struct InlineHook {
    /// The original address of the function to be hooked.
    pub original_address: *mut u8,

    /// The shadow copy address where the hook will be placed.
    pub shadow_copy_address: *mut u8,

    /// The handler function to be called when the hook is triggered.
    pub hook_handler: *mut u8,

    /// The type of inline hook to be created.
    pub hook_type: InlineHookType,

    pub trampoline: [u8; JMP_SIZE],
}

impl InlineHook {
    pub fn new(
        original_address: *mut u8,
        shadow_copy_address: *mut u8,
        hook_handler: *mut u8,
        hook_type: InlineHookType,
    ) -> Self {
        trace!("Constructing new inline hook");
        trace!("Hook Type: {:?}", hook_type);

        Self {
            original_address,
            shadow_copy_address,
            hook_handler,
            hook_type,
            trampoline: [0; JMP_SIZE],
        }
    }

    /// Creates a trampoline to store the stolen bytes and resumes execution flow, then calls the detour function.
    pub fn trampoline_hook64(&mut self) {
        trace!("Hook Type: {:?}", self.hook_type);

        trace!("Creating trampoline with address: {:#x}", self.trampoline.as_ptr() as usize);

        // Trampoline: Store the bytes that are to be stolen in the trampoline so we can resume execution flow and jump to them later
        unsafe {
            copy_nonoverlapping(
                self.shadow_copy_address,
                self.trampoline.as_mut_ptr(),
                JMP_SIZE,
            )
        };

        // 14 bytes for x86_64 for the trampoline
        let mut jmp_bytes: [u8; JMP_SIZE] = [
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // placeholder for address
        ];

        trace!("Creating jmp bytes for trampoline");

        // Populate jmp with an address to jump to: jmp <addresss>
        // The address to jump to is the original address + the size of the stolen bytes (instruction after the overwritten bytes)
        unsafe {
            copy_nonoverlapping(
                ((&((self.original_address as usize) + JMP_SIZE)) as *const usize) as *mut u8,
                jmp_bytes.as_mut_ptr().offset(6),
                8,
            );
        }

        trace!("Copied jmp bytes to trampoline: {:#x?}", jmp_bytes);

        trace!(
            "Copying jmp bytes to trampoline address: {:#x?}",
            self.trampoline
        );

        // Trampoline: Write a jmp at the end of the trampoline (after the restoring stolen bytes), to the address of the instruction after the hook to resume execution flow
        unsafe {
            copy_nonoverlapping(
                jmp_bytes.as_ptr(),
                ((self.trampoline.as_mut_ptr() as usize) + JMP_SIZE) as *mut u8,
                JMP_SIZE,
            );
        }
    }

    /// Performs a detour or hook, from source to the destination function.
    pub fn detour64(&mut self) {
        trace!("Hook Type: {:?}", self.hook_type);

        match self.hook_type {
            InlineHookType::Jmp => {
                // 14 bytes for x86_64 for the inline hook
                let mut jmp_shellcode: [u8; 14] = [
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00,
                ];

                trace!("Creating jmp bytes for hook");

                // Populate jmp array with the address of our detour function: jmp <hook handler>
                unsafe {
                    copy_nonoverlapping(
                        (&(self.hook_handler as usize) as *const usize) as *mut u8,
                        jmp_shellcode.as_mut_ptr().offset(6),
                        8,
                    );
                };

                /* Memory must be writable before hook */

                trace!(
                    "Copying jmp bytes to shadow copy address: {:#x?}",
                    self.shadow_copy_address
                );

                // Hook the original function and place a jmp <hook handler>
                unsafe {
                    copy_nonoverlapping(jmp_shellcode.as_ptr(), self.shadow_copy_address, JMP_SIZE);
                }
            }
            InlineHookType::Breakpoint => {
                // 1 byte for x86_64 for the inline hook
                let int3_shellcode: [u8; 1] = [0xCC];

                trace!("Creating int3 bytes for hook");

                // Hook the original function and place a jmp <shadow_copy_address>
                unsafe {
                    copy_nonoverlapping(
                        int3_shellcode.as_ptr(),
                        self.shadow_copy_address,
                        INT3_SIZE,
                    );
                }
            }
        };

        trace!("The hook has been installed successfully");
    }

    /// Provides a constant function to retrieve the address of the trampoline.
    ///
    /// ## Returns
    /// Returns the address of the trampoline as a mutable pointer to a 64-bit unsigned integer.
    pub const fn trampoline_address(&self) -> *mut u64 {
        self.trampoline.as_ptr() as _
    }
}
