use {core::ptr::copy_nonoverlapping, log::*};

/// Enum to define the types of inline hooks we support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineHookType {
    Int3,
    Cpuid,
    Vmcall,
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
    pub fn new(shadow_function_pa: *mut u8, guest_function_va: *mut u8, hook_handler: *mut u8, hook_type: InlineHookType) -> Self {
        trace!("Creating a new hook configuration");

        Self {
            shadow_function_pa,
            guest_function_va,
            hook_type,
            hook_handler,
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
        };

        unsafe {
            // Then, overwrite the target location with the hook
            copy_nonoverlapping(shellcode.as_ptr(), self.shadow_function_pa, shellcode.len());
        }

        trace!("The hook has been installed successfully");
    }

    /// Returns the size of the hook code in bytes based on the hook type.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the hook code in bytes.
    pub fn hook_size(&self) -> usize {
        match self.hook_type {
            InlineHookType::Int3 => 1,   // int3 is 1 byte
            InlineHookType::Cpuid => 2,  // cpuid is 2 bytes
            InlineHookType::Vmcall => 3, // vmcall is 3 bytes
        }
    }
}
