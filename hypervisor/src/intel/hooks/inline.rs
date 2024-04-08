use {core::ptr::copy_nonoverlapping, log::*};

/// Enum to define the types of inline hooks we support.
#[derive(Debug, Clone, Copy)]
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
    ///
    /// # Returns
    ///
    /// * `Self` - The new hook configuration.
    pub fn new(shadow_function_pa: *mut u8, hook_type: InlineHookType) -> Self {
        trace!("Creating a new hook configuration");

        Self {
            shadow_function_pa,
            hook_type,
        }
    }

    /// Performs a detour or hook, from the source to the destination function, by overwriting it with either int3, cpuid, or vmcall instructions.
    pub fn detour64(&mut self) {
        trace!("Hook Type: {:?}", self.hook_type);

        match self.hook_type {
            InlineHookType::Int3 => {
                // Shellcode for the int3 (Breakpoint) instruction
                let int3_shellcode: [u8; 1] = [0xCC]; // int3 instruction

                trace!("Creating int3 bytes for hook");

                // Overwrite the original function with the int3 instruction
                unsafe {
                    copy_nonoverlapping(
                        int3_shellcode.as_ptr(),
                        self.shadow_function_pa,
                        int3_shellcode.len(),
                    );
                }
            }
            InlineHookType::Cpuid => {
                // Shellcode for the cpuid instruction
                let cpuid_shellcode: [u8; 2] = [0x0F, 0xA2]; // cpuid instruction

                trace!("Creating cpuid bytes for hook");

                // Overwrite the original function with the cpuid instruction
                unsafe {
                    copy_nonoverlapping(
                        cpuid_shellcode.as_ptr(),
                        self.shadow_function_pa,
                        cpuid_shellcode.len(),
                    );
                }
            }
            InlineHookType::Vmcall => {
                // Shellcode for the vmcall instruction
                let vmcall_shellcode: [u8; 3] = [0x0F, 0x01, 0xC1]; // vmcall instruction

                trace!("Creating vmcall bytes for hook");

                // Overwrite the original function with the vmcall instruction
                unsafe {
                    copy_nonoverlapping(
                        vmcall_shellcode.as_ptr(),
                        self.shadow_function_pa,
                        vmcall_shellcode.len(),
                    );
                }
            }
        }

        trace!("The hook has been installed successfully");
    }
}
