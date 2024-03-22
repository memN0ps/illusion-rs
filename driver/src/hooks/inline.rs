//! Provides utilities for inline hooking of functions, allowing redirection of function calls.
//! It includes creating and managing hooks with support for different types, enabling and disabling hooks,
//! and managing the necessary memory and page table entries.
//! Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/utils/function_hook.rs

use {
    crate::error::HypervisorError,
    alloc::{boxed::Box, string::String, vec::Vec},
    iced_x86::{
        BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, FlowControl,
        Formatter, Instruction, InstructionBlock, NasmFormatter, OpKind,
    },
    log::*,
};

/// Length in bytes of the shellcode used to perform a jump (JMP) inline hook.
pub const JMP_SHELLCODE_LEN: usize = 14;

/// Length in bytes of the shellcode for a breakpoint (INT3) inline hook.
pub const BP_SHELLCODE_LEN: usize = 1;

/// Types of inline hooks that can be created by this library.
pub enum InlineHookType {
    /// Jump-based inline hook, which redirects execution flow to a custom handler.
    Jmp,

    /// Breakpoint-based inline hook, utilizing the INT3 instruction to trigger a breakpoint exception.
    Breakpoint,
}

/// Represents an inline hook on a specific function or memory address.
pub struct InlineHook {
    /// Memory address of the target function or code block to be hooked.
    pub original_va: u64,

    /// Optional: Copy of the target memory address, allowing for safer manipulation.
    pub shadow_va: Option<u64>,

    /// Memory address of the custom handler function that the inline hook redirects to.
    pub hook_handler: u64,

    /// Dynamically generated trampoline code to ensure original code execution can continue.
    pub trampoline: Box<[u8]>,

    /// Type of the inline hook, determining the method of interception.
    pub hook_type: InlineHookType,
}

impl InlineHook {
    /// Constructs a new hook with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `original_va`: Address of the code to hook.
    /// * `shadow_va`: Optional address of a copy of the target code.
    /// * `hook_handler`: Address of the hook handler function.
    /// * `hook_type`: Type of the hook (JMP or Breakpoint).
    ///
    /// # Returns
    ///
    /// * An `Option<Self>` containing the constructed hook if successful.
    pub fn new(
        original_va: u64,
        shadow_va: Option<u64>,
        hook_handler: u64,
        hook_type: InlineHookType,
    ) -> Option<Self> {
        // Generate the appropriate trampoline based on the hook type.
        let trampoline = match hook_type {
            InlineHookType::Jmp => Self::trampoline_shellcode(original_va, JMP_SHELLCODE_LEN).ok()?,
            InlineHookType::Breakpoint => {
                Self::trampoline_shellcode(original_va, BP_SHELLCODE_LEN).ok()?
            }
        };

        Some(Self {
            original_va,
            shadow_va,
            hook_handler,
            trampoline,
            hook_type,
        })
    }

    /// Generates trampoline shellcode for safely executing the original code before/after the hook.
    ///
    /// This function reads the target code, creates a copy of the necessary instructions,
    /// and appends a jump back to the original code to ensure smooth execution flow.
    ///
    /// # Arguments
    ///
    /// *  `target_address`: Address of the code to generate a trampoline for.
    /// *  `required_size`: Required size of the trampoline shellcode.
    ///
    /// # Returns
    ///
    /// * A `Result<Box<[u8]>, HypervisorError>` containing the trampoline shellcode if successful.
    fn trampoline_shellcode(
        original_va: u64,
        required_size: usize,
    ) -> Result<Box<[u8]>, HypervisorError> {
        // Attempt to read the original code from the target address.
        let target_bytes = unsafe {
            core::slice::from_raw_parts(
                original_va as *mut u8,
                usize::max(required_size * 2, 15), // Read more than needed to find valid instructions.
            )
        };

        trace!("Original code:");
        Self::disassemble(target_bytes, original_va);

        // Decode the instructions at the target address to ensure we can safely relocate them.
        let original_code: Vec<u8> = target_bytes.to_vec();
        let mut decoder = Decoder::with_ip(
            64,
            original_code.as_slice(),
            original_va,
            DecoderOptions::NONE,
        );

        // Collect enough instructions to relocate, ensuring space for a JMP.
        let mut total_bytes = 0;
        let mut instructions_to_relocate: Vec<Instruction> = Vec::new();

        // Decode instructions until we have enough space for our JMP
        for instr in &mut decoder {
            // Check for invalid instructions to avoid corrupting execution flow.
            if instr.is_invalid() {
                return Err(HypervisorError::InvalidBytes);
            }

            if total_bytes >= required_size {
                break;
            }

            // Create the new trampoline instruction
            instructions_to_relocate.push(instr);
            total_bytes += instr.len();

            match instr.flow_control() {
                FlowControl::Next | FlowControl::Return => {}
                FlowControl::Call
                | FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectCall => {
                    // return Err(HypervisorError::RelativeInstruction);
                }
                FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend
                | FlowControl::Exception => {
                    return Err(HypervisorError::UnsupportedInstruction);
                }
            };
        }

        // Ensure we have collected enough bytes to place our hook.
        if total_bytes < required_size {
            return Err(HypervisorError::NotEnoughBytes);
        }

        // Ensure we have collected at least one instruction to relocate.
        if instructions_to_relocate.is_empty() {
            return Err(HypervisorError::NoInstructions);
        }

        // Append a JMP instruction to jump back to the original code after executing the hook.
        let jmp_back_instruction =
            Self::create_jmp_instruction(original_va + total_bytes as u64);

        instructions_to_relocate.push(jmp_back_instruction);

        // Allocate new memory and initialize for the trampoline and encode the instructions.
        let mut trampoline = Box::new_uninit_slice(instructions_to_relocate.len());

        // Encode the relocated instructions, fixing any relative addresses as needed.
        let block =
            InstructionBlock::new(&instructions_to_relocate, trampoline.as_mut_ptr() as u64);
        let encoded =
            BlockEncoder::encode(decoder.bitness(), block, BlockEncoderOptions::NONE)?.code_buffer;

        // Copy the encoded bytes
        unsafe {
            core::ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                trampoline.as_mut_ptr() as _,
                encoded.len(),
            )
        };

        let trampoline = unsafe { trampoline.assume_init() };

        // Disassemble the moved code
        trace!("Moved code:");
        Self::disassemble(encoded.as_slice(), trampoline.as_ptr() as _);

        // Return the encoded instructions as the trampoline shellcode.
        Ok(trampoline)
    }

    /// Enables the hook by inserting a JMP or INT3 instruction at the target address.
    ///
    /// This function overwrites the beginning of the target code with a jump to the hook handler,
    /// effectively redirecting execution flow.
    ///
    /// # Returns
    ///
    /// * A `Result<(), HypervisorError>` indicating success or failure of the hook activation.
    pub fn enable(&mut self) -> Result<(), HypervisorError> {
        // Generate the JMP instruction to redirect execution to the hook handler.
        let hook_type = Self::create_jmp_instruction(self.hook_handler);

        let mut encoder = Encoder::new(64);

        // Check if we want to hook the original function or a copy of the function
        let address = match self.shadow_va {
            Some(_) => self.shadow_va.unwrap(),
            None => self.original_va,
        };

        // Encode the JMP instruction to be written into the target address.
        encoder.encode(&hook_type, self.original_va)?;

        // Get the encoded bytes
        let buffer = encoder.take_buffer();

        // Check if the hook length is JMP or INT3
        let buffer_length = match self.hook_type {
            InlineHookType::Jmp => JMP_SHELLCODE_LEN,
            InlineHookType::Breakpoint => BP_SHELLCODE_LEN,
        };

        // Copy the encoded bytes to the target address
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), address as *mut u8, buffer_length)
        };

        // Disassemble it
        trace!("Original + patched code:");
        Self::disassemble(buffer.as_slice(), address);

        Ok(())
    }

    /// Creates a JMP instruction targeting a specific address.
    ///
    /// This helper function generates a JMP instruction that can be used to redirect execution flow.
    ///
    /// # Arguments
    ///
    /// * `target_address`: The address to jump to.
    ///
    /// # Returns
    ///
    /// * An `Instruction` representing the JMP instruction.
    fn create_jmp_instruction(target_address: u64) -> Instruction {
        let mut jmp_instr = Instruction::new();
        jmp_instr.set_code(Code::Jmp_rel32_64);
        jmp_instr.set_op0_kind(OpKind::Immediate64);
        jmp_instr.set_near_branch64(target_address);
        jmp_instr
    }

    /// Retrieves the address of the trampoline code.
    ///
    /// This function allows other components to obtain the starting address of the
    /// trampoline shellcode, facilitating execution flow redirection.
    ///
    /// # Returns
    ///
    /// * A mutable pointer to the trampoline shellcode.
    pub const fn trampoline_address(&self) -> *mut u64 {
        self.trampoline.as_ptr() as *mut u64
    }

    /// Disassembles and logs the instructions at a given memory address.
    ///
    /// This debugging function prints the assembly representation of code at a specific address.
    ///
    /// # Arguments
    ///
    /// * `data`: Byte slice containing the instructions to disassemble.
    /// * `ip`: Instruction pointer address where the byte slice starts.
    fn disassemble(data: &[u8], ip: u64) {
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();
        let mut decoder = Decoder::with_ip(64, data, ip, DecoderOptions::NONE);

        for instruction in &mut decoder {
            output.clear();
            formatter.format(&instruction, &mut output);
            trace!("{:016X} {}", instruction.ip(), output);
        }
        trace!("");
    }
}
