//! This library provides functionality to create and manage hooks at the instruction
//! level using hardware-assisted virtualization features. It supports creating trampoline
//! shellcode for safely redirecting execution flow to custom handlers while preserving
//! the original execution context.

use {
    crate::error::HypervisorError,
    alloc::{boxed::Box, string::String, vec::Vec},
    iced_x86::{
        BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Encoder, FlowControl,
        Formatter, Instruction, InstructionBlock, NasmFormatter, OpKind,
    },
    log::*,
};

/// Length in bytes of the shellcode used to perform a jump (JMP) hook.
pub const JMP_SHELLCODE_LEN: usize = 14;

/// Length in bytes of the shellcode for a breakpoint (INT3) hook.
pub const BP_SHELLCODE_LEN: usize = 1;

/// Types of hooks that can be created by this library.
pub enum HookType {
    /// Jump-based hook, which redirects execution flow to a custom handler.
    Jmp,

    /// Breakpoint-based hook, utilizing the INT3 instruction to trigger a breakpoint exception.
    Breakpoint,
}

/// Represents a hook on a specific function or memory address.
pub struct Hook {
    /// Memory address of the target function or code block to be hooked.
    target_address: u64,

    /// Optional: Copy of the target memory address, allowing for safer manipulation.
    target_address_copy: Option<u64>,

    /// Memory address of the custom handler function that the hook redirects to.
    hook_address: u64,

    /// Dynamically generated trampoline code to ensure original code execution can continue.
    trampoline: Box<[u8]>,

    /// Type of the hook, determining the method of interception.
    hook_type: HookType,
}

impl Hook {
    /// Constructs a new hook with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `target_address`: Address of the code to hook.
    /// * `target_address_copy`: Optional address of a copy of the target code.
    /// * `hook_address`: Address of the hook handler function.
    /// * `hook_type`: Type of the hook (JMP or Breakpoint).
    ///
    /// # Returns
    ///
    /// * An initialized `Hook` instance, if successful.
    pub fn new(
        target_address: u64,
        target_address_copy: Option<u64>,
        hook_address: u64,
        hook_type: HookType,
    ) -> Option<Self> {
        // Generate the appropriate trampoline based on the hook type.
        let trampoline = match hook_type {
            HookType::Jmp => Self::trampoline_shellcode(target_address, JMP_SHELLCODE_LEN).ok()?,
            HookType::Breakpoint => {
                Self::trampoline_shellcode(target_address, BP_SHELLCODE_LEN).ok()?
            }
        };

        Some(Self {
            target_address,
            target_address_copy,
            hook_address,
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
    /// * A `Result` containing the generated trampoline shellcode or an error.
    fn trampoline_shellcode(
        target_address: u64,
        required_size: usize,
    ) -> Result<Box<[u8]>, HypervisorError> {
        // Attempt to read the original code from the target address.
        let target_bytes = unsafe {
            core::slice::from_raw_parts(
                target_address as *mut u8,
                usize::max(required_size * 2, 15), // Read more than needed to find valid instructions.
            )
        };

        trace!("Original code:");
        Self::disassemble(target_bytes, target_address);

        // Decode the instructions at the target address to ensure we can safely relocate them.
        let original_code: Vec<u8> = target_bytes.to_vec();
        let mut decoder = Decoder::with_ip(
            64,
            original_code.as_slice(),
            target_address,
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

            instructions_to_relocate.push(instr);
            total_bytes += instr.len();

            // Create the new trampoline instruction
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
            Self::create_jmp_instruction(target_address + total_bytes as u64);

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
    fn enable_hook(&mut self) -> Result<(), HypervisorError> {
        // Generate the JMP instruction to redirect execution to the hook handler.
        let hook_type = Self::create_jmp_instruction(self.hook_address);

        let mut encoder = Encoder::new(64);

        // Check if we want to hook the original function or a copy of the function
        let address = match self.target_address_copy {
            Some(_) => self.target_address_copy.unwrap(),
            None => self.target_address,
        };

        // Encode the JMP instruction to be written into the target address.
        encoder.encode(&hook_type, self.target_address)?;

        // Get the encoded bytes
        let buffer = encoder.take_buffer();

        // Check if the hook length is JMP or INT3
        let buffer_length = match self.hook_type {
            HookType::Jmp => JMP_SHELLCODE_LEN,
            HookType::Breakpoint => BP_SHELLCODE_LEN,
        };

        // Copy the encoded bytes (Might need to use another function to perform the copy??? maybe not)
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
    /// * The generated `Instruction` object.
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
    /// * The address of the trampoline as a `*mut u64`.
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
