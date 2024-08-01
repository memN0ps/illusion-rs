//! Facilitates capturing and managing guest CPU state for VMX operations.
//!
//! Provides mechanisms to capture the current state of general-purpose registers, RFLAGS, RSP, RIP, and XMM registers,
//! essential for virtualization tasks such as state saving/restoring during VM exits and entries. Suitable
//! for use in hypervisor development, allowing precise control and manipulation of guest CPU context.

use core::{arch::global_asm, fmt, mem};

extern "efiapi" {
    /// Captures the current state of general-purpose registers, RFLAGS, RSP, and RIP.
    ///
    /// Safely stores the current CPU state into the provided `GuestRegisters` struct. Intended
    /// for use in contexts where capturing the exact CPU state is necessary, such as before VM
    /// entry or after VM exit.
    ///
    /// # Arguments
    ///
    /// - `registers`: A mutable reference to a `GuestRegisters` struct where the CPU state
    /// will be stored.
    ///
    /// # Returns
    ///
    /// Returns `true` if the capture was successful, `false` otherwise. Currently always returns `true`.
    ///
    /// # Safety
    ///
    /// This function involves inline assembly and direct manipulation of register values, requiring
    /// careful consideration of calling context to ensure system stability.
    pub fn capture_registers(registers: &mut GuestRegisters) -> bool;
}

/// Represents the state of guest general-purpose registers along with RFLAGS, RSP, and RIP.
///
/// Stores the complete CPU state relevant for VM operations, including all general-purpose
/// registers and system flags. Useful for tasks requiring preservation of the CPU state, such
/// as context switching in a virtualized environment.
/// The guest register are required to be in this order: Table 28-3. Exit Qualification for Control-Register Accesses
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub xmm0: M128A,
    pub xmm1: M128A,
    pub xmm2: M128A,
    pub xmm3: M128A,
    pub xmm4: M128A,
    pub xmm5: M128A,
    pub xmm6: M128A,
    pub xmm7: M128A,
    pub xmm8: M128A,
    pub xmm9: M128A,
    pub xmm10: M128A,
    pub xmm11: M128A,
    pub xmm12: M128A,
    pub xmm13: M128A,
    pub xmm14: M128A,
    pub xmm15: M128A,
    pub original_lstar: u64,
    pub hook_lstar: u64,
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Default)]
pub struct M128A {
    pub low: u64,
    pub high: i64,
}

impl fmt::Debug for GuestRegisters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestRegisters {\n")?;

        // General-purpose registers in 4 columns
        write!(f, "  rax: {:#018x}, rcx: {:#018x}, rdx: {:#018x}, rbx: {:#018x}\n", self.rax, self.rcx, self.rdx, self.rbx)?;
        write!(f, "  rsp: {:#018x}, rbp: {:#018x}, rsi: {:#018x}, rdi: {:#018x}\n", self.rsp, self.rbp, self.rsi, self.rdi)?;
        write!(f, "  r8: {:#018x}, r9: {:#018x}, r10: {:#018x}, r11: {:#018x}\n", self.r8, self.r9, self.r10, self.r11)?;
        write!(f, "  r12: {:#018x}, r13: {:#018x}, r14: {:#018x}, r15: {:#018x}, rip: {:#018x}\n", self.r12, self.r13, self.r14, self.r15, self.rip)?;
        write!(f, "  rflags: {:#018x}\n", self.rflags)?;

        // XMM registers in 4 columns
        write!(f, "  xmm0: {:?}, xmm1: {:?}, xmm2: {:?}, xmm3: {:?}\n", self.xmm0, self.xmm1, self.xmm2, self.xmm3)?;
        write!(f, "  xmm4: {:?}, xmm5: {:?}, xmm6: {:?}, xmm7: {:?}\n", self.xmm4, self.xmm5, self.xmm6, self.xmm7)?;
        write!(f, "  xmm8: {:?}, xmm9: {:?}, xmm10: {:?}, xmm11: {:?}\n", self.xmm8, self.xmm9, self.xmm10, self.xmm11)?;
        write!(f, "  xmm12: {:?}, xmm13: {:?}, xmm14: {:?}, xmm15: {:?}\n", self.xmm12, self.xmm13, self.xmm14, self.xmm15)?;

        f.write_str("}")
    }
}

impl fmt::Debug for M128A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:#018x}, {:#018x})", self.low, self.high)
    }
}

global_asm!(
    r#"
// Captures current general purpose registers, RFLAGS, RSP, RIP, and XMM registers.
//
// extern "efiapi" fn capture_registers(registers: &mut GuestRegisters)
.global capture_registers
capture_registers:
    // Capture general purpose registers.
    mov     [rcx + {registers_rax}], rax
    mov     [rcx + {registers_rcx}], rcx
    mov     [rcx + {registers_rdx}], rdx
    mov     [rcx + {registers_rbx}], rbx
    mov     [rcx + {registers_rsp}], rsp
    mov     [rcx + {registers_rbp}], rbp
    mov     [rcx + {registers_rsi}], rsi
    mov     [rcx + {registers_rdi}], rdi
    mov     [rcx + {registers_r8}],  r8
    mov     [rcx + {registers_r9}],  r9
    mov     [rcx + {registers_r10}], r10
    mov     [rcx + {registers_r11}], r11
    mov     [rcx + {registers_r12}], r12
    mov     [rcx + {registers_r13}], r13
    mov     [rcx + {registers_r14}], r14
    mov     [rcx + {registers_r15}], r15

    // Capture RFLAGS.
    pushfq
    pop     rax
    mov     [rcx + {registers_rflags}], rax

    // Capture RSP.
    mov     rax, rsp
    add     rax, 8
    mov     [rcx + {registers_rsp}], rax

    // Capture RIP.
    mov     rax, [rsp]
    mov     [rcx + {registers_rip}], rax

    // Capture XMM registers.
    movaps  [rcx + {registers_xmm0}], xmm0
    movaps  [rcx + {registers_xmm1}], xmm1
    movaps  [rcx + {registers_xmm2}], xmm2
    movaps  [rcx + {registers_xmm3}], xmm3
    movaps  [rcx + {registers_xmm4}], xmm4
    movaps  [rcx + {registers_xmm5}], xmm5
    movaps  [rcx + {registers_xmm6}], xmm6
    movaps  [rcx + {registers_xmm7}], xmm7
    movaps  [rcx + {registers_xmm8}], xmm8
    movaps  [rcx + {registers_xmm9}], xmm9
    movaps  [rcx + {registers_xmm10}], xmm10
    movaps  [rcx + {registers_xmm11}], xmm11
    movaps  [rcx + {registers_xmm12}], xmm12
    movaps  [rcx + {registers_xmm13}], xmm13
    movaps  [rcx + {registers_xmm14}], xmm14
    movaps  [rcx + {registers_xmm15}], xmm15

    // Return false to indicate that the processor is not virtualized currently.
    xor rax, rax

    ret
"#,
    registers_rax = const mem::offset_of!(GuestRegisters, rax),
    registers_rcx = const mem::offset_of!(GuestRegisters, rcx),
    registers_rdx = const mem::offset_of!(GuestRegisters, rdx),
    registers_rbx = const mem::offset_of!(GuestRegisters, rbx),
    registers_rsp = const mem::offset_of!(GuestRegisters, rsp),
    registers_rbp = const mem::offset_of!(GuestRegisters, rbp),
    registers_rsi = const mem::offset_of!(GuestRegisters, rsi),
    registers_rdi = const mem::offset_of!(GuestRegisters, rdi),
    registers_r8  = const mem::offset_of!(GuestRegisters, r8),
    registers_r9  = const mem::offset_of!(GuestRegisters, r9),
    registers_r10 = const mem::offset_of!(GuestRegisters, r10),
    registers_r11 = const mem::offset_of!(GuestRegisters, r11),
    registers_r12 = const mem::offset_of!(GuestRegisters, r12),
    registers_r13 = const mem::offset_of!(GuestRegisters, r13),
    registers_r14 = const mem::offset_of!(GuestRegisters, r14),
    registers_r15 = const mem::offset_of!(GuestRegisters, r15),
    registers_rip = const mem::offset_of!(GuestRegisters, rip),
    registers_rflags = const mem::offset_of!(GuestRegisters, rflags),
    registers_xmm0 = const mem::offset_of!(GuestRegisters, xmm0),
    registers_xmm1 = const mem::offset_of!(GuestRegisters, xmm1),
    registers_xmm2 = const mem::offset_of!(GuestRegisters, xmm2),
    registers_xmm3 = const mem::offset_of!(GuestRegisters, xmm3),
    registers_xmm4 = const mem::offset_of!(GuestRegisters, xmm4),
    registers_xmm5 = const mem::offset_of!(GuestRegisters, xmm5),
    registers_xmm6 = const mem::offset_of!(GuestRegisters, xmm6),
    registers_xmm7 = const mem::offset_of!(GuestRegisters, xmm7),
    registers_xmm8 = const mem::offset_of!(GuestRegisters, xmm8),
    registers_xmm9 = const mem::offset_of!(GuestRegisters, xmm9),
    registers_xmm10 = const mem::offset_of!(GuestRegisters, xmm10),
    registers_xmm11 = const mem::offset_of!(GuestRegisters, xmm11),
    registers_xmm12 = const mem::offset_of!(GuestRegisters, xmm12),
    registers_xmm13 = const mem::offset_of!(GuestRegisters, xmm13),
    registers_xmm14 = const mem::offset_of!(GuestRegisters, xmm14),
    registers_xmm15 = const mem::offset_of!(GuestRegisters, xmm15),
);
