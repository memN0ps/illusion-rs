//! Facilitates capturing and managing guest CPU state for VMX operations.
//!
//! Provides mechanisms to capture the current state of general-purpose registers, RFLAGS, RSP, RIP, and XMM registers,
//! essential for virtualization tasks such as state saving/restoring during VM exits and entries. Suitable
//! for use in hypervisor development, allowing precise control and manipulation of guest CPU context.

use core::{arch::global_asm, fmt};

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
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
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
//static_assertions::const_assert_eq!(core::mem::size_of::<GuestRegisters>(), 0x190 /* 400 bytes */);

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
        write!(
            f,
            "  rax: {:#018x}, rbx: {:#018x}, rcx: {:#018x}, rdx: {:#018x}\n",
            self.rax, self.rbx, self.rcx, self.rdx
        )?;
        write!(
            f,
            "  rsi: {:#018x}, rdi: {:#018x}, rbp: {:#018x}, r8: {:#018x}\n",
            self.rsi, self.rdi, self.rbp, self.r8
        )?;
        write!(
            f,
            "  r9: {:#018x}, r10: {:#018x}, r11: {:#018x}, r12: {:#018x}\n",
            self.r9, self.r10, self.r11, self.r12
        )?;
        write!(
            f,
            "  r13: {:#018x}, r14: {:#018x}, r15: {:#018x}, rip: {:#018x}\n",
            self.r13, self.r14, self.r15, self.rip
        )?;
        write!(
            f,
            "  rsp: {:#018x}, rflags: {:#018x}\n",
            self.rsp, self.rflags
        )?;

        // XMM registers in 4 columns
        write!(
            f,
            "  xmm0: {:?}, xmm1: {:?}, xmm2: {:?}, xmm3: {:?}\n",
            self.xmm0, self.xmm1, self.xmm2, self.xmm3
        )?;
        write!(
            f,
            "  xmm4: {:?}, xmm5: {:?}, xmm6: {:?}, xmm7: {:?}\n",
            self.xmm4, self.xmm5, self.xmm6, self.xmm7
        )?;
        write!(
            f,
            "  xmm8: {:?}, xmm9: {:?}, xmm10: {:?}, xmm11: {:?}\n",
            self.xmm8, self.xmm9, self.xmm10, self.xmm11
        )?;
        write!(
            f,
            "  xmm12: {:?}, xmm13: {:?}, xmm14: {:?}, xmm15: {:?}\n",
            self.xmm12, self.xmm13, self.xmm14, self.xmm15
        )?;

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
// The module containing the `capture_registers` function.

// Offsets for each field in the GuestRegisters struct. These offsets are used
// to facilitate the direct manipulation of guest register values stored in memory.
.set registers_rax, 0x0
.set registers_rbx, 0x8
.set registers_rcx, 0x10
.set registers_rdx, 0x18
.set registers_rdi, 0x20
.set registers_rsi, 0x28
.set registers_rbp, 0x30
.set registers_r8,  0x38
.set registers_r9,  0x40
.set registers_r10, 0x48
.set registers_r11, 0x50
.set registers_r12, 0x58
.set registers_r13, 0x60
.set registers_r14, 0x68
.set registers_r15, 0x70
.set registers_rip, 0x78
.set registers_rsp, 0x80
.set registers_rflags, 0x88
.set registers_xmm0, 0x90
.set registers_xmm1, 0xA0
.set registers_xmm2, 0xB0
.set registers_xmm3, 0xC0
.set registers_xmm4, 0xD0
.set registers_xmm5, 0xE0
.set registers_xmm6, 0xF0
.set registers_xmm7, 0x100
.set registers_xmm8, 0x110
.set registers_xmm9, 0x120
.set registers_xmm10, 0x130
.set registers_xmm11, 0x140
.set registers_xmm12, 0x150
.set registers_xmm13, 0x160
.set registers_xmm14, 0x170
.set registers_xmm15, 0x180

// Captures current general purpose registers, RFLAGS, RSP, RIP, and XMM registers.
//
// extern "efiapi" fn capture_registers(registers: &mut GuestRegisters)
.global capture_registers
capture_registers:
    // Capture general purpose registers.
    mov     [rcx + registers_rax], rax
    mov     [rcx + registers_rbx], rbx
    mov     [rcx + registers_rcx], rcx
    mov     [rcx + registers_rdx], rdx
    mov     [rcx + registers_rsi], rsi
    mov     [rcx + registers_rdi], rdi
    mov     [rcx + registers_rbp], rbp
    mov     [rcx + registers_r8],  r8
    mov     [rcx + registers_r9],  r9
    mov     [rcx + registers_r10], r10
    mov     [rcx + registers_r11], r11
    mov     [rcx + registers_r12], r12
    mov     [rcx + registers_r13], r13
    mov     [rcx + registers_r14], r14
    mov     [rcx + registers_r15], r15

    // Capture RFLAGS.
    pushfq
    pop     rax
    mov     [rcx + registers_rflags], rax

    // Capture RSP.
    mov     rax, rsp
    add     rax, 8
    mov     [rcx + registers_rsp], rax

    // Capture RIP.
    mov     rax, [rsp]
    mov     [rcx + registers_rip], rax

    // Capture XMM registers.
    movaps  [rcx + registers_xmm0], xmm0
    movaps  [rcx + registers_xmm1], xmm1
    movaps  [rcx + registers_xmm2], xmm2
    movaps  [rcx + registers_xmm3], xmm3
    movaps  [rcx + registers_xmm4], xmm4
    movaps  [rcx + registers_xmm5], xmm5
    movaps  [rcx + registers_xmm6], xmm6
    movaps  [rcx + registers_xmm7], xmm7
    movaps  [rcx + registers_xmm8], xmm8
    movaps  [rcx + registers_xmm9], xmm9
    movaps  [rcx + registers_xmm10], xmm10
    movaps  [rcx + registers_xmm11], xmm11
    movaps  [rcx + registers_xmm12], xmm12
    movaps  [rcx + registers_xmm13], xmm13
    movaps  [rcx + registers_xmm14], xmm14
    movaps  [rcx + registers_xmm15], xmm15

    // Return false to indicate that the processor is not virtualized currently.
    xor rax, rax

    ret
"#
);
