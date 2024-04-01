//! Facilitates capturing and managing guest CPU state for VMX operations.
//!
//! Provides mechanisms to capture the current state of general-purpose registers, RFLAGS, RSP, and RIP,
//! essential for virtualization tasks such as state saving/restoring during VM exits and entries. Suitable
//! for use in hypervisor development, allowing precise control and manipulation of guest CPU context.

use core::arch::global_asm;

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
///
/// Fields:
/// - `rax`, `rbx`, `rcx`, etc.: General-purpose registers.
/// - `rflags`: Status flags register.
/// - `rsp`: Stack pointer register.
/// - `rip`: Instruction pointer register.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
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
    pub rflags: u64,
    pub rsp: u64,
    pub rip: u64,
    pub original_lstar: u64,
    pub hook_lstar: u64,
    pub command_number: u64,
}

global_asm!(
    r#"
// The module containing the `capture_registers` function.

// Offsets to each field in the GuestRegisters struct.
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
.set registers_rflags, 0x78
.set registers_rsp, 0x80
.set registers_rip, 0x88

// Captures current general purpose registers, RFLAGS, RSP, and RIP.
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

    // Capture RFLAGS, RSP, and RIP.
    pushfq
    pop     rax
    mov     [rcx + registers_rflags], rax

    mov     rax, rsp
    add     rax, 8
    mov     [rcx + registers_rsp], rax

    mov     rax, [rsp]
    mov     [rcx + registers_rip], rax

    xor rax, rax

    ret
"#
);
