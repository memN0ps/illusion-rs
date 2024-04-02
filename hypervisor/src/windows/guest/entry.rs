use {
    crate::windows::{guest::agent::HostGuestAgentContext, nt::types::WindowsKTrapFrame},
    core::arch::global_asm,
};

/// The initial stack for the guest agent, ensuring proper alignment for XMM registers
///    +-----------------+
///    |     XMM Regs    | <- Space for XMM registers, rsp points to start of this area
///    +-----------------+
///    |      Flags      |
///    +-----------------+
///    |     General     |
///    |   Purpose Regs  |
///    +-----------------+
///    | Trap Frame Area |
///    +-----------------+
#[repr(C, align(16))]
pub struct InitialGuestAgentStack {
    /// Space for XMM registers (xmm0-xmm5 in this example, adjust as necessary). Each XMM register is 128 bits
    pub xmm_registers: [u128; 6],

    /// Saved Flags (RFLAGS)
    pub flags: u64,

    /// Saved general-purpose registers
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,

    /// Trap frame area
    pub trap_frame: WindowsKTrapFrame,

    /// The HostGuestAgentContext for the guest agent.
    pub guest_agent_context: HostGuestAgentContext,
}

extern "C" {
    /// Credits Satoshi Tanda: https://gist.github.com/tandasat/bf0189952f113518f75c4f008c1e8d04#file-guestagentasm-asm
    pub fn asm_guest_agent_entry_point() -> !;
}

// Credits Satoshi Tanda: https://gist.github.com/tandasat/bf0189952f113518f75c4f008c1e8d04#file-guestagentasm-asm
global_asm!(
    r#"
.equ KTRAP_FRAME_SIZE, 0x190

.text

.global asm_guest_agent_entry_point
asm_guest_agent_entry_point:
    // Adjust the stack for context save area.
    sub rsp, KTRAP_FRAME_SIZE

    // Save general-purpose registers.
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    // Save Flags register.
    pushfq

    // Allocate space and save XMM registers.
    sub     rsp, 0x60
    movaps  [rsp +  0x00], xmm0
    movaps  [rsp +  0x10], xmm1
    movaps  [rsp +  0x20], xmm2
    movaps  [rsp +  0x30], xmm3
    movaps  [rsp +  0x40], xmm4
    movaps  [rsp +  0x50], xmm5

    // Prepare for the function call.
    mov     rcx, rsp
    call    guest_agent_entry_point

    // Restore XMM registers.
    movaps  xmm0, [rsp +  0x00]
    movaps  xmm1, [rsp +  0x10]
    movaps  xmm2, [rsp +  0x20]
    movaps  xmm3, [rsp +  0x30]
    movaps  xmm4, [rsp +  0x40]
    movaps  xmm5, [rsp +  0x50]
    add     rsp, 0x60

    // Restore Flags and general-purpose registers.
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    // Adjust the stack back.
    add rsp, KTRAP_FRAME_SIZE

    // RestoreGuestContext (1338)
    mov rax, 0x1338
    
    // Return to the hypervisor.
    vmcall
"#
);
