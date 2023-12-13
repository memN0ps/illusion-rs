#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use static_assertions::const_assert_eq;

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

pub type CONTEXT_FLAGS = u32;

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    // https://docs.rs/windows-sys/0.52.0/windows_sys/Win32/System/Diagnostics/Debug/struct.CONTEXT.html
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: CONTEXT_FLAGS,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

impl CONTEXT {
    /// Outputs the processor's context for debugging purposes.
    pub fn dump_context(context: &CONTEXT) {
        /*
        log::info!("P1Home: {:#x}", context.P1Home);
        log::info!("P2Home: {:#x}", context.P2Home);
        log::info!("P3Home: {:#x}", context.P3Home);
        log::info!("P4Home: {:#x}", context.P4Home);
        log::info!("P5Home: {:#x}", context.P5Home);
        log::info!("P6Home: {:#x}", context.P6Home);
        log::info!("ContextFlags: {:#x}", context.ContextFlags);
        log::info!("MxCsr: {:#x}", context.MxCsr);
        */

        log::info!("SegCs: {:#x}", context.SegCs);
        log::info!("SegDs: {:#x}", context.SegDs);
        log::info!("SegEs: {:#x}", context.SegEs);
        log::info!("SegFs: {:#x}", context.SegFs);
        log::info!("SegGs: {:#x}", context.SegGs);
        log::info!("SegSs: {:#x}", context.SegSs);
        log::info!("EFlags: {:#x}", context.EFlags);
        log::info!("Dr0: {:#x}", context.Dr0);
        log::info!("Dr1: {:#x}", context.Dr1);
        log::info!("Dr2: {:#x}", context.Dr2);
        log::info!("Dr3: {:#x}", context.Dr3);
        log::info!("Dr6: {:#x}", context.Dr6);
        log::info!("Dr7: {:#x}", context.Dr7);
        log::info!("Rax: {:#x}", context.Rax);
        log::info!("Rcx: {:#x}", context.Rcx);
        log::info!("Rdx: {:#x}", context.Rdx);
        log::info!("Rbx: {:#x}", context.Rbx);
        log::info!("Rsp: {:#x}", context.Rsp);
        log::info!("Rbp: {:#x}", context.Rbp);
        log::info!("Rsi: {:#x}", context.Rsi);
        log::info!("Rdi: {:#x}", context.Rdi);
        log::info!("R8: {:#x}", context.R8);
        log::info!("R9: {:#x}", context.R9);
        log::info!("R10: {:#x}", context.R10);
        log::info!("R11: {:#x}", context.R11);
        log::info!("R12: {:#x}", context.R12);
        log::info!("R13: {:#x}", context.R13);
        log::info!("R14: {:#x}", context.R14);
        log::info!("R15: {:#x}", context.R15);
        log::info!("Rip: {:#x}", context.Rip);

        /*
        // Note: I'm skipping the __bindgen_anon_1 field as it might be a complex type.
        // If needed, you can add print statements for its subfields.
        for (i, vec_reg) in context.VectorRegister.iter().enumerate() {
            log::info!(
                "VectorRegister[{}]: Low: {:#x}, High: {:#x}",
                i, vec_reg.Low, vec_reg.High
            );
        }

        log::info!("VectorControl: {:#x}", context.VectorControl);
        log::info!("DebugControl: {:#x}", context.DebugControl);
        log::info!("LastBranchToRip: {:#x}", context.LastBranchToRip);
        log::info!("LastBranchFromRip: {:#x}", context.LastBranchFromRip);
        log::info!("LastExceptionToRip: {:#x}", context.LastExceptionToRip);
        log::info!("LastExceptionFromRip: {:#x}", context.LastExceptionFromRip);
        */
    }
}

/// Represents the state of guest registers during a VM exit.
///
/// This structure is used to capture the state of all general-purpose registers,
/// of a virtualized guest when a VM exit occurs.
/// It allows the hypervisor to inspect or modify the guest's state as necessary
/// before resuming guest execution.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4.1 Guest Register State
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
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
    // XMM registers (each represented as two u64 for 16-byte alignment)
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
}
const_assert_eq!(
    core::mem::size_of::<GuestRegisters>(),
    0x190 /* 400 bytes */
);

#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}
