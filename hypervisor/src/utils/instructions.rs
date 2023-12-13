#![allow(dead_code)]

use {
    core::arch::asm,
    x86::{
        controlregs::{Cr0, Cr4, Xcr0},
        dtables::DescriptorTablePointer,
    },
};

/// Write to Extended Control Register XCR0. Only supported if CR4_ENABLE_OS_XSAVE is set.
pub fn xsetbv(val: Xcr0) {
    unsafe { x86::controlregs::xcr0_write(val) };
}

/// Write back all modified cache contents to memory and invalidate the caches.
#[inline(always)]
pub fn wbinvd() {
    unsafe {
        asm!("wbinvd", options(nostack, nomem));
    }
}

/// Returns the timestamp counter value.
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Reads an MSR.
pub fn rdmsr(msr: u32) -> u64 {
    unsafe { x86::msr::rdmsr(msr) }
}

/// Writes a value to an MSR.
pub fn wrmsr(msr: u32, value: u64) {
    unsafe { x86::msr::wrmsr(msr, value) };
}

/// Reads the CR0 register.
pub fn cr0() -> Cr0 {
    unsafe { x86::controlregs::cr0() }
}

/// Writes a value to the CR0 register.
pub fn cr0_write(val: Cr0) {
    unsafe { x86::controlregs::cr0_write(val) };
}

/// Reads the CR3 register.
pub fn cr3() -> u64 {
    unsafe { x86::controlregs::cr3() }
}

/// Reads the CR4 register.
pub fn cr4() -> Cr4 {
    unsafe { x86::controlregs::cr4() }
}

/// Writes a value to the CR4 register.
pub fn cr4_write(val: Cr4) {
    unsafe { x86::controlregs::cr4_write(val) };
}

/// Disables maskable interrupts.
pub fn cli() {
    unsafe { x86::irq::disable() };
}

/// Halts execution of the processor.
pub fn hlt() {
    unsafe { x86::halt() };
}

/// Reads 8-bits from an IO port.
pub fn inb(port: u16) -> u8 {
    unsafe { x86::io::inb(port) }
}

/// Writes 8-bits to an IO port.
pub fn outb(port: u16, val: u8) {
    unsafe { x86::io::outb(port, val) };
}

/// Reads the IDTR register.
pub fn sidt() -> DescriptorTablePointer<u64> {
    let mut idtr = DescriptorTablePointer::<u64>::default();
    unsafe { x86::dtables::sidt(&mut idtr) };
    idtr
}

/// Reads the GDTR.
pub fn sgdt() -> DescriptorTablePointer<u64> {
    let mut gdtr = DescriptorTablePointer::<u64>::default();
    unsafe { x86::dtables::sgdt(&mut gdtr) };
    gdtr
}

/// Read the RIP register (instruction pointer).
#[inline(always)]
pub fn rip() -> u64 {
    let rip: u64;
    unsafe {
        asm!("leaq 0(%rip), {0}", out(reg) rip, options(att_syntax));
    }
    rip
}

/// Read the RSP register (stack pointer register).
#[inline(always)]
pub fn rsp() -> u64 {
    let rsp: u64;
    unsafe {
        asm!("mov %rsp, {0}", out(reg) rsp, options(att_syntax));
    }
    rsp
}

/// Read the RBP register (base pointer register).
#[inline(always)]
pub fn rbp() -> u64 {
    let rbp: u64;
    unsafe {
        asm!("mov %rbp, {0}", out(reg) rbp, options(att_syntax));
    }
    rbp
}

/// Read the RAX register (accumulator register).
#[inline(always)]
pub fn rax() -> u64 {
    let rax: u64;
    unsafe {
        asm!("mov %rax, {0}", out(reg) rax, options(att_syntax));
    }
    rax
}

/// Read the RBX register (base register).
#[inline(always)]
pub fn rbx() -> u64 {
    let rbx: u64;
    unsafe {
        asm!("mov %rbx, {0}", out(reg) rbx, options(att_syntax));
    }
    rbx
}

/// Read the RCX register (counter register).
#[inline(always)]
pub fn rcx() -> u64 {
    let rcx: u64;
    unsafe {
        asm!("mov %rcx, {0}", out(reg) rcx, options(att_syntax));
    }
    rcx
}

/// Read the RDX register (data register).
#[inline(always)]
pub fn rdx() -> u64 {
    let rdx: u64;
    unsafe {
        asm!("mov %rdx, {0}", out(reg) rdx, options(att_syntax));
    }
    rdx
}

/// Read the RDI register (destination index register).
#[inline(always)]
pub fn rdi() -> u64 {
    let rdi: u64;
    unsafe {
        asm!("mov %rdi, {0}", out(reg) rdi, options(att_syntax));
    }
    rdi
}

/// Read the RSI register (source index register).
#[inline(always)]
pub fn rsi() -> u64 {
    let rsi: u64;
    unsafe {
        asm!("mov %rsi, {0}", out(reg) rsi, options(att_syntax));
    }
    rsi
}

/// Read the R8 register (general-purpose register 8).
#[inline(always)]
pub fn r8() -> u64 {
    let r8: u64;
    unsafe {
        asm!("mov %r8, {0}", out(reg) r8, options(att_syntax));
    }
    r8
}

/// Read the R9 register (general-purpose register 9).
#[inline(always)]
pub fn r9() -> u64 {
    let r9: u64;
    unsafe {
        asm!("mov %r9, {0}", out(reg) r9, options(att_syntax));
    }
    r9
}

/// Read the R10 register (general-purpose register 10).
#[inline(always)]
pub fn r10() -> u64 {
    let r10: u64;
    unsafe {
        asm!("mov %r10, {0}", out(reg) r10, options(att_syntax));
    }
    r10
}

/// Read the R11 register (general-purpose register 11).
#[inline(always)]
pub fn r11() -> u64 {
    let r11: u64;
    unsafe {
        asm!("mov %r11, {0}", out(reg) r11, options(att_syntax));
    }
    r11
}

/// Read the R12 register (general-purpose register 12).
#[inline(always)]
pub fn r12() -> u64 {
    let r12: u64;
    unsafe {
        asm!("mov %r12, {0}", out(reg) r12, options(att_syntax));
    }
    r12
}

/// Read the R13 register (general-purpose register 13).
#[inline(always)]
pub fn r13() -> u64 {
    let r13: u64;
    unsafe {
        asm!("mov %r13, {0}", out(reg) r13, options(att_syntax));
    }
    r13
}

/// Read the R14 register (general-purpose register 14).
#[inline(always)]
pub fn r14() -> u64 {
    let r14: u64;
    unsafe {
        asm!("mov %r14, {0}", out(reg) r14, options(att_syntax));
    }
    r14
}

/// Read the R15 register (general-purpose register 15).
#[inline(always)]
pub fn r15() -> u64 {
    let r15: u64;
    unsafe {
        asm!("mov %r15, {0}", out(reg) r15, options(att_syntax));
    }
    r15
}
