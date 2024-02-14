#![allow(dead_code)]

use {
    core::arch::asm,
    x86::{
        controlregs::{Cr0, Cr4, Xcr0},
        dtables::DescriptorTablePointer,
    },
    crate::error::HypervisorError,
};

/// Enable VMX operation.
pub fn vmxon(vmxon_region: u64) {
    unsafe { x86::bits64::vmx::vmxon(vmxon_region).unwrap() };
}

/// Disable VMX operation.
pub fn vmxoff() -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmxoff() } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMXOFFFailed),
    }
}

/// Clear VMCS.
pub fn vmclear(vmcs_region: u64) {
    unsafe { x86::bits64::vmx::vmclear(vmcs_region).unwrap() };
}

/// Load current VMCS pointer.
pub fn vmptrld(vmcs_region: u64) {
    unsafe { x86::bits64::vmx::vmptrld(vmcs_region).unwrap() }
}

/*
/// Return current VMCS pointer.
#[allow(dead_code)]
pub fn vmptrst() -> *const Vmcs {
    unsafe { x86::bits64::vmx::vmptrst().unwrap() as *const Vmcs }
}
*/

/// Read a specified field from a VMCS.
pub fn vmread(field: u32) -> u64 {
    unsafe { x86::bits64::vmx::vmread(field) }.unwrap_or(0)
}

/// Write to a specified field in a VMCS.
pub fn vmwrite<T: Into<u64>>(field: u32, val: T)
    where
        u64: From<T>,
{
    unsafe { x86::bits64::vmx::vmwrite(field, u64::from(val)) }.unwrap();
}


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