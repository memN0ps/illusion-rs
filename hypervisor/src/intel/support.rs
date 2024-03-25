#![allow(dead_code)]

use {
    crate::{
        error::HypervisorError,
        intel::{paging::PageTables, vmcs::Vmcs},
    },
    core::arch::asm,
    x86::vmx::vmcs,
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

/// Return current VMCS pointer.
pub fn vmptrst() -> *const Vmcs {
    unsafe { x86::bits64::vmx::vmptrst().unwrap() as *const Vmcs }
}

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
pub fn xsetbv(val: x86::controlregs::Xcr0) {
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
pub fn cr0() -> x86::controlregs::Cr0 {
    unsafe { x86::controlregs::cr0() }
}

/// Writes a value to the CR0 register.
pub fn cr0_write(val: x86::controlregs::Cr0) {
    unsafe { x86::controlregs::cr0_write(val) };
}

/// Reads the CR3 register.
pub fn cr3() -> u64 {
    unsafe { x86::controlregs::cr3() }
}

/// Reads the CR4 register.
pub fn cr4() -> x86::controlregs::Cr4 {
    unsafe { x86::controlregs::cr4() }
}

/// Writes a value to the CR4 register.
pub fn cr4_write(val: x86::controlregs::Cr4) {
    unsafe { x86::controlregs::cr4_write(val) };
}

/// Writes a value to the Cr2 register.
pub fn cr2_write(val: u64) {
    unsafe { x86::controlregs::cr2_write(val) };
}

/// Writes a value to the DR0 register.
pub fn dr0_write(val: u64) {
    unsafe { x86::debugregs::dr0_write(val as _) };
}

/// Writes a value to the DR1 register.
pub fn dr1_write(val: u64) {
    unsafe { x86::debugregs::dr1_write(val as _) };
}

/// Writes a value to the DR2 register.
pub fn dr2_write(val: u64) {
    unsafe { x86::debugregs::dr2_write(val as _) };
}

/// Writes a value to the DR3 register.
pub fn dr3_write(val: u64) {
    unsafe { x86::debugregs::dr3_write(val as _) };
}

/// Writes a value to the DR6 register.
pub fn dr6_write(val: u64) {
    let dr6 = x86::debugregs::Dr6::from_bits_truncate(val as _);
    unsafe { x86::debugregs::dr6_write(dr6) };
}

/// Reads the DR0 register.
pub fn dr0_read() -> u64 {
    unsafe { x86::debugregs::dr0() as u64 }
}

/// Reads the DR1 register.
pub fn dr1_read() -> u64 {
    unsafe { x86::debugregs::dr1() as u64 }
}

/// Reads the DR2 register.
pub fn dr2_read() -> u64 {
    unsafe { x86::debugregs::dr2() as u64 }
}

/// Reads the DR3 register.
pub fn dr3_read() -> u64 {
    unsafe { x86::debugregs::dr3() as u64 }
}

/// Reads the DR6 register.
pub fn dr6_read() -> u64 {
    unsafe { x86::debugregs::dr6().bits() as u64 }
}

/// Reads the DR7 register.
pub fn dr7_read() -> u64 {
    unsafe { x86::debugregs::dr7().0 as u64 }
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
pub fn sidt() -> x86::dtables::DescriptorTablePointer<u64> {
    let mut idtr = x86::dtables::DescriptorTablePointer::<u64>::default();
    unsafe { x86::dtables::sidt(&mut idtr) };
    idtr
}

/// Reads the GDTR.
pub fn sgdt() -> x86::dtables::DescriptorTablePointer<u64> {
    let mut gdtr = x86::dtables::DescriptorTablePointer::<u64>::default();
    unsafe { x86::dtables::sgdt(&mut gdtr) };
    gdtr
}

/// Reads a value of a specified type from guest memory at the provided virtual address, ensuring safety by internal validation.
///
/// # Arguments
///
/// * `guest_cr3` - The base address of the guest's page table hierarchy.
/// * `guest_va` - The guest virtual address from which to read.
///
/// # Returns
///
/// * Returns an `Option<T>` which is `Some(value)` if the read is successful and safe, or `None` if the address cannot be translated or if safety conditions are not met.
///
/// # Type Parameters
///
/// * `T` - The type of the value to read. This can be any type that implements the `Copy` trait and has a size that can be read atomically.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
pub fn read_guest_memory<T: Copy>(guest_cr3: usize, guest_va: usize) -> Option<T> {
    // Safety justification:
    // The translation function ensures that the physical address is valid and maps to a real physical memory location.
    // The dereference is only performed if the translation succeeds, and it's constrained to types that are Copy, implying they can be safely duplicated and do not manage resources that require manual cleanup.
    // Still, the caller must ensure that reading from this specific address does not violate any safety contracts.
    let pa = PageTables::translate_guest_virtual_to_physical(guest_cr3, guest_va)?;
    unsafe { Some(*(pa as *const T)) }
}

/// Finds the base virtual address of an image by scanning memory for the 'MZ' signature, starting
/// from a specified address and scanning backwards. This function is typically used to locate
/// the base address of system modules like ntoskrnl.exe in a Windows guest.
///
/// # Arguments
/// * `start_address` - The guest virtual address from where the backward scanning begins.
///
/// # Returns
/// * `Option<u64>` - Some with the base virtual address of the image if the 'MZ' signature is found,
///   indicating the start of a PE header; otherwise None.
///
/// # Safety
/// This function performs raw memory accesses based on a guest virtual address. The caller must ensure
/// that the provided address and the memory being accessed are valid and safely accessible.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
pub fn get_image_base_address(start_address: u64) -> Option<u64> {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // 'MZ' signature at the start of DOS headers.

    // Align the start address down to the nearest page boundary.
    let mut guest_va = start_address & !0xFFF;
    let guest_cr3 = vmread(vmcs::guest::CR3) as usize;

    loop {
        // Attempt to read the potential DOS signature at the current address.
        match read_guest_memory::<u16>(guest_cr3 as _, guest_va as _)? {
            IMAGE_DOS_SIGNATURE => return Some(guest_va), // Found the 'MZ' signature.
            _ => {
                if guest_va == 0 {
                    break; // Prevent underflow and ensure the loop eventually terminates.
                }
                guest_va -= 0x1000; // Move to the previous page.
            }
        }
    }

    None // The 'MZ' signature was not found in the scanned range.
}
