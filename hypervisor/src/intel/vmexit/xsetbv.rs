//! Provides handlers for managing VM exits due to the XSETBV instruction, ensuring
//! controlled manipulation of the XCR0 register by guest VMs.

use {
    crate::intel::{
        events::EventInjection,
        support::{cr4, cr4_write, xsetbv},
        vm::Vm,
        vmexit::ExitType,
    },
    core::arch::x86_64::_XCR_XFEATURE_ENABLED_MASK,
    x86_64::registers::{control::Cr4Flags, xcontrol::XCr0Flags},
};

/// Manages the XSETBV instruction during a VM exit. It logs the event, updates
/// CR4 to enable the necessary feature, sets the XCR0 value, and advances the
/// guest's instruction pointer.
///
/// # Arguments
///
/// * `vm`: A mutable reference to the VM.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `XSETBV` instruction in the VM.
pub fn handle_xsetbv(vm: &mut Vm) -> ExitType {
    log::debug!("Handling XSETBV VM VM exit...");

    // Extract the XCR (extended control register) number from the guest's RCX register.
    let xcr: u32 = vm.guest_registers.rcx as u32;

    if xcr != _XCR_XFEATURE_ENABLED_MASK {
        log::debug!("Invalid XCR value for xsetbv: {:#x}", xcr);
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // Combine the guest's RAX and RDX registers to form the 64-bit value for the XCR0 register.
    let value_raw = (vm.guest_registers.rax & 0xffff_ffff) | ((vm.guest_registers.rdx & 0xffff_ffff) << 32);

    // Attempt to create a Xcr0 structure from the given bits.
    let value = XCr0Flags::from_bits_retain(value_raw);

    // Make sure the guest is not trying to set any unsupported bits via cpuid cache
    if value.bits() & vm.xcr0_unsupported_mask != 0 {
        log::debug!("Trying to set unsupported XCR0 value for xsetbv: {:#x}", xcr);
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // Make sure bits being set are architecturally valid.
    if !is_valid_xcr0(value) {
        log::debug!("Invalid XCR0 value for xsetbv: {:#x}", xcr);
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    log::trace!("XSETBV executed with xcr: {:#x}, value: {:#x}", xcr, value_raw);

    // Enable the OS XSAVE feature in CR4 before setting the extended control register value.
    cr4_write(cr4() | Cr4Flags::OSXSAVE.bits());

    // Write the value to the specified XCR (extended control register).
    xsetbv(value_raw);

    log::debug!("XSETBV VM exit handled successfully!");

    // Advance the guest's instruction pointer to the next instruction to be executed.
    ExitType::IncrementRIP
}

/// Validates the XCR0 value to ensure that the guest is not trying to set any unsupported bits.
///
/// # Arguments
///
/// * `xcr0`: The XCR0 value to validate.
///
/// # Returns
///
/// * `true` if the XCR0 value is valid, `false` otherwise.
fn is_valid_xcr0(xcr0: XCr0Flags) -> bool {
    // #GP(0) if clearing XCR0.X87
    if !xcr0.contains(XCr0Flags::X87) {
        return false;
    }

    // #GP(0) if XCR0.AVX is 1 while XCRO.SSE is cleared
    if xcr0.contains(XCr0Flags::AVX) && !xcr0.contains(XCr0Flags::SSE) {
        return false;
    }

    // #GP(0) if XCR0.AVX is clear and XCR0.opmask, XCR0.ZMM_Hi256, or XCR0.Hi16_ZMM is set
    if !xcr0.contains(XCr0Flags::AVX)
        && (xcr0.contains(XCr0Flags::OPMASK) || xcr0.contains(XCr0Flags::ZMM_HI256) || xcr0.contains(XCr0Flags::HI16_ZMM))
    {
        return false;
    }

    // BNDREGS and BNDCSR must be the same.
    if xcr0.contains(XCr0Flags::BNDREG) != xcr0.contains(XCr0Flags::BNDCSR) {
        return false;
    }

    // #GP(0) if setting XCR0.opmask, XCR0.ZMM_Hi256, or XCR0.Hi16_ZMM while not setting all of them
    if xcr0.contains(XCr0Flags::OPMASK) != xcr0.contains(XCr0Flags::ZMM_HI256)
        || xcr0.contains(XCr0Flags::ZMM_HI256) != xcr0.contains(XCr0Flags::HI16_ZMM)
    {
        return false;
    }

    true
}
