use {
    crate::intel::{events::EventInjection, support::read_effective_guest_cr4, vmexit::ExitType},
    log::trace,
    x86_64::registers::control::Cr4Flags,
};

/// Handles VMXON instruction.
///
/// This function is called when the VM exits due to a VMXON instruction.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue after handling the VMXON instruction.
pub fn handle_vmxon() -> ExitType {
    trace!("Handling VMXON VM exit...");

    let curr_cr4 = Cr4Flags::from_bits_retain(read_effective_guest_cr4());

    if !curr_cr4.contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS) {
        EventInjection::vmentry_inject_ud();
    } else {
        EventInjection::vmentry_inject_gp(0);
    }

    trace!("VMXON VMEXIT handled successfully!");

    ExitType::Continue
}
