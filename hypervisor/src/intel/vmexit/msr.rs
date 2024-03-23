//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.
//! Credits:
//! https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/
//! https://mellownight.github.io/AetherVisor

use {
    crate::intel::support::{rdmsr, wrmsr},
    crate::intel::{capture::GuestRegisters, events::EventInjection, vmexit::ExitType},
    x86::msr,
};

/// Enum representing the type of MSR access.
///
/// There are two types of MSR access: reading from an MSR and writing to an MSR.
pub enum MsrAccessType {
    Read,
    Write,
}

/// Handles MSR access based on the provided access type.
///
/// This function checks if the requested MSR address is within a valid
/// range, a reserved range, or a synthetic MSR range used by Hyper-V.
/// For valid MSRs, the function will either read or write to the MSR based
/// on the access type. For reserved or synthetic MSRs, a general protection
/// fault is injected.
///
/// # Arguments
///
/// * `registers` - A mutable reference to the guest's current register state.
/// * `access_type` - The type of MSR access (read or write).
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `rdmsr` or `wrmsr` instruction in the VM.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: RDMSR—Read From Model Specific Register or WRMSR—Write to Model Specific Register
/// and Table C-1. Basic Exit Reasons 31 and 32.
#[rustfmt::skip]
pub fn handle_msr_access(guest_registers: &mut GuestRegisters, access_type: MsrAccessType) -> ExitType {
    log::debug!("Handling MSR VM exit...");

    const MSR_MASK_LOW: u64 = u32::MAX as u64;
    const MSR_RANGE_LOW_END: u64 = 0x00001FFF;
    const MSR_RANGE_HIGH_START: u64 = 0xC0000000;
    const MSR_RANGE_HIGH_END: u64 = 0xC0001FFF;
    const HYPERV_MSR_START: u64 = 0x40000000;
    const HYPERV_MSR_END: u64 = 0x4000FFFF;

    let msr_id = guest_registers.rcx as u32;
    let msr_value = (guest_registers.rdx << 32) | (guest_registers.rax & MSR_MASK_LOW);

    // Determine if the MSR address is valid, reserved, or synthetic (EasyAntiCheat and Battleye invalid MSR checks).
    // Credits: https://mellownight.github.io/AetherVisor
    if !((msr_id <= MSR_RANGE_LOW_END as u32) || ((msr_id >= MSR_RANGE_HIGH_START as u32) && (msr_id <= MSR_RANGE_HIGH_END as u32)) || ((msr_id >= HYPERV_MSR_START as u32) && (msr_id <= HYPERV_MSR_END as u32))) {
        // Invalid MSR access attempted, inject a general protection fault.
        log::trace!("Invalid MSR access attempted: {:#x}", msr_id);
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    log::trace!("Valid MSR access attempted: {:#x}", msr_id);
    match access_type {
        // Credits: https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/
        MsrAccessType::Read => {
            let result_value = match msr_id {
                msr::IA32_LSTAR => guest_registers.original_lstar,
                _ => rdmsr(msr_id),
            };

            guest_registers.rax = result_value & MSR_MASK_LOW;
            guest_registers.rdx = result_value >> 32;
        },
        MsrAccessType::Write => {
            if msr_id == msr::IA32_LSTAR && msr_value == guest_registers.original_lstar {
                // Let the guest overwrite our hook to avoid possible detection, but shadow the original value.
                wrmsr(msr_id, guest_registers.hook_lstar);
            } else {
                // For MSRs other than msr::IA32_LSTAR or non-original LSTAR value writes, proceed with the write operation.
                wrmsr(msr_id, msr_value);
            }
        },
    }

    log::debug!("MSR VMEXIT handled successfully.");
    ExitType::IncrementRIP
}
