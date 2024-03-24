//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.
//! Credits:
//! https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/
//! https://mellownight.github.io/AetherVisor
//! jessiep_

use {
    crate::intel::{
        capture::GuestRegisters,
        events::EventInjection,
        support::{rdmsr, vmread, wrmsr},
        vmexit::ExitType,
    },
    x86::{msr, vmx::vmcs},
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

    const VMX_LOCK_BIT: u64 = 1 << 0;

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
        // Credits: jessiep_ and https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/
        MsrAccessType::Read => {
            let result_value = match msr_id {
                // When the guest reads the LSTAR MSR, the hypervisor returns the shadowed original value instead of the actual (modified) value.
                // This way, the guest OS sees what it expects, assuming no tampering has occurred.
                msr::IA32_LSTAR =>  {
                    log::trace!("IA32_LSTAR read attempted with MSR value: {:#x}", msr_value);
                    // This won't be 0 here because we intercept and populate it during MsrAccessType::Write on IA32_LSTAR which is set during the initial phase when ntoskrnl.exe
                    guest_registers.original_lstar
                },

                // Simulate IA32_FEATURE_CONTROL as locked: VMX locked bit set, VMX outside SMX clear.
                // Set lock bit, indicating that feature control is locked.
                msr::IA32_FEATURE_CONTROL => {
                    log::trace!("IA32_FEATURE_CONTROL read attempted with MSR value: {:#x}", msr_value);
                    VMX_LOCK_BIT
                }
                _ => rdmsr(msr_id),
            };

            guest_registers.rax = result_value & MSR_MASK_LOW;
            guest_registers.rdx = result_value >> 32;
        },
        MsrAccessType::Write => {
            if msr_id == msr::IA32_LSTAR {
                log::trace!("IA32_LSTAR write attempted with MSR value: {:#x}", msr_value);
                log::trace!("GuestRegisters Original LSTAR value: {:#x}", guest_registers.original_lstar);
                log::trace!("GuestRegisters Hook LSTAR value: {:#x}", guest_registers.hook_lstar);

                let ntoskrnl_base = find_ntoskrnl_base(msr_value).unwrap();
                log::trace!("ntoskrnl.exe base address: {:#x}", ntoskrnl_base);

                // Check if it's the first time we're intercepting a write to LSTAR.
                // If so, store the value being written as the original LSTAR value.
                if guest_registers.original_lstar == 0 {
                    guest_registers.original_lstar = msr_value;
                    // Optionally set a hook LSTAR value here. For now, let's assume we simply store the original value.
                    // This is a placeholder for where you would set your hook.
                    guest_registers.hook_lstar = guest_registers.original_lstar; // This should eventually be replaced with an actual hook address.
                }

                // If the guest attempts to write back the original LSTAR value we provided,
                // it could be part of an integrity check. In such a case, we allow the write to go through
                // but actually write our hook again to maintain control.
                if msr_value == guest_registers.original_lstar {
                    // Write the hook LSTAR value if it's set, otherwise write the original value.
                    // This check is necessary in case the hook_lstar is not yet implemented or set to 0.
                    let value_to_write = if guest_registers.hook_lstar != 0 {
                        guest_registers.hook_lstar
                    } else {
                        guest_registers.original_lstar
                    };

                    wrmsr(msr_id, value_to_write);
                }

            } else {
                // For MSRs other than msr::IA32_LSTAR or non-original LSTAR value writes, proceed with the write operation.
                // If the guest writes any other value (which would typically only happen if the guest is attempting to modify the syscall mechanism itself),
                // the write operation proceeds.
                wrmsr(msr_id, msr_value);
            }
        },
    }

    log::debug!("MSR VMEXIT handled successfully.");
    ExitType::IncrementRIP
}

/// Define the 'MZ' signature found at the beginning of DOS headers.
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// Reads a 16-bit value from guest memory at the specified virtual address.
/// This is a low-level function that directly accesses guest memory, assuming
/// the guest virtual address space is currently active.
///
/// # Safety
/// This function is unsafe because it performs raw pointer dereferencing
/// and can lead to undefined behavior if the address is not valid or mapped in the current context.
///
/// # Returns
/// Returns Some(u16) containing the value read from the guest memory at the specified address
/// if the operation is successful, or None if the address cannot be translated to a physical address.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
unsafe fn read_guest_memory_u16(address: u64) -> Option<u16> {
    let pa = translate_guest_virtual_to_physical(vmread(vmcs::guest::CR3) as _, address as usize)?
        as *const u16;
    Some(*pa)
}

/// Attempts to find the base virtual address of the ntoskrnl.exe kernel module
/// by scanning backwards from a given start address in guest memory. It looks for the
/// 'MZ' DOS signature that marks the start of PE headers in Windows executables.
///
/// # Arguments
/// * `start_address` - The guest virtual address to start scanning from. This address
/// should ideally be somewhere within or near the ntoskrnl.exe module to ensure that
/// the search does not have to span a large area.
///
/// # Returns
/// Returns Some(u64) containing the base virtual address of ntoskrnl.exe if found,
/// or None if the search fails to find the DOS signature.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
fn find_ntoskrnl_base(start_address: u64) -> Option<u64> {
    // Align the start address to a page boundary to ensure that the search starts at the beginning of a page.
    let mut current_address = start_address & !0xFFF;

    loop {
        // Attempt to read the potential DOS signature at the current address.
        match unsafe { read_guest_memory_u16(current_address) }? {
            IMAGE_DOS_SIGNATURE => return Some(current_address),
            _ => current_address -= 0x1000,
        }
    }
}

/// Translates a guest virtual address to a physical address using the guest's CR3.
/// This function traverses the guest's page tables, assuming an identity-mapped
/// host address space for simplicity.
///
/// # Arguments
/// * `guest_cr3` - The guest CR3 register value, which contains the base address of the
/// guest's page table hierarchy.
/// * `virtual_address` - The guest virtual address to translate.
///
/// # Safety
/// This function is unsafe because it involves raw memory access based on potentially
/// arbitrary addresses, which may lead to undefined behavior if the addresses are invalid
/// or the memory is not properly mapped.
///
/// # Returns
/// Returns Some(usize) containing the translated physical address if successful,
/// or None if the translation fails at any level of the page table hierarchy.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
pub unsafe fn translate_guest_virtual_to_physical(
    guest_cr3: usize,
    virtual_address: usize,
) -> Option<usize> {
    // Mask used to clear the lower 12 bits of an address, effectively aligning it to a page boundary.
    const ADDRESS_MASK: usize = ((1 << x86::bits64::paging::MAXPHYADDR) - 1) & !0xFFF;

    // Start at the base of the guest's page table hierarchy.
    let mut current_paging = guest_cr3 as *const usize;

    // Iterate through the page table levels, checking for large pages and
    // extracting the physical address from the page table entries.
    for (supports_large, index, offset_mask) in [
        (false, (virtual_address >> 39) & 0x1FF, 0),
        (true, (virtual_address >> 30) & 0x1FF, 0x3FFFFFFF),
        (true, (virtual_address >> 21) & 0x1FF, 0x1FFFFF),
    ] {
        let page_entry = *current_paging.add(index);

        // If the page is not present, translation fails.
        if page_entry & 1 == 0 {
            return None;
        }

        // If this is a large page, calculate the physical address and return it, taking into account the offset within the large page.
        if supports_large && (page_entry & 0x80 != 0) {
            return Some((page_entry & ADDRESS_MASK) | (virtual_address & offset_mask));
        }

        // go to the next page :)
        current_paging = (page_entry & ADDRESS_MASK) as *const usize;
    }

    let page_entry = *current_paging.add((virtual_address >> 12) & 0x1FF);

    Some((page_entry & ADDRESS_MASK) | (virtual_address & 0xFFF))
}
