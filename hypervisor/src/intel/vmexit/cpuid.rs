//! Handles CPU-related virtualization tasks, specifically intercepting and managing
//! the `CPUID` instruction in a VM to control the exposure of CPU features to the guest.

use {
    crate::{
        error::HypervisorError,
        intel::{
            hooks::{hook::EptHookType, inline::InlineHookType},
            vm::Vm,
            vmexit::ExitType,
        },
    },
    bitfield::BitMut,
    core::ops::RangeInclusive,
    log::*,
    x86::cpuid::cpuid,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Enum representing the various CPUID leaves for feature and interface discovery.
/// Reference: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
pub enum CpuidLeaf {
    /// CPUID function number to retrieve the processor's vendor identification string.
    VendorInfo = 0x0,

    /// CPUID function for feature information, including hypervisor presence.
    FeatureInformation = 0x1,

    /// CPUID function for cache information.
    CacheInformation = 0x2,

    /// CPUID function for extended feature information.
    ExtendedFeatureInformation = 0x7,

    /// Hypervisor vendor information leaf.
    HypervisorVendor = 0x40000000,

    /// Hypervisor interface identification leaf.
    HypervisorInterface = 0x40000001,

    /// Hypervisor system identity information leaf.
    HypervisorSystemIdentity = 0x40000002,

    /// Hypervisor feature identification leaf.
    HypervisorFeatureIdentification = 0x40000003,

    /// Hypervisor implementation recommendations leaf.
    ImplementationRecommendations = 0x40000004,

    /// Hypervisor implementation limits leaf.
    HypervisorImplementationLimits = 0x40000005,

    /// Hardware-specific features in use by the hypervisor leaf.
    ImplementationHardwareFeatures = 0x40000006,

    /// Nested hypervisor feature identification leaf.
    NestedHypervisorFeatureIdentification = 0x40000009,

    /// Nested virtualization features available leaf.
    HypervisorNestedVirtualizationFeatures = 0x4000000A,
}

/// Enumerates specific feature bits in the ECX register for CPUID instruction results.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum FeatureBits {
    /// Bit 5 of ECX for CPUID with EAX=1, indicating VMX support.
    HypervisorVmxSupportBit = 5,
    /// Bit 31 of ECX for CPUID with EAX=1, indicating hypervisor presence.
    HypervisorPresentBit = 31,
}

/// Handles the `CPUID` VM-exit.
///
/// This function is invoked when the guest executes the `CPUID` instruction.
/// The handler retrieves the results of the `CPUID` instruction executed on
/// the host and then modifies or masks certain bits, if necessary, before
/// returning the results to the guest.
///
/// # Arguments
///
/// * `registers` - A mutable reference to the guest's current register state.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `CPUID` instruction in the VM.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual, Table C-1. Basic Exit Reasons 10.
#[rustfmt::skip]
pub fn handle_cpuid(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling CPUID VM exit...");

    const HYPERV_CPUID_LEAF_RANGE: RangeInclusive<u32> = 0x40000000..=0x4FFFFFFF;

    let leaf = vm.guest_registers.rax as u32;
    let sub_leaf = vm.guest_registers.rcx as u32;

    // Execute CPUID instruction on the host and retrieve the result
    let mut cpuid_result = cpuid!(leaf, sub_leaf);

    trace!("CpuidLeaf: {:#x}", leaf);

    match leaf {
        leaf if leaf == CpuidLeaf::VendorInfo as u32 => {
            trace!("CPUID leaf 0x0 detected (Vendor Identification).");
        },
        leaf if leaf == CpuidLeaf::FeatureInformation as u32 => {
            trace!("CPUID leaf 0x1 detected (Feature Information).");
            // Check if the guest is querying for hypervisor presence.
            if sub_leaf == 0 {
                // Set the hypervisor present bit in ECX to indicate the presence of a hypervisor.
                cpuid_result.ecx.set_bit(FeatureBits::HypervisorPresentBit as usize, true);
            }
        },
        leaf if leaf == CpuidLeaf::CacheInformation as u32 => {
            trace!("CPUID leaf 0x2 detected (Cache Information).");
            if vm.hook_manager.has_cpuid_cache_info_been_called == false && cfg!(feature = "test-windows-uefi-hooks") {
                trace!("Register state before handling VM exit: {:#x?}", vm.guest_registers);
                let mut kernel_hook = vm.hook_manager.as_mut().kernel_hook;

                // Setup a named function hook (example: MmIsAddressValid)
                // info!("Hooking MmIsAddressValid with inline hook");
                // kernel_hook.setup_kernel_inline_hook(vm, "MmIsAddressValid", core::ptr::null_mut(), EptHookType::Function(InlineHookType::Vmcall))?;

                info!("Hooking NtCreateFile with syscall number 0x055");
                kernel_hook.setup_kernel_ssdt_hook(vm, 0x055, false, core::ptr::null_mut(), EptHookType::Function(InlineHookType::Vmcall))?;

                //info!("Hooking NtQuerySystemInformation with syscall number 0x36");
                //kernel_hook.setup_kernel_ssdt_hook(vm, 0x36, false, core::ptr::null_mut(), EptHookType::Function(InlineHookType::Vmcall))?;

                //info!("Hooking NtOpenProcess with syscall number 0x26");
                //kernel_hook.setup_kernel_ssdt_hook(vm, 0x26, false, core::ptr::null_mut(), EptHookType::Function(InlineHookType::Vmcall))?;

                //info!("Hook installed successfully!");

                vm.hook_manager.has_cpuid_cache_info_been_called = true;
            }
        },
        leaf if leaf == CpuidLeaf::ExtendedFeatureInformation as u32 => {
            trace!("CPUID leaf 0x7 detected (Extended Feature Information).");
        },
        leaf if HYPERV_CPUID_LEAF_RANGE.contains(&leaf) => {
            trace!("Hypervisor specific CPUID leaf 0x{leaf:X} detected.");
            // Depending on your specific implementation, you may need to modify or mask the results
            // For example, for the Hypervisor Vendor leaf:
            if leaf == CpuidLeaf::HypervisorVendor as u32 {
                // Provide a customized vendor ID signature
                cpuid_result.eax = 0; // Set to a meaningful max CPUID leaf value or leave it for default behavior
                cpuid_result.ebx = 0x756c6c49; // "ullI" - part of "Illusion" (in reverse due to little-endian storage)
                cpuid_result.ecx = 0x6e6f6973; // "nois" - remaining part of "Illusion"
                cpuid_result.edx = 0x00000000; // Filled with null bytes as no further characters to encode
            } else {
                // Default handling for unrecognized but within range leaves
                cpuid_result.eax = 0;
                cpuid_result.ebx = 0;
                cpuid_result.ecx = 0;
                cpuid_result.edx = 0;
            }
        },
        _ => {
            trace!("Unhandled or unknown CPUID leaf 0x{leaf:X}. Treating as reserved.");
            // Mask off the results to avoid exposing unsupported features
            cpuid_result.eax = 0;
            cpuid_result.ebx = 0;
            cpuid_result.ecx = 0;
            cpuid_result.edx = 0;
        }
    }

    // Update the guest registers with the results
    vm.guest_registers.rax = cpuid_result.eax as u64;
    vm.guest_registers.rbx = cpuid_result.ebx as u64;
    vm.guest_registers.rcx = cpuid_result.ecx as u64;
    vm.guest_registers.rdx = cpuid_result.edx as u64;

    trace!("CPUID VMEXIT handled successfully!");

    Ok(ExitType::IncrementRIP)

}
