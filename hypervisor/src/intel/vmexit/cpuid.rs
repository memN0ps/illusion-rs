//! Handles CPU-related virtualization tasks, specifically intercepting and managing
//! the `CPUID` instruction in a VM to control the exposure of CPU features to the guest.

use {
    crate::{
        error::HypervisorError,
        intel::{
            hooks::hook_manager::HookManager,
            vm::Vm,
            vmexit::{commands::handle_guest_commands, ExitType},
        },
    },
    bitfield::BitMut,
    log::*,
    x86::cpuid::cpuid,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
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

/// The password used for authentication with the hypervisor.
const PASSWORD: u64 = 0xDEADBEEF;

/// Handles the `CPUID` VM-exit.
///
/// This function is invoked when the guest executes the `CPUID` instruction.
/// The handler retrieves the results of the `CPUID` instruction executed on
/// the host and then modifies or masks certain bits, if necessary, before
/// returning the results to the guest.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `CPUID` instruction in the VM.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual, Table C-1. Basic Exit Reasons 10.
pub fn handle_cpuid(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling CPUID VM exit...");

    let leaf = vm.guest_registers.rax as u32;
    let sub_leaf = vm.guest_registers.rcx as u32;

    if vm.guest_registers.rax == PASSWORD {
        // Handle the guest command and update the CPUID result accordingly
        vm.guest_registers.rax = if handle_guest_commands(vm) {
            0x1 // Command handled successfully
        } else {
            0x0 // Command handling failed
        };

        trace!("Command executed successfully with leaf {:#x}", leaf);
    } else {
        // Execute CPUID instruction on the host and retrieve the result
        let mut cpuid_result = cpuid!(leaf, sub_leaf);
        trace!("CpuidLeaf: {:#x}", leaf);

        match leaf {
            leaf if leaf == CpuidLeaf::VendorInfo as u32 => {
                trace!("CPUID leaf 0x0 detected (Vendor Identification).");
            }
            leaf if leaf == CpuidLeaf::FeatureInformation as u32 => {
                trace!("CPUID leaf 1 detected (Standard Feature Information).");

                // Hide hypervisor presence by setting the appropriate bit in ECX.
                cpuid_result.ecx.set_bit(FeatureBits::HypervisorPresentBit as usize, false);

                // Hide VMX support by setting the appropriate bit in ECX.
                cpuid_result.ecx.set_bit(FeatureBits::HypervisorVmxSupportBit as usize, false);
            }
            leaf if leaf == CpuidLeaf::CacheInformation as u32 => {
                trace!("CPUID leaf 0x2 detected (Cache Information).");

                // Lock the global HookManager once
                let mut hook_manager = HookManager::get_hook_manager_mut();

                if !hook_manager.has_cpuid_cache_info_been_called {
                    // Test UEFI boot-time hooks
                    HookManager::manage_kernel_ept_hook(
                        &mut hook_manager,
                        vm,
                        crate::windows::nt::pe::djb2_hash("NtQuerySystemInformation".as_bytes()),
                        0x0036,
                        crate::intel::hooks::hook_manager::EptHookType::Function(crate::intel::hooks::inline::InlineHookType::Vmcall),
                        true,
                    )?;
                    HookManager::manage_kernel_ept_hook(
                        &mut hook_manager,
                        vm,
                        crate::windows::nt::pe::djb2_hash("NtCreateFile".as_bytes()),
                        0x0055,
                        crate::intel::hooks::hook_manager::EptHookType::Function(crate::intel::hooks::inline::InlineHookType::Vmcall),
                        true,
                    )?;
                    HookManager::manage_kernel_ept_hook(
                        &mut hook_manager,
                        vm,
                        crate::windows::nt::pe::djb2_hash("NtAllocateVirtualMemory".as_bytes()),
                        0x18,
                        crate::intel::hooks::hook_manager::EptHookType::Function(crate::intel::hooks::inline::InlineHookType::Vmcall),
                        true,
                    )?;
                    HookManager::manage_kernel_ept_hook(
                        &mut hook_manager,
                        vm,
                        crate::windows::nt::pe::djb2_hash("NtQueryInformationProcess".as_bytes()),
                        0x19,
                        crate::intel::hooks::hook_manager::EptHookType::Function(crate::intel::hooks::inline::InlineHookType::Vmcall),
                        true,
                    )?;
                    // Set the flag
                    hook_manager.has_cpuid_cache_info_been_called = true;
                }
            }
            leaf if leaf == CpuidLeaf::ExtendedFeatureInformation as u32 => {
                trace!("CPUID leaf 0x7 detected (Extended Feature Information).");
            }
            leaf if leaf == CpuidLeaf::HypervisorVendor as u32 => {
                trace!("CPUID leaf 0x40000000 detected (Hypervisor Vendor Information).");
                // Set the CPUID response to provide the hypervisor's vendor ID signature.
                // We use the signature "Illusion" encoded in a little-endian format.
                cpuid_result.eax = CpuidLeaf::HypervisorInterface as u32; // Maximum supported CPUID leaf range.
                cpuid_result.ebx = 0x756c6c49; // "ullI", part of "Illusion" (in reverse order due to little-endian storage).
                cpuid_result.ecx = 0x6e6f6973; // "nois", part of "Illusion" (in reverse order due to little-endian storage).
                cpuid_result.edx = 0x00000000; // Filled with null bytes as there are no more characters to encode.
            }
            leaf if leaf == CpuidLeaf::HypervisorInterface as u32 => {
                trace!("CPUID leaf 0x40000001 detected (Hypervisor Interface Identification).");
                // Return information indicating the hypervisor's interface.
                // Here, we specify that our hypervisor does not conform to the Microsoft hypervisor interface ("Hv#1").
                // cpuid_result.eax = 0x00000000; // Interface signature indicating non-conformance to Microsoft interface.
                // cpuid_result.ebx = 0x00000000; // Reserved field set to zero.
                // cpuid_result.ecx = 0x00000000; // Reserved field set to zero.
                // cpuid_result.edx = 0x00000000; // Reserved field set to zero.
            }
            _ => trace!("CPUID leaf 0x{leaf:X}."),
        }

        // Update the guest registers with the results
        vm.guest_registers.rax = cpuid_result.eax as u64;
        vm.guest_registers.rbx = cpuid_result.ebx as u64;
        vm.guest_registers.rcx = cpuid_result.ecx as u64;
        vm.guest_registers.rdx = cpuid_result.edx as u64;
    }

    trace!("CPUID VMEXIT handled successfully!");

    Ok(ExitType::IncrementRIP)
}
