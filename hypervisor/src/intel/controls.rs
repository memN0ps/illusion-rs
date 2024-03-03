//! Module for handling VMX control adjustments.
//! Provides mechanisms for adjusting VMX controls based on certain conditions
//! and capabilities, ensuring safe and effective VMX operations.
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hypervisor-101-in-Rust/blob/main/hypervisor/src/hardware_vt/vmx.rs

use x86::msr;

/// Enumerates the types of VMX control fields.
#[derive(Clone, Copy)]
pub enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    VmExit,
    VmEntry,
}

/// Adjusts the VMX controls based on the requested value and capabilities.
///
/// # Arguments
///
/// * `control` - The type of VMX control to be adjusted.
/// * `requested_value` - The desired value for the control.
///
/// # Returns
///
/// Returns the adjusted control value based on system capabilities and the requested value.
pub fn adjust_vmx_controls(control: VmxControl, requested_value: u64) -> u64 {
    const IA32_VMX_BASIC_VMX_CONTROLS_FLAG: u64 = 1 << 55;

    let vmx_basic = unsafe { msr::rdmsr(msr::IA32_VMX_BASIC) };
    let true_cap_msr_supported = (vmx_basic & IA32_VMX_BASIC_VMX_CONTROLS_FLAG) != 0;

    let cap_msr = match (control, true_cap_msr_supported) {
        (VmxControl::PinBased, true) => msr::IA32_VMX_TRUE_PINBASED_CTLS,
        (VmxControl::PinBased, false) => msr::IA32_VMX_PINBASED_CTLS,
        (VmxControl::ProcessorBased, true) => msr::IA32_VMX_TRUE_PROCBASED_CTLS,
        (VmxControl::ProcessorBased, false) => msr::IA32_VMX_PROCBASED_CTLS,
        (VmxControl::VmExit, true) => msr::IA32_VMX_TRUE_EXIT_CTLS,
        (VmxControl::VmExit, false) => msr::IA32_VMX_EXIT_CTLS,
        (VmxControl::VmEntry, true) => msr::IA32_VMX_TRUE_ENTRY_CTLS,
        (VmxControl::VmEntry, false) => msr::IA32_VMX_ENTRY_CTLS,
        // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use IA32_VMX_PROCBASED_CTLS2 unconditionally.
        (VmxControl::ProcessorBased2, _) => msr::IA32_VMX_PROCBASED_CTLS2,
    };

    let capabilities = unsafe { msr::rdmsr(cap_msr) };
    let allowed0 = capabilities as u32;
    let allowed1 = (capabilities >> 32) as u32;
    let mut effective_value = u32::try_from(requested_value).unwrap();
    effective_value |= allowed0;
    effective_value &= allowed1;
    u64::from(effective_value)
}
