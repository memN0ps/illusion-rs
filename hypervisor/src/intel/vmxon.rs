//! Provides structures and functions for initializing and managing the VMXON region for VMX operations.
//!
//! This crate includes the `Vmxon` struct, which is essential for hypervisor development, enabling VMX operations on Intel CPUs.
//! It covers setting up the VMXON region, adjusting necessary control registers, and handling model-specific registers to meet Intel's virtualization requirements.

use {
    crate::{error::HypervisorError, intel::support::rdmsr},
    bitfield::BitMut,
    x86::{controlregs, current::paging::BASE_PAGE_SIZE, msr},
    x86_64::registers::control::Cr4,
};

/// A representation of the VMXON region in memory.
///
/// The VMXON region is essential for enabling VMX operations on the CPU.
/// This structure offers methods for setting up the VMXON region, enabling VMX operations,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.11.5 VMXON Region
#[repr(C, align(4096))]
pub struct Vmxon {
    /// Revision ID required for VMXON.
    pub revision_id: u32,

    /// Data array constituting the rest of the VMXON region.
    pub data: [u8; BASE_PAGE_SIZE - 4],
}

impl Vmxon {
    /// Initializes the VMXON region.
    pub fn init(&mut self) {
        self.revision_id = rdmsr(msr::IA32_VMX_BASIC) as u32;
        self.revision_id.set_bit(31, false);
    }

    /// Enables VMX operation by setting the VMX-enable bit in CR4.
    ///
    /// Sets the CR4_VMX_ENABLE_BIT to enable VMX operations, preparing the processor to enter VMX operation mode.
    pub fn enable_vmx_operation() {
        const CR4_VMX_ENABLE_BIT: usize = 13;
        let mut cr4 = Cr4::read_raw();
        cr4.set_bit(CR4_VMX_ENABLE_BIT, true);
        unsafe { Cr4::write_raw(cr4) };
    }

    /// Adjusts the IA32_FEATURE_CONTROL MSR to set the lock bit and enable VMXON outside SMX if necessary.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the MSR is successfully adjusted, or a `HypervisorError` if the lock bit is set but VMXON outside SMX is disabled.
    pub fn adjust_feature_control_msr() -> Result<(), HypervisorError> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { msr::rdmsr(msr::IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe { msr::wrmsr(msr::IA32_FEATURE_CONTROL, VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control) };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::VMXBIOSLock);
        }

        Ok(())
    }

    /// Sets and clears mandatory bits in CR0 as required for VMX operation.
    ///
    /// Adjusts CR0 based on the fixed0 and fixed1 MSRs to ensure that all required bits for VMX operation are correctly set.
    pub fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { controlregs::cr0() };

        cr0 |= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { controlregs::cr0_write(cr0) };
    }

    /// Modifies CR4 to set and clear mandatory bits for VMX operation.
    ///
    /// Uses the IA32_VMX_CR4_FIXED0 and IA32_VMX_CR4_FIXED1 MSRs to adjust CR4, ensuring the processor meets the requirements for VMX operation.
    pub fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = Cr4::read_raw();

        cr4 |= ia32_vmx_cr4_fixed0;
        cr4 &= ia32_vmx_cr4_fixed1;

        unsafe { Cr4::write_raw(cr4) };
    }
}
