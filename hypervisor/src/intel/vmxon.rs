use {
    crate::{
        error::HypervisorError,
        intel::support::rdmsr,
    },
    bitfield::BitMut,
    x86::{msr, current::paging::BASE_PAGE_SIZE},
    x86_64::registers::control::Cr4,
    x86::controlregs,
};
use crate::intel::vmcs::Vmcs;

/// A representation of the VMXON region in memory.
///
/// The VMXON region is essential for enabling VMX operations on the CPU.
/// This structure offers methods for setting up the VMXON region, enabling VMX operations,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.11.5 VMXON Region
#[repr(C, align(4096))]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; BASE_PAGE_SIZE - 4],
}
const _: () = assert_eq!(core::mem::size_of::<Vmxon>(), BASE_PAGE_SIZE);

impl Default for Vmxon {
    fn default() -> Self {
        Self {
            revision_id: rdmsr(msr::IA32_VMX_BASIC) as u32,
            data: [0; BASE_PAGE_SIZE - 4],
        }
    }
}

impl Vmxon {
    /// Enables VMX operation by setting appropriate bits and executing the VMXON instruction.
    pub fn setup_vmxon(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Enabling Virtual Machine Extensions (VMX)");
        Self::enable_vmx_operation();
        log::trace!("VMX enabled");

        log::trace!("Adjusting IA32_FEATURE_CONTROL MSR");
        Self::adjust_feature_control_msr()?;
        log::trace!("IA32_FEATURE_CONTROL MSR adjusted");

        log::trace!("Setting CR0 bits");
        Self::set_cr0_bits();
        log::trace!("CR0 bits set");

        log::trace!("Setting CR4 bits");
        Self::set_cr4_bits();
        log::trace!("CR4 bits set");

        self.revision_id.set_bit(31, false);

        Ok(())
    }

    /// Enables VMX operation by setting appropriate bits and executing the VMXON instruction.
    fn enable_vmx_operation() {
        const CR4_VMX_ENABLE_BIT: usize = 13;
        let mut cr4 = Cr4::read_raw();
        cr4.set_bit(CR4_VMX_ENABLE_BIT, true);
        unsafe { Cr4::write_raw(cr4) };
    }

    /// Sets the lock bit in IA32_FEATURE_CONTROL if necessary.
    fn adjust_feature_control_msr() -> Result<(), HypervisorError> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { msr::rdmsr(msr::IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                msr::wrmsr(
                    msr::IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                )
            };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::VMXBIOSLock);
        }

        Ok(())
    }

    /// Modifies CR0 to set and clear mandatory bits.
    fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { controlregs::cr0() };

        cr0 |= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { controlregs::cr0_write(cr0) };
    }

    /// Modifies CR4 to set and clear mandatory bits.
    fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = Cr4::read_raw();

        cr4 |= ia32_vmx_cr4_fixed0;
        cr4 &= ia32_vmx_cr4_fixed1;

        unsafe { Cr4::write_raw(cr4) };
    }
}