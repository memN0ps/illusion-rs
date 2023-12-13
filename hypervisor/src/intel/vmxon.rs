//! A module responsible for managing the VMXON region and enabling VMX operations.
//!
//! This module provides functionality to set up the VMXON region in memory and
//! enable VMX operations. It also offers utility functions for adjusting control
//! registers to facilitate VMX operations.

use {
    crate::{
        error::HypervisorError,
        intel::{support::vmxon, vmcs::Vmcs},
        utils::{addresses::PhysicalAddress, alloc::PhysicalAllocator},
    },
    alloc::boxed::Box,
    bitfield::BitMut,
};

pub const PAGE_SIZE: usize = 0x1000;

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
    pub data: [u8; PAGE_SIZE - 4],
}

impl Vmxon {
    /// Sets up the VMXON region and enables VMX operations.
    ///
    /// # Arguments
    /// * `vmxon_region` - A mutable reference to the VMXON region in memory.
    ///
    /// # Returns
    /// A result indicating success or an error.
    pub fn setup(vmxon_region: &mut Box<Vmxon, PhysicalAllocator>) -> Result<(), HypervisorError> {
        log::info!("Setting up VMXON region");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        log::info!("Enabling Virtual Machine Extensions (VMX)");
        Self::enable_vmx_operation()?;

        let vmxon_region_physical_address =
            PhysicalAddress::pa_from_va(vmxon_region.as_ref() as *const _ as _);

        if vmxon_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("VMXON Region Virtual Address: {:p}", vmxon_region);
        log::info!(
            "VMXON Region Physical Addresss: 0x{:x}",
            vmxon_region_physical_address
        );

        vmxon_region.revision_id = Vmcs::get_vmcs_revision_id();
        vmxon_region.as_mut().revision_id.set_bit(31, false);

        // Enable VMX operation.
        vmxon(vmxon_region_physical_address);
        log::info!("VMXON setup successful!");

        Ok(())
    }

    /// Enables VMX operation by setting appropriate bits and executing the VMXON instruction.
    fn enable_vmx_operation() -> Result<(), HypervisorError> {
        let mut cr4 = unsafe { x86::controlregs::cr4() };
        cr4.set(x86::controlregs::Cr4::CR4_ENABLE_VMX, true);
        unsafe { x86::controlregs::cr4_write(cr4) };

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        log::info!("Setting Lock Bit set via IA32_FEATURE_CONTROL");
        Self::set_lock_bit()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.8 RESTRICTIONS ON VMX OPERATION */
        log::info!("Adjusting Control Registers");
        Self::adjust_control_registers();

        Ok(())
    }

    /// Sets the lock bit in IA32_FEATURE_CONTROL if necessary.
    fn set_lock_bit() -> Result<(), HypervisorError> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { x86::msr::rdmsr(x86::msr::IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                x86::msr::wrmsr(
                    x86::msr::IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                )
            };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::VMXBIOSLock);
        }

        Ok(())
    }

    /// Adjusts control registers by setting mandatory bits.
    fn adjust_control_registers() {
        Self::set_cr0_bits();
        Self::set_cr4_bits();
    }

    /// Modifies CR0 to set and clear mandatory bits.
    fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { x86::controlregs::cr0() };

        cr0 |= x86::controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= x86::controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { x86::controlregs::cr0_write(cr0) };
    }

    /// Modifies CR4 to set and clear mandatory bits.
    fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { x86::controlregs::cr4() };

        cr4 |= x86::controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= x86::controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { x86::controlregs::cr4_write(cr4) };
    }
}
