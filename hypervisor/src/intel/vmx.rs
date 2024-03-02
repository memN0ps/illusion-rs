//! Enables VMXON region management for VMX operations.
//!
//! Offers the `Vmx` struct to facilitate the setup and activation of the VMXON region,
//! supporting hypervisor development by adhering to Intel's specifications for virtualization.

use {
    crate::{
        error::HypervisorError,
        intel::{support::vmxon, vmxon::Vmxon},
    },
    bit_field::BitField,
};

/// Manages VMX operations, including the activation of the VMXON region.
///
/// This struct is responsible for initializing and activating the VMXON region, which is essential
/// for enabling VMX (Virtual Machine Extensions) operations on the CPU. It includes functionalities
/// to set up the environment required for VMX operations by configuring system and model-specific
/// registers (MSRs) as per Intel's virtualization technology requirements.
pub struct Vmx {
    pub vmxon_region: Vmxon,
}

impl Vmx {
    /// Creates a new instance of `Vmx`.
    ///
    /// Initializes the VMXON region with default settings to prepare the system for VMX operation activation.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `Vmx`..
    pub fn new() -> Self {
        Self {
            vmxon_region: Vmxon::default(),
        }
    }

    /// Activates the VMXON region to enable VMX operation.
    ///
    /// Sets up the VMXON region and executes the VMXON instruction. This involves configuring control registers,
    /// adjusting the IA32_FEATURE_CONTROL MSR, and validating the VMXON region's revision ID to ensure the CPU is ready
    /// for VMX operation mode.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful activation, or an `Err(HypervisorError)` if any step in the activation process fails.
    pub fn activate_vmxon(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Setting up VMXON region");
        self.setup_vmxon()?;
        log::trace!("VMXON region setup successfully!");

        log::trace!("Executing VMXON instruction");
        vmxon(&mut self.vmxon_region as *const _ as _);
        log::trace!("VMXON executed successfully!");

        Ok(())
    }

    /// Prepares the system for VMX operation by configuring necessary control registers and MSRs.
    ///
    /// Ensures that the system meets all prerequisites for VMX operation as defined by Intel's specifications.
    /// This includes enabling VMX operation through control register modifications, setting the lock bit in
    /// IA32_FEATURE_CONTROL MSR, and adjusting mandatory CR0 and CR4 bits.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all configurations are successfully applied, or an `Err(HypervisorError)` if adjustments fail.
    fn setup_vmxon(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Enabling Virtual Machine Extensions (VMX)");
        Vmxon::enable_vmx_operation();
        log::trace!("VMX enabled");

        log::trace!("Adjusting IA32_FEATURE_CONTROL MSR");
        Vmxon::adjust_feature_control_msr()?;
        log::trace!("IA32_FEATURE_CONTROL MSR adjusted");

        log::trace!("Setting CR0 bits");
        Vmxon::set_cr0_bits();
        log::trace!("CR0 bits set");

        log::trace!("Setting CR4 bits");
        Vmxon::set_cr4_bits();
        log::trace!("CR4 bits set");

        self.vmxon_region.revision_id.set_bit(31, false);

        Ok(())
    }
}
