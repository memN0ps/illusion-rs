use alloc::boxed::Box;
use bit_field::BitField;
use crate::error::HypervisorError;
use crate::intel::support::vmxon;
use crate::intel::vmxon::Vmxon;

pub struct Vmx {
    pub vmxon_region: Box<Vmxon>,
}

impl Vmx {
    pub fn new() -> Self {
        Self {
            vmxon_region: Box::<Vmxon>::default(),
        }
    }

    pub fn activate_vmxon(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Setting up VMXON region");
        self.setup_vmxon()?;
        log::trace!("VMXON region setup successfully!");

        log::trace!("Executing VMXON instruction");
        vmxon(&mut self.vmxon_region as *mut _ as _);
        log::trace!("VMXON executed successfully!");

        Ok(())
    }

    /// Enables VMX operation by setting appropriate bits and executing the VMXON instruction.
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