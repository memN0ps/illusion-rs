use bit_field::BitField;
use crate::error::HypervisorError;
use crate::intel::support::vmxon;
use crate::intel::vmxon::Vmxon;

pub struct Vmx {
    pub vmxon_region: Vmxon,
}

impl Vmx {
    pub fn new() -> Self {
        Self {
            vmxon_region: Vmxon::default(),
        }
    }

    pub fn enable(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Setting up VMXON region");
        self.setup_vmxon()?;
        log::trace!("VMXON region setup successfully!");

        log::trace!("Executing VMXON instruction");
        vmxon(&mut self.vmxon_region as *mut _ as _);
        log::trace!("VMXON executed successfully!");

        Ok(())
    }
}