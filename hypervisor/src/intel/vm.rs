use alloc::boxed::Box;
use core::fmt;
use core::ptr::NonNull;
use bit_field::BitField;
use x86::vmx::vmcs;
use crate::error::HypervisorError;
use crate::intel::capture::GuestRegisters;
use crate::intel::descriptor::DescriptorTables;
use crate::intel::paging::PageTables;
use crate::intel::shared_data::SharedData;
use crate::intel::support::{vmclear, vmptrld, vmread};
use crate::intel::vmcs::Vmcs;

pub struct Vm {
    /// The VMCS (Virtual Machine Control Structure) for the VM.
    pub vmcs_region: Box<Vmcs>,

    /// The guest's descriptor tables.
    pub guest_descriptor_table: Box<DescriptorTables>,

    /// The host's descriptor tables.
    pub host_descriptor_table: Box<DescriptorTables>,

    /// The host's paging tables.
    pub host_paging: Box<PageTables>,

    /// The guest's general-purpose registers state.
    pub guest_registers: GuestRegisters,

    /// The shared data between processors.
    pub shared_data: NonNull<SharedData>,
}

impl Vm {
    pub fn new(guest_registers: &GuestRegisters, shared_data: &mut SharedData) -> Self {
        let mut vmcs = Box::<Vmcs>::default();
        let mut host_paging = unsafe { Box::<PageTables>::new_zeroed().assume_init() };

        host_paging.build_identity();

        Self {
            vmcs_region: vmcs,
            host_paging,
            guest_registers: guest_registers.clone(),
            shared_data: unsafe { NonNull::new_unchecked(shared_data as *mut _) },
        }
    }

    pub fn activate_vmcs(&mut self) -> Result<(), HypervisorError> {
        self.vmcs_region.revision_id.set_bit(31, false);

        // Clear the VMCS region.
        vmclear(&mut self.vmcs_region as *mut _ as _);
        log::trace!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(&mut self.vmcs_region as *mut _ as _);
        log::trace!("VMPTRLD successful!");

        self.setup_vmcs()?;

        Ok(())
    }

    pub fn setup_vmcs(&mut self) -> Result<(), HypervisorError> {
        Vmcs::setup_guest_registers_state(&self.guest_descriptor_table, &mut self.guest_registers)?;
        Vmcs::setup_host_registers_state(&self.host_descriptor_table, &self.host_paging)?;
        Vmcs::setup_vmcs_control_fields(&mut self.shared_data)?;

        Ok(())
    }

    // launches in a loop returns the types of vmexits
    pub fn run(&mut self) {
        //vmlaunch
    }
}