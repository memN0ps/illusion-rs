#![feature(new_uninit)]
#![no_main]
#![no_std]

extern crate alloc;

use {
    log::*,
    uefi::prelude::*,
    hypervisor::{
        vmm::is_hypervisor_present,
        intel::{
            capture::{capture_registers, GuestRegisters},
            ept::paging::{AccessType, Ept},
            shared_data::SharedData,
        },
        error::HypervisorError
    },
    crate::virtualize::virtualize_system,
    alloc::boxed::Box,
};

pub mod virtualize;

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize the COM2 port logger with level filter set to Info.
    com_logger::builder().base(0x2f8).filter(LevelFilter::Trace).setup();

    uefi_services::init(&mut system_table).unwrap();
    
    info!("The Matrix is an illusion");

    let mut shared_data = match setup_ept() {
        Ok(shared_data) => shared_data,
        Err(e) => panic!("Failed to setup EPT: {:?}", e),
    };

    // Capture the register values to be used as an initial state of the VM.
    let mut regs = GuestRegisters::default();
    unsafe { capture_registers(&mut regs) }

    // Since we captured RIP just above, the VM will start running from here.
    // Check if our hypervisor is already loaded. If so, done, otherwise, continue
    // installing the hypervisor.
    if !is_hypervisor_present() {
        debug!("Virtualizing the system");
        virtualize_system(&regs, &mut shared_data, &system_table);
    }

    info!("The hypervisor has been installed successfully!");
    
    //system_table.boot_services().stall(10_000_000);

    Status::SUCCESS
}

pub fn setup_ept() -> Result<Box<SharedData>, HypervisorError> {
    let mut primary_ept: Box<Ept> = unsafe { Box::new_zeroed().assume_init() };
    let mut secondary_ept: Box<Ept> = unsafe { Box::new_zeroed().assume_init() };

    debug!("Creating Primary EPT");
    primary_ept.identity_2mb(AccessType::READ_WRITE_EXECUTE)?;

    debug!("Creating Secondary EPT");
    secondary_ept.identity_2mb(AccessType::READ_WRITE_EXECUTE)?;

    let shared_data = SharedData::new(primary_ept, secondary_ept);

    shared_data
}