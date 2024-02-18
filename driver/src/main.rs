#![feature(new_uninit)]
#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::{
        processor::MpManager,
        virtualize::{switch_stack_and_virtualize_core, Virtualize},
    },
    alloc::boxed::Box,
    core::ffi::c_void,
    hypervisor::{
        error::HypervisorError,
        intel::{
            capture::{capture_registers, GuestRegisters},
            ept::paging::{AccessType, Ept},
            shared_data::SharedData,
        },
    },
    log::*,
    uefi::prelude::*,
};

pub mod processor;
pub mod virtualize;

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize the COM2 port logger with level filter set to Info.
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Trace)
        .setup();

    uefi_services::init(&mut system_table).unwrap();

    info!("The Matrix is an illusion");

    let mp_manager =
        MpManager::new(system_table.boot_services()).expect("Failed to create MpManager");

    // Get the processor count
    let processor_count = match mp_manager.processor_count() {
        Ok(processor_count) => processor_count,
        Err(e) => panic!("Failed to get processor count: {:?}", e),
    };

    info!("Total processors: {}", processor_count.total);
    info!("Enabled processors: {}", processor_count.enabled);

    // Setup the EPT
    let shared_data = match setup_ept() {
        Ok(shared_data) => shared_data,
        Err(e) => panic!("Failed to setup EPT: {:?}", e),
    };

    // Capture the register values to be used as an initial state of the VM.
    let mut guest_registers = GuestRegisters::default();
    unsafe { capture_registers(&mut guest_registers) }

    // Since we captured RIP just above, the VM will start running from here.
    // Check if our hypervisor is already loaded. If so, done, otherwise, continue
    // installing the hypervisor.
    if !mp_manager.is_virtualized() {
        debug!("Virtualizing the system");

        let mut virtualize = Virtualize::new(guest_registers, shared_data, &system_table);

        debug!("Virtualizing each core");
        mp_manager.set_virtualized();

        if processor_count.enabled == 1 {
            switch_stack_and_virtualize_core(&mut virtualize as *mut _ as *mut c_void);
        } else {
            match mp_manager.start_virtualization_on_all_processors(
                switch_stack_and_virtualize_core,
                &mut virtualize as *mut _ as *mut c_void,
            ) {
                Ok(_) => debug!("Virtualization started on all processors"),
                Err(e) => panic!("Failed to start virtualization on all processors: {:?}", e),
            }
        }
    }

    info!("The hypervisor has been installed successfully!");

    system_table.boot_services().stall(20_000_000);

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
