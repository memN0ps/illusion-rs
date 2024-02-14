#![no_main]
#![no_std]

extern crate alloc;

use {
    log::*,
    uefi::prelude::*,
    hypervisor::vmm::is_hypervisor_present,
    crate::{virtualize::virtualize_system, capture::{capture_registers, GuestRegisters}},
};

pub mod virtualize;

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize the COM2 port logger with level filter set to Info.
    com_logger::builder().base(0x2f8).filter(LevelFilter::Trace).setup();

    uefi_services::init(&mut system_table).unwrap();
    
    info!("The Matrix is an illusion");

    // Capture the register values to be used as an initial state of the VM.
    let mut regs = GuestRegisters::default();
    unsafe { capture_registers(&mut regs) }

    // Since we captured RIP just above, the VM will start running from here.
    // Check if our hypervisor is already loaded. If so, done, otherwise, continue
    // installing the hypervisor.
    if !is_hypervisor_present() {
        debug!("Virtualizing the system");
        virtualize_system(&regs, &system_table);
    }

    info!("The hypervisor has been installed successfully!");
    
    //system_table.boot_services().stall(10_000_000);

    Status::SUCCESS
}
