// This crate provides the core functionality for initializing a hypervisor environment
// within a UEFI application. It demonstrates advanced features such as custom panic handlers,
// early logging, and direct manipulation of loaded image properties for hypervisor initialization.

#![feature(new_uninit)]
#![feature(panic_info_message)]
#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::{processor::start_hypervisor_on_all_processors, setup::setup},
    hypervisor::{
        allocator::initialize_system_table_and_heap,
        logger::{self, SerialPort},
    },
    log::*,
    uefi::prelude::*,
};

pub mod processor;
pub mod setup;
pub mod virtualize;

/// Custom panic handler for the UEFI application.
///
/// # Arguments
///
/// * `info` - Information about the panic, including the location and optional message.
#[cfg(not(test))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    // Log the file, line, and column of the panic.
    if let Some(location) = info.location() {
        error!("[-] Panic in {} at ({}, {}):", location.file(), location.line(), location.column());
    }
    // Log the panic message.
    error!("[-] {}", info);

    // Enter an infinite loop as the panic handler should not return.
    loop {}
}

/// Entry point for the UEFI application.
///
/// Initializes logging, UEFI services, and attempts to start the hypervisor on all processors.
///
/// # Arguments
///
/// * `_image_handle` - Handle to the loaded image of the application.
/// * `system_table` - Reference to the UEFI System Table.
///
/// # Returns
///
/// The status of the application execution. Returns `Status::SUCCESS` on successful execution,
/// or `Status::ABORTED` if the hypervisor fails to install.
#[entry]
fn main(_image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    unsafe {
        initialize_system_table_and_heap(&system_table);
    }

    // Initialize logging with the COM2 port and set the level filter to Debug.
    logger::init(SerialPort::COM1, LevelFilter::Trace);

    info!("The Matrix is an illusion");

    let boot_services = system_table.boot_services();

    // Set up the hypervisor
    debug!("Setting up the hypervisor");
    if let Err(e) = setup(boot_services) {
        error!("Failed to set up the hypervisor: {:?}", e);
        return Status::ABORTED;
    }

    // Attempt to start the hypervisor on all processors.
    debug!("Starting hypervisor on all processors");
    if let Err(e) = start_hypervisor_on_all_processors(boot_services) {
        error!("Failed to start hypervisor on all processors: {:?}", e);
        return Status::ABORTED;
    }

    // Return success status to UEFI environment.
    Status::SUCCESS
}
