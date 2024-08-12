// This crate provides the core functionality for initializing a hypervisor environment
// within a UEFI application. It demonstrates advanced features such as custom panic handlers,
// early logging, and direct manipulation of loaded image properties for hypervisor initialization.

#![feature(new_uninit)]
#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::{hide::hide_uefi_memory, processor::start_hypervisor_on_all_processors, setup::setup, stack::init},
    hypervisor::{
        allocator::heap_init,
        logger::{self, SerialPort},
    },
    log::*,
    uefi::prelude::*,
};

pub mod hide;
pub mod processor;
pub mod setup;
pub mod stack;
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
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    unsafe {
        // Initialize the stack allocator.
        init(&mut system_table);
        // Initialize the global heap allocator.
        heap_init();
    }

    // Initialize logging with the COM2 port and set the level filter to Debug.
    logger::init(SerialPort::COM1, LevelFilter::Trace);

    info!("The Matrix is an illusion");

    let boot_services = system_table.boot_services();

    debug!("Hiding hypervisor memory from UEFI");
    if let Err(e) = hide_uefi_memory(boot_services) {
        error!("Failed to hide hypervisor memory from UEFI: {:?}", e);
        return Status::ABORTED;
    }

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
