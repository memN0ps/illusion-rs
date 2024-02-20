// This crate provides the core functionality for initializing a hypervisor environment
// within a UEFI application. It demonstrates advanced features such as custom panic handlers,
// early logging, and direct manipulation of loaded image properties for hypervisor initialization.

#![feature(new_uninit)]
#![feature(panic_info_message)]
#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::processor::start_hypervisor_on_all_processors,
    hypervisor::logger,
    log::*,
    uefi::{prelude::*, proto::loaded_image::LoadedImage},
};

pub mod allocator;
pub mod processor;
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
        error!(
            "[-] Panic in {} at ({}, {}):",
            location.file(),
            location.line(),
            location.column()
        );
        // Log the panic message if available.
        if let Some(message) = info.message() {
            error!("[-] {}", message);
        }
    }

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
    // Initialize logging with the COM2 port and set the level filter to Trace.
    logger::init(LevelFilter::Trace);

    // Initialize UEFI services.
    //uefi_services::init(&mut system_table).unwrap();
    allocator::init(&system_table);

    info!("The Matrix is an illusion");

    match zap_relocations(&system_table) {
        Ok(_) => debug!("Relocations zapped successfully"),
        Err(e) => {
            error!("Failed to zap relocations: {:?}", e);
            return Status::ABORTED;
        }
    }

    // Attempt to start the hypervisor on all processors.
    match start_hypervisor_on_all_processors(&system_table) {
        Ok(_) => debug!("Hypervisor installed successfully"),
        Err(e) => {
            error!("Failed to install hypervisor: {:?}", e);
            return Status::ABORTED;
        }
    }

    // Return success status to UEFI environment.
    Status::SUCCESS
}

/// Nullifies the relocation table of the loaded UEFI image to prevent relocation.
///
/// This function manipulates the loaded image's PE header to zero out the relocation table,
/// preventing UEFI from applying patches to the hypervisor code during the transition
/// from physical-mode to virtual-mode addressing by the operating system.
///
/// # Arguments
///
/// * `system_table` - Reference to the UEFI System Table.
///
/// # Returns
///
/// The result of the operation. Returns `uefi::Result::SUCCESS` on success, or an error
pub fn zap_relocations(system_table: &SystemTable<Boot>) -> uefi::Result<()> {
    let boot_service = system_table.boot_services();

    // Obtain the current loaded image protocol.
    let loaded_image =
        boot_service.open_protocol_exclusive::<LoadedImage>(boot_service.image_handle())?;

    // Extract the image base address and size.
    let (image_base, image_size) = loaded_image.info();
    let image_base = image_base as usize;
    let image_range = image_base..image_base + image_size as usize;

    // Log the image base address range for debugging purposes.
    debug!("Image base: {:#x?}", image_range);

    // Unsafe block to directly modify the PE header of the loaded image.
    // This operation nullifies the relocation table to prevent UEFI from
    // applying relocations to the hypervisor code.
    unsafe {
        *((image_base + 0x128) as *mut u32) = 0; // Zero out the relocation table offset.
        *((image_base + 0x12c) as *mut u32) = 0; // Zero out the relocation table size.
    }

    Ok(())
}
