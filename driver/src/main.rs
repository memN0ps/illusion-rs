#![feature(new_uninit)]
#![feature(panic_info_message)]
#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::{processor::MpManager, virtualize::virtualize_system},
    hypervisor::{
        global::GlobalState,
        intel::capture::{capture_registers, GuestRegisters},
        logger::init_uart_logger,
    },
    log::*,
    uefi::prelude::*,
};

pub mod processor;
pub mod virtualize;

// Change as you like
#[cfg(not(test))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = info.location() {
        error!(
            "[-] Panic in {} at ({}, {}):",
            location.file(),
            location.line(),
            location.column()
        );
        if let Some(message) = info.message() {
            error!("[-] {}", message);
        }
    }

    loop {}
}

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize the COM2 port logger with level filter set to Info.
    // init_uart_logger();

    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Trace)
        .setup();

    uefi_services::init(&mut system_table).unwrap();

    info!("The Matrix is an illusion");

    // Get the MP Services (MultiProcessor Services) Protocol
    let mp_manager = match MpManager::new(system_table.boot_services()) {
        Ok(mp_manager) => mp_manager,
        Err(e) => panic!("Failed to get MP Services: {:?}", e),
    };

    // Get the processor count
    let processor_count = match mp_manager.processor_count() {
        Ok(processor_count) => processor_count,
        Err(e) => panic!("Failed to get processor count: {:?}", e),
    };

    info!("Total processors: {}", processor_count.total);
    info!("Enabled processors: {}", processor_count.enabled);

    // Capture the register values to be used as an initial state of the VM.
    let mut guest_registers = GuestRegisters::default();
    unsafe { capture_registers(&mut guest_registers) }

    // Since we captured RIP just above, the VM will start running from here.
    // Check if our hypervisor is already loaded. If so, done, otherwise, continue installing the hypervisor.
    if !mp_manager.is_virtualized() {
        debug!("Virtualizing the system");
        mp_manager.set_virtualized();

        let mut global_state = GlobalState::new(guest_registers);

        if processor_count.enabled == 1 {
            info!("Found only one processor, virtualizing it");
            virtualize_system(&mut global_state, &system_table);
        }
        /*
            else {
                info!("Found multiple processors, virtualizing all of them");
                match mp_manager.start_virtualization_on_all_processors(
                    switch_stack_and_virtualize_core,
                    &mut global_state as *mut _ as *mut c_void,
                ) {
                    Ok(_) => debug!("Virtualization started on all processors"),
                    Err(e) => panic!("Failed to start virtualization on all processors: {:?}", e),
                }
            }
        */
    }

    info!("The hypervisor has been installed successfully!");

    system_table.boot_services().stall(20_000_000);

    Status::SUCCESS
}
