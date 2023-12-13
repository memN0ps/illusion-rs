#![no_main]
#![no_std]
#![feature(lang_items)]
#![feature(panic_info_message)]
#![feature(offset_of)]

use {
    uefi::{
        prelude::*,
        table::boot::{AllocateType, MemoryType},
    },
    core::ptr::copy_nonoverlapping,
    log::LevelFilter,
};


#[cfg(not(test))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = info.location() {
        log::error!(
            "[-] Panic in {} at ({}, {}):",
            location.file(),
            location.line(),
            location.column()
        );
        if let Some(message) = info.message() {
            log::error!("[-] {}", message);
        }
    }

    loop {}
}

/* The image handle represents the currently-running executable, and the system table provides access to many different UEFI services.
(Removed as it requires uefi_services::init)
//#[entry]
//fn main(image_handle: handle, image_handle: Handle, mut system_table: SystemTable<Boot>) { }
*/

#[no_mangle]
extern "efiapi" fn efi_main(image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    /* Setup a simple memory allocator, initialize logger, and provide panic handler. (Removed as it conflicts with com_logger) */
    //uefi_services::init(&mut system_table).unwrap();

    /* Clear stdout/stderr output screen */
    //system_table.stdout().clear().expect("Failed to clear the stdout output screen.");
    //system_table.stderr().clear().expect("Failed to clear the stderr output screen.");

    /* Setup a logger with the default settings. The default settings is COM1 port with level filter Info */
    //com_logger::init();

    // Use COM2 port with level filter Info
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Info)
        .setup();

    log::info!("UEFI Hypervisor (Illusion) in Rust");

    // Capture the register values to be used as an initial state of the VM.
    let mut regs = GuestRegisters::default();
    unsafe { capture_registers(&mut regs) };


    if virtualize().is_none() {
        log::error!("Failed to virtualize processors");
        return STATUS_UNSUCCESSFUL;
    }

    /* Make the system pause for 10 seconds */
    log::info!("[+] Stalling the processor for 10 seconds");
    system_table.boot_services().stall(10_000_000);

    /* Start Windows EFI Boot Manager (bootmgfw.efi) */
    log::info!("[+] Starting Windows EFI Boot Manager (bootmgfw.efi)...");
    boot_services
        .start_image(bootmgfw_handle)
        .expect("[-] Failed to start Windows EFI Boot Manager");

    Status::SUCCESS
}

/// The main hypervisor object.
///
/// This static mutable option holds the global instance of the hypervisor used by this driver.
static mut HYPERVISOR: Option<Hypervisor> = None;

/// Attempts to virtualize the system.
///
/// This function initializes a new hypervisor and then attempts to virtualize all
/// processors on the system.
///
/// # Returns
///
/// * `Some(())` if the system was successfully virtualized.
/// * `None` if there was an error during virtualization.
fn virtualize() -> Option<()> {
    let mut hypervisor = match Hypervisor::new() {
        Ok(hypervisor) => hypervisor,
        Err(err) => {
            log::info!("Failed to initialize hypervisor: {}", err);
            return None;
        }
    };

    match hypervisor.virtualize_system() {
        Ok(_) => log::info!("Successfully virtualized system!"),
        Err(err) => {
            log::info!("Failed to virtualize system: {}", err);
            return None;
        }
    }

    unsafe { HYPERVISOR = Some(hypervisor) };

    Some(())
}