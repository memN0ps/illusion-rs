#![no_main]
#![no_std]

mod images;

use uefi::{prelude::*, table::boot::LoadImageSource};

#[entry]
unsafe fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    if let Err(error) = uefi_services::init(&mut system_table) {
        log::error!("Failed to initialize UEFI services ({:?})", error);
        return Status::ABORTED;
    }

    log::info!("Searching Illusion hypervisor (illusion.efi)..");

    match images::find_hypervisor(system_table.boot_services()) {
        Some(hypervisor_device_path) => {
            log::info!("Found! Loading hypervisor into memory..");

            match system_table.boot_services().load_image(
                image_handle,
                LoadImageSource::FromDevicePath {
                    device_path: &hypervisor_device_path,
                    from_boot_manager: false,
                },
            ) {
                Ok(handle) => {
                    log::info!("Loaded hypervisor into mermoy, starting..");

                    if let Err(error) = system_table.boot_services().start_image(handle) {
                        log::error!("Failed to start hypervisor ({:?})", error);
                        return Status::ABORTED;
                    }
                }
                Err(error) => {
                    log::error!("Failed to load hypervisor ({:?})", error);
                    return Status::ABORTED;
                }
            }
        }
        None => {
            log::info!("Failed to find hypervisor image");
            return Status::ABORTED;
        }
    };

    log::info!("Searching Windows boot manager (bootmgfw.efi)..");

    match images::find_windows_boot_manager(system_table.boot_services()) {
        Some(bootmgr_device_path) => {
            log::info!("Found! Loading boot manager into memory..");

            system_table.boot_services().stall(3_000_000);

            match system_table.boot_services().load_image(
                image_handle,
                LoadImageSource::FromDevicePath {
                    device_path: &bootmgr_device_path,
                    from_boot_manager: false,
                },
            ) {
                Ok(handle) => {
                    log::info!("Loaded boot manager into memory, starting..");

                    if let Err(error) = system_table.boot_services().start_image(handle) {
                        log::error!("Failed to start boot manager ({:?})", error);
                        return Status::ABORTED;
                    }
                }
                Err(error) => {
                    log::error!("Failed to load boot manager ({:?})", error);
                    return Status::ABORTED;
                }
            }
        }
        None => {
            log::info!("Failed to find Windows boot manager image");
            return Status::ABORTED;
        }
    }

    Status::SUCCESS
}
