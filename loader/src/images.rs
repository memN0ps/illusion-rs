extern crate alloc;

use {
    alloc::{borrow::ToOwned, boxed::Box, vec::Vec},
    uefi::{
        prelude::*,
        proto::{
            device_path::{
                build::{media::FilePath, DevicePathBuilder},
                DevicePath,
            },
            media::{
                file::{File, FileAttribute, FileMode},
                fs::SimpleFileSystem,
            },
        },
        table::boot::{HandleBuffer, SearchType},
        CStr16, Identify,
    },
};

const WINDOWS_BOOT_MANAGER_PATH: &CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
const HYPERVISOR_PATH: &CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\illusion.efi");

/// Finds the device path for a given file path.
///
/// # Arguments
///
/// * `boot_services` - A reference to the UEFI boot services.
/// * `path` - The file path to search for, as a `CStr16`.
///
/// # Returns
///
/// If a device containing the specified file is found, this function returns an `Option` containing
/// a `DevicePath` to the file. If no such device is found, it returns `None`.
pub(crate) fn find_device_path(
    boot_services: &BootServices,
    path: &CStr16,
) -> Option<Box<DevicePath>> {
    let handles: HandleBuffer = boot_services
        .locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
        .ok()?;

    handles.iter().find_map(|handle| {
        let mut file_system = boot_services
            .open_protocol_exclusive::<SimpleFileSystem>(*handle)
            .ok()?;

        let mut root = file_system.open_volume().ok()?;
        root.open(path, FileMode::Read, FileAttribute::READ_ONLY)
            .ok()?;

        let device_path = boot_services
            .open_protocol_exclusive::<DevicePath>(*handle)
            .ok()?;

        let mut storage = Vec::new();
        let boot_path = device_path
            .node_iter()
            .fold(
                DevicePathBuilder::with_vec(&mut storage),
                |builder, item| builder.push(&item).unwrap(),
            )
            .push(&FilePath { path_name: path })
            .ok()?
            .finalize()
            .ok()?;

        Some(boot_path.to_owned())
    })
}

/// Finds the device path of the Windows boot manager.
///
/// # Arguments
///
/// * `boot_services` - A reference to the UEFI boot services.
///
/// # Returns
///
/// If a device containing the Windows boot manager is found, this function returns an `Option` containing
/// a `DevicePath` to the file. If no such device is found, it returns `None`.
pub(crate) fn find_windows_boot_manager(boot_services: &BootServices) -> Option<Box<DevicePath>> {
    find_device_path(boot_services, WINDOWS_BOOT_MANAGER_PATH)
}

/// Finds the device path of the Illusion hypervisor.
///
/// # Arguments
///
/// * `boot_services` - A reference to the UEFI boot services.
///
/// # Returns
///
/// If a device containing the Illusion hypervisor is found, this function returns an `Option` containing
/// a `DevicePath` to the file. If no such device is found, it returns `None`.
pub(crate) fn find_hypervisor(boot_services: &BootServices) -> Option<Box<DevicePath>> {
    find_device_path(boot_services, HYPERVISOR_PATH)
}
