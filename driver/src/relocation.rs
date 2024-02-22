use {
    log::debug,
    uefi::{prelude::BootServices, proto::loaded_image::LoadedImage},
};

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
pub fn zap_relocations(boot_service: &BootServices) -> uefi::Result<()> {
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
