use {
    log::trace,
    uefi::{prelude::BootServices, proto::loaded_image::LoadedImage, table::boot::MemoryType},
};

/// Hides the hypervisor's memory in the UEFI memory map.
///
/// This function identifies the memory regions occupied by the hypervisor and
/// modifies the UEFI memory map to mark those regions as unusable. This ensures
/// that the hypervisor's memory is hidden from any UEFI-based memory queries,
/// enhancing security by preventing other components from detecting the hypervisor's memory.
///
/// # Arguments
///
/// * `boot_services` - A reference to the UEFI boot services table, which provides
///   access to UEFI protocols and services.
///
/// # Returns
///
/// Returns a `uefi::Result<()>`, which is `Ok(())` on success or an error type if the
/// operation fails at any step.
pub fn hide_uefi_memory(boot_services: &BootServices) -> uefi::Result<()> {
    // Open the LoadedImage protocol to retrieve information about the hypervisor's loaded image
    let loaded_image = boot_services.open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())?;

    // Get the base physical address and size of the hypervisor's memory
    let image_base = loaded_image.info().0 as u64;
    let image_size = loaded_image.info().1;

    // Calculate the end physical address of the hypervisor's memory
    let image_end = image_base + image_size;
    trace!("Hypervisor memory range: {:#x?} - {:#x?}", image_base, image_end);
    trace!("Hypervisor memory size: {:#x?}", image_size);

    // Retrieve the current UEFI memory map
    let mut memory_map = boot_services.memory_map(MemoryType::LOADER_DATA)?;

    // Sort the memory map entries by physical address (optional but recommended for consistency)
    memory_map.sort();

    // Iterate over the memory map to find descriptors that overlap with the hypervisor's memory
    let mut i = 0;
    loop {
        // Attempt to get a mutable reference to the memory descriptor at index `i`
        if let Some(descriptor) = memory_map.get_mut(i) {
            let start = descriptor.phys_start;
            let end = start + descriptor.page_count * 0x1000;

            // Check if the memory descriptor overlaps with the hypervisor's memory range
            if (start >= image_base && start < image_end) || (end > image_base && end <= image_end) || (start <= image_base && end >= image_end) {
                // Mark the overlapping memory as unusable to hide it from UEFI memory queries
                descriptor.ty = MemoryType::UNUSABLE;
            }

            i += 1; // Move to the next memory descriptor
        } else {
            // No more entries in the memory map, exit the loop
            break;
        }
    }

    Ok(())
}
