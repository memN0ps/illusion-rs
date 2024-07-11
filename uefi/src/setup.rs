//! Provides functionality to nullify the relocation table of a loaded UEFI image,
//! preventing UEFI from relocating hypervisor code during the transition from
//! physical to virtual addressing. This is useful for ensuring a stable memory layout in hypervisor development.

use {
    alloc::boxed::Box,
    hypervisor::{
        allocator::box_zeroed,
        intel::{
            hooks::hook_manager::{HookManager, SHARED_HOOK_MANAGER},
            page::Page,
        },
    },
    log::debug,
    uefi::{prelude::BootServices, proto::loaded_image::LoadedImage},
};

/// Sets up the hypervisor by recording the image base, creating a dummy page, initializing the shared hook manager, and nullifying relocations.
///
/// # Arguments
///
/// * `boot_services` - A reference to the UEFI boot services table.
///
/// # Returns
///
/// Returns a `uefi::Result` indicating success or failure.
pub fn setup(boot_services: &BootServices) -> uefi::Result<()> {
    let loaded_image = boot_services.open_protocol_exclusive::<LoadedImage>(boot_services.image_handle())?;
    record_image_base(&loaded_image);
    let dummpy_page_pa = create_dummy_page(0xFF);
    HookManager::initialize_shared_hook_manager(dummpy_page_pa);
    let image_base = loaded_image.info().0 as u64;
    zap_relocations(image_base);
    Ok(())
}

/// Records the base address and size of the loaded UEFI image.
///
/// This function retrieves the base address and size of the loaded UEFI image
/// and records this information for memory tracking purposes.
///
/// # Arguments
///
/// * `loaded_image` - A reference to the loaded UEFI image.
pub fn record_image_base(loaded_image: &LoadedImage) {
    let (image_base, image_size) = loaded_image.info();
    let image_range = image_base as usize..(image_base as usize + image_size as usize);
    debug!("Loaded image base: {:#x?}", image_range);

    // Lock the shared hook manager
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();
    hook_manager.record_allocation(image_base as usize, image_size as usize);
}

/// Creates a dummy page filled with a specific byte value.
///
/// This function allocates a page of memory and fills it with a specified byte value.
/// The address of the dummy page is stored in a global variable for access by multiple cores/threads/processors.
///
/// # Arguments
///
/// * `fill_byte` - The byte value to fill the page with.
pub fn create_dummy_page(fill_byte: u8) -> u64 {
    let mut dummy_page = unsafe { box_zeroed::<Page>() };
    dummy_page.0.iter_mut().for_each(|byte| *byte = fill_byte);
    let dummy_page_pa = Box::into_raw(dummy_page) as u64;
    dummy_page_pa
}

/// Nullifies the relocation table of the loaded UEFI image to prevent relocation.
///
/// This function modifies the loaded image's PE header to zero out the relocation table,
/// preventing UEFI from applying patches to the hypervisor code during the transition
/// from physical to virtual addressing by the operating system.
///
/// # Arguments
///
/// * `image_base` - The base address of the loaded UEFI image.
pub fn zap_relocations(image_base: u64) {
    // Unsafe block to directly modify the PE header of the loaded image.
    // This operation nullifies the relocation table to prevent UEFI from
    // applying relocations to the hypervisor code.
    unsafe {
        *((image_base + 0x128) as *mut u32) = 0; // Zero out the relocation table offset.
        *((image_base + 0x12c) as *mut u32) = 0; // Zero out the relocation table size.
    }
}
