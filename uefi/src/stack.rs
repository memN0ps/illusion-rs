use {
    core::{
        alloc::Layout,
        ffi::c_void,
        ptr,
        sync::atomic::{AtomicPtr, AtomicU32, Ordering},
    },
    hypervisor::intel::hooks::hook_manager::SHARED_HOOK_MANAGER,
    uefi::{
        prelude::{Boot, BootServices, SystemTable},
        proto::loaded_image::LoadedImage,
        table::boot::MemoryType,
    },
};

/// Reference to the system table, used to call the boot services pool memory
/// allocation functions.
///
/// The pointer is only safe to dereference if UEFI boot services have not been
/// exited by the host application yet.
static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The memory type used for pool memory allocations.
static MEMORY_TYPE: AtomicU32 = AtomicU32::new(MemoryType::LOADER_DATA.0);

/// Initializes the allocator.
///
/// # Safety
///
/// This function is unsafe because you _must_ make sure that exit_boot_services
/// will be called when UEFI boot services will be exited.
pub unsafe fn init(system_table: &mut SystemTable<Boot>) {
    SYSTEM_TABLE.store(system_table.as_ptr().cast_mut(), Ordering::Release);

    let boot_services = system_table.boot_services();
    if let Ok(loaded_image) = boot_services.open_protocol_exclusive::<LoadedImage>(boot_services.image_handle()) {
        MEMORY_TYPE.store(loaded_image.data_type().0, Ordering::Release);
    }
}

/// Allocate memory using [`BootServices::allocate_pool`]. The allocation is
/// of type [`MemoryType::LOADER_DATA`] for UEFI applications, [`MemoryType::BOOT_SERVICES_DATA`]
/// for UEFI boot drivers and [`MemoryType::RUNTIME_SERVICES_DATA`] for UEFI runtime drivers.
pub unsafe fn allocate_host_stack(layout: Layout) -> *mut u8 {
    let size = layout.size();
    let align = layout.align();

    // Get the system table and boot services
    let memory_type = MemoryType(MEMORY_TYPE.load(Ordering::Acquire));
    let boot_services = &*boot_services();

    let stack = if align > 8 {
        // The requested alignment is greater than 8, but `allocate_pool` is
        // only guaranteed to provide eight-byte alignment. Allocate extra
        // space so that we can return an appropriately-aligned pointer
        // within the allocation.
        let full_alloc_ptr = if let Ok(ptr) = boot_services.allocate_pool(memory_type, size + align) {
            ptr.as_ptr()
        } else {
            return ptr::null_mut();
        };

        // Calculate the offset needed to get an aligned pointer within the
        // full allocation. If that offset is zero, increase it to `align`
        // so that we still have space to store the extra pointer described
        // below.
        let mut offset = full_alloc_ptr.align_offset(align);
        if offset == 0 {
            offset = align;
        }

        // Before returning the aligned allocation, store a pointer to the
        // full unaligned allocation in the bytes just before the aligned
        // allocation. We know we have at least eight bytes there due to
        // adding `align` to the memory allocation size. We also know the
        // write is appropriately aligned for a `*mut u8` pointer because
        // `align_ptr` is aligned, and alignments are always powers of two
        // (as enforced by the `Layout` type).
        let aligned_ptr = full_alloc_ptr.add(offset);
        aligned_ptr.cast::<*mut u8>().sub(1).write(full_alloc_ptr);
        aligned_ptr
    } else {
        // The requested alignment is less than or equal to eight, and
        // `allocate_pool` always provides eight-byte alignment, so we can
        // use `allocate_pool` directly.
        boot_services
            .allocate_pool(memory_type, size)
            .map(|ptr| ptr.as_ptr())
            .unwrap_or(ptr::null_mut())
    };

    // Lock the shared hook manager
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();
    hook_manager.record_allocation(stack as usize, layout.size());

    stack
}

/// Access the boot services
fn boot_services() -> *const BootServices {
    let ptr = SYSTEM_TABLE.load(Ordering::Acquire);
    let system_table = unsafe { SystemTable::from_ptr(ptr) }.expect("The system table handle is not available");
    system_table.boot_services()
}
