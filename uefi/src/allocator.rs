//! This module provides a global allocator using UEFI's memory allocation functions.
//! It tracks memory usage and ensures thread-safe operations.

use {
    core::{
        alloc::{GlobalAlloc, Layout},
        ffi::c_void,
        ptr,
        sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering},
    },
    uefi::{
        proto::loaded_image::LoadedImage,
        table::{
            boot::{BootServices, MemoryType},
            Boot, SystemTable,
        },
    },
};

/// The size of the heap in bytes.
const HEAP_SIZE: usize = 0x10000;

/// Reference to the system table, used to call the boot services pool memory
/// allocation functions.
static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The memory type used for pool memory allocations.
static MEMORY_TYPE: AtomicU32 = AtomicU32::new(MemoryType::LOADER_DATA.0);

/// A global allocator that uses UEFI's pool allocation functions and tracks memory usage.
pub struct GlobalAllocator {
    /// Atomic counter to track used memory.
    used_memory: AtomicUsize,
}

impl GlobalAllocator {
    /// Creates a new, uninitialized GlobalAllocator.
    ///
    /// # Returns
    ///
    /// A new instance of `GlobalAllocator`.
    pub const fn new() -> Self {
        Self {
            used_memory: AtomicUsize::new(0),
        }
    }

    /// Initializes the allocator and sets the system table.
    ///
    /// # Safety
    ///
    /// This function must be called exactly once before any allocations are made.
    ///
    /// # Arguments
    ///
    /// * `system_table` - A reference to the UEFI system table.
    pub unsafe fn init(&self, system_table: &SystemTable<Boot>) {
        // Store the system table pointer for later use in allocation and deallocation.
        SYSTEM_TABLE.store(system_table.as_ptr().cast_mut(), Ordering::Release);

        // Set the memory type based on the loaded image data type.
        let boot_services = system_table.boot_services();
        if let Ok(loaded_image) = boot_services.open_protocol_exclusive::<LoadedImage>(boot_services.image_handle()) {
            MEMORY_TYPE.store(loaded_image.data_type().0, Ordering::Release);
        }
    }

    /// Returns the amount of memory currently in use.
    ///
    /// # Returns
    ///
    /// The amount of memory currently in use, in bytes.
    pub fn used(&self) -> usize {
        self.used_memory.load(Ordering::SeqCst)
    }

    /// Returns the amount of memory currently available.
    ///
    /// # Returns
    ///
    /// The amount of memory currently available, in bytes.
    pub fn free(&self) -> usize {
        HEAP_SIZE - self.used()
    }

    /// Access the boot services.
    ///
    /// # Returns
    ///
    /// A reference to the boot services.
    fn boot_services(&self) -> *const BootServices {
        let ptr = SYSTEM_TABLE.load(Ordering::Acquire);
        let system_table = unsafe { SystemTable::from_ptr(ptr) }.expect("The system table handle is not available");
        system_table.boot_services()
    }
}

/// Global allocator instance.
#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

unsafe impl GlobalAlloc for GlobalAllocator {
    /// Allocates memory using UEFI's pool allocation functions.
    ///
    /// # Arguments
    ///
    /// * `layout` - The layout of the memory to be allocated.
    ///
    /// # Returns
    ///
    /// A pointer to the allocated memory.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let memory_type = MemoryType(MEMORY_TYPE.load(Ordering::Acquire));
        let boot_services = &*self.boot_services();

        if align > 8 {
            let full_alloc_ptr = if let Ok(ptr) = boot_services.allocate_pool(memory_type, size + align) {
                ptr
            } else {
                return ptr::null_mut();
            };

            let mut offset = full_alloc_ptr.align_offset(align);
            if offset == 0 {
                offset = align;
            }

            let aligned_ptr = full_alloc_ptr.add(offset);
            aligned_ptr.cast::<*mut u8>().sub(1).write(full_alloc_ptr);
            self.used_memory.fetch_add(size, Ordering::SeqCst);
            aligned_ptr
        } else {
            let alloc_ptr = boot_services.allocate_pool(memory_type, size).map(|ptr| ptr).unwrap_or(ptr::null_mut());
            if !alloc_ptr.is_null() {
                self.used_memory.fetch_add(size, Ordering::SeqCst);
            }
            alloc_ptr
        }
    }

    /// Deallocates memory using UEFI's pool allocation functions.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to be deallocated.
    /// * `layout` - The layout of the memory to be deallocated.
    unsafe fn dealloc(&self, mut ptr: *mut u8, layout: Layout) {
        if layout.align() > 8 {
            ptr = (ptr as *const *mut u8).sub(1).read();
        }
        let boot_services = &*self.boot_services();
        boot_services.free_pool(ptr).unwrap();
        self.used_memory.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    /// Allocates zeroed memory using UEFI's pool allocation functions.
    ///
    /// # Arguments
    ///
    /// * `layout` - The layout of the memory to be allocated.
    ///
    /// # Returns
    ///
    /// A pointer to the allocated and zeroed memory.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }

    /// Reallocates memory using UEFI's pool allocation functions.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to be reallocated.
    /// * `layout` - The layout of the memory to be reallocated.
    /// * `new_size` - The new size of the memory to be allocated.
    ///
    /// # Returns
    ///
    /// A pointer to the reallocated memory.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = self.alloc(Layout::from_size_align(new_size, layout.align()).unwrap());
        if !new_ptr.is_null() {
            ptr::copy_nonoverlapping(ptr, new_ptr, layout.size());
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

/// Initializes the global heap allocator with the UEFI system table.
///
/// This function must be called before any memory allocation operations are performed.
///
/// # Safety
///
/// This function is unsafe because it must be called exactly once and must be called
/// before any allocations are made.
///
/// # Arguments
///
/// * `system_table` - A reference to the UEFI system table.
pub unsafe fn init_heap(system_table: &SystemTable<Boot>) {
    GLOBAL_ALLOCATOR.init(system_table);
}

/// Notifies the allocator library that boot services are no longer available.
///
/// This function must be called before exiting UEFI boot services.
pub fn exit_boot_services() {
    SYSTEM_TABLE.store(ptr::null_mut(), Ordering::Release);
}
