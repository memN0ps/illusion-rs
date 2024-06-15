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
        table::{boot::MemoryType, Boot, SystemTable},
    },
};

/// The size of the heap in bytes.
const HEAP_SIZE: usize = 0x800000; // 4MB

/// Reference to the system table, used to call the boot services pool memory
/// allocation functions.
static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The memory type used for pool memory allocations.
static MEMORY_TYPE: AtomicU32 = AtomicU32::new(MemoryType::LOADER_DATA.0);

/// A global allocator that uses UEFI's pool allocation functions and tracks memory usage.
pub struct GlobalAllocator {
    /// Atomic counter to track used memory.
    used_memory: AtomicUsize,
    /// Base address of the allocated heap.
    heap_base_address: AtomicPtr<u8>,
    /// Size of the allocated heap.
    heap_size: usize,
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
            heap_base_address: AtomicPtr::new(ptr::null_mut()),
            heap_size: HEAP_SIZE,
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

        // Allocate the initial heap pool and set the base address.
        let heap_base = boot_services
            .allocate_pool(MemoryType::LOADER_DATA, self.heap_size)
            .expect("Failed to allocate heap pool");

        self.heap_base_address.store(heap_base, Ordering::Release);
    }

    /// Returns the amount of memory currently in use.
    ///
    /// # Returns
    ///
    /// The amount of memory currently in use, in bytes.
    pub fn used(&self) -> usize {
        self.used_memory.load(Ordering::SeqCst)
    }

    /// Returns the base address of the heap.
    ///
    /// # Returns
    ///
    /// The base address of the heap.
    pub fn heap_base(&self) -> *mut u8 {
        self.heap_base_address.load(Ordering::Acquire)
    }
}

/// Global allocator instance.
#[global_allocator]
pub static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

unsafe impl GlobalAlloc for GlobalAllocator {
    /// Allocates memory from the pre-allocated heap.
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
        log::debug!("Requested allocation: size = {:#x}, align = {:#x}", size, align);

        // Ensure the alignment and size fit within the heap bounds
        let used = self.used();
        log::debug!("Current used memory: {:#x}", used);
        let start = self.heap_base().add(used);
        let aligned_start = start.add(start.align_offset(align));
        let end = aligned_start.add(size);

        if end > self.heap_base().add(self.heap_size) {
            log::error!("Out of memory: requested end = {:#x}, heap end = {:#x}", end as usize, self.heap_base().add(self.heap_size) as usize);
            return ptr::null_mut(); // Out of memory
        }

        self.used_memory.fetch_add(end as usize - start as usize, Ordering::SeqCst);
        log::debug!("Allocated memory: start = {:#x}, end = {:#x}", start as usize, end as usize);

        aligned_start
    }

    /// Deallocates memory within the pre-allocated heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to be deallocated.
    /// * `layout` - The layout of the memory to be deallocated.
    unsafe fn dealloc(&self, _ptr: *mut u8, layout: Layout) {
        // Note: In a simple bump allocator, deallocation is often a no-op.
        // You might want to implement more complex free logic if needed.
        self.used_memory.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    /// Allocates zeroed memory from the pre-allocated heap.
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
