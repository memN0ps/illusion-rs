//! This module provides a global allocator using UEFI's memory allocation functions.
//! It tracks memory usage and ensures thread-safe operations.

use {
    crate::global_const::HEAP_SIZE,
    alloc::{
        alloc::{alloc_zeroed, handle_alloc_error},
        boxed::Box,
    },
    core::{
        alloc::{GlobalAlloc, Layout},
        ffi::c_void,
        mem::{align_of, size_of},
        ptr,
        sync::atomic::{AtomicPtr, AtomicU32, Ordering},
    },
    log::trace,
    uefi::{
        proto::loaded_image::LoadedImage,
        table::{boot::MemoryType, Boot, SystemTable},
    },
};

/// Reference to the system table, used to call the boot services pool memory
/// allocation functions.
static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The memory type used for pool memory allocations.
static MEMORY_TYPE: AtomicU32 = AtomicU32::new(MemoryType::LOADER_DATA.0);

/// A global allocator that uses UEFI's pool allocation functions and tracks memory usage.
pub struct GlobalAllocator {
    /// Heap allocator instance
    heap: ListHeap<{ HEAP_SIZE }>,
}

impl GlobalAllocator {
    /// Creates a new, uninitialized GlobalAllocator.
    ///
    /// # Returns
    ///
    /// A new instance of `GlobalAllocator`.
    pub const fn new() -> Self {
        Self { heap: ListHeap::new() }
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
        trace!("Initializing global allocator");

        // Store the system table pointer for later use in allocation and deallocation.
        SYSTEM_TABLE.store(system_table.as_ptr().cast_mut(), Ordering::Release);

        // Set the memory type based on the loaded image data type.
        let boot_services = system_table.boot_services();
        if let Ok(loaded_image) = boot_services.open_protocol_exclusive::<LoadedImage>(boot_services.image_handle()) {
            MEMORY_TYPE.store(loaded_image.data_type().0, Ordering::Release);
        }

        // Allocate the initial heap pool and set the base address.
        let heap_base = boot_services
            .allocate_pool(MemoryType::LOADER_DATA, HEAP_SIZE)
            .expect("Failed to allocate heap pool");

        self.heap.initialize(heap_base);
    }

    /// Returns the amount of memory currently in use.
    ///
    /// # Returns
    ///
    /// The amount of memory currently in use, in bytes.
    pub fn used(&self) -> usize {
        unsafe { self.heap.used_memory() }
    }

    /// Returns the base address of the heap.
    ///
    /// # Returns
    ///
    /// The base address of the heap.
    pub fn heap_base(&self) -> *mut u8 {
        self.heap.base_address()
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
        trace!("Allocating memory: size = {:#x}, align = {:#x}", layout.size(), layout.align());
        self.heap.alloc(layout)
    }

    /// Deallocates memory within the pre-allocated heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to be deallocated.
    /// * `layout` - The layout of the memory to be deallocated.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        trace!("Deallocating memory: ptr = {:p}, size = {:#x}", ptr, layout.size());
        self.heap.dealloc(ptr, layout)
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
        trace!("Allocating zeroed memory: size = {:#x}, align = {:#x}", layout.size(), layout.align());
        self.heap.alloc_zeroed(layout)
    }
}

/// A heap allocator based on a linked list of free chunks.
#[repr(align(0x10))]
pub struct ListHeap<const SIZE: usize>(core::mem::MaybeUninit<[u8; SIZE]>);

impl<const SIZE: usize> ListHeap<SIZE> {
    /// Creates a new, uninitialized ListHeap.
    ///
    /// # Returns
    ///
    /// A new instance of `ListHeap`.
    pub const fn new() -> Self {
        Self(core::mem::MaybeUninit::uninit())
    }

    /// Initializes the heap with the given base address.
    ///
    /// # Safety
    ///
    /// This function must be called exactly once before any allocations are made.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The base address of the allocated heap.
    pub unsafe fn initialize(&self, base_address: *mut u8) {
        trace!("Initializing heap at base address: {:p}", base_address);

        let start = self.first_link();
        let last = self.last_link(base_address);
        (&mut *start).size = 0;
        (&mut *start).next = last;
        (&mut *last).size = 0;
        (&mut *last).next = last;
    }

    /// Returns the first link in the heap.
    ///
    /// # Returns
    ///
    /// A pointer to the first link in the heap.
    fn first_link(&self) -> *mut Link {
        self.0.as_ptr() as *mut _
    }

    /// Returns the last link in the heap.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The base address of the allocated heap.
    ///
    /// # Returns
    ///
    /// A pointer to the last link in the heap.
    fn last_link(&self, base_address: *mut u8) -> *mut Link {
        unsafe { (base_address as *const u8).add(SIZE).sub(Link::SIZE) as *mut _ }
    }

    /// Returns the amount of memory currently in use.
    ///
    /// # Safety
    ///
    /// This function must be called from a safe context where memory is not concurrently modified.
    ///
    /// # Returns
    ///
    /// The amount of memory currently in use, in bytes.
    pub unsafe fn used_memory(&self) -> usize {
        let mut used = 0;
        let mut link = self.first_link();
        while !(&*link).is_last() {
            used += (&*link).size as usize;
            link = (&*link).next;
        }
        used
    }

    /// Returns the base address of the heap.
    ///
    /// # Returns
    ///
    /// The base address of the heap.
    pub fn base_address(&self) -> *mut u8 {
        self.0.as_ptr() as *mut _
    }
}

/// A structure representing a link in a linked list heap.
///
/// This struct is used to manage free and allocated memory chunks in the heap.
/// Each link points to the next chunk and tracks the size of the current chunk.
#[repr(C, align(0x10))]
struct Link {
    /// Pointer to the next link in the list.
    next: *mut Link,
    /// Size of the current chunk.
    size: isize,
}

impl Link {
    const SIZE: usize = size_of::<Link>();
    const ALIGN: usize = align_of::<Link>();

    /// Gets the start of the buffer.
    ///
    /// # Returns
    ///
    /// The start position of the buffer.
    pub fn position(&self) -> usize {
        self as *const _ as usize + Link::SIZE
    }

    /// Checks if the link is the last in the list.
    ///
    /// # Returns
    ///
    /// `true` if the link is the last, `false` otherwise.
    pub fn is_last(&self) -> bool {
        self.next as *const _ == self
    }

    /// Returns the maximum size available for allocation.
    ///
    /// # Returns
    ///
    /// The maximum size available for allocation.
    pub fn max_size(&self) -> isize {
        (self.next as usize - self.position()) as isize
    }

    /// Returns the free space available for allocation.
    ///
    /// # Returns
    ///
    /// The free space available for allocation.
    pub fn free_space(&self) -> isize {
        self.max_size() - self.size
    }

    /// Returns the start position of the free space.
    ///
    /// # Returns
    ///
    /// The start position of the free space.
    pub fn free_space_start(&self) -> usize {
        self.position() + self.size as usize
    }
}

unsafe impl<const SIZE: usize> GlobalAlloc for ListHeap<SIZE> {
    /// Allocates memory from the linked list heap.
    ///
    /// # Arguments
    ///
    /// * `layout` - The layout of the memory to be allocated.
    ///
    /// # Returns
    ///
    /// A pointer to the allocated memory.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut link = self.first_link();

        let required_align = layout.align().max(Link::ALIGN);
        let required_size = layout.size() as isize;

        while !(&*link).is_last() {
            if (&*link).free_space() > required_size {
                let effective_start = (&*link).free_space_start() + Link::SIZE;
                let effective_size = (&*link).free_space() - Link::SIZE as isize;

                let mask = required_align - 1;
                let aligned_pointer = (effective_start + mask) & !mask;
                let aligned_size = effective_size - (aligned_pointer - effective_start) as isize;

                if required_size < aligned_size {
                    let new_link = (aligned_pointer - Link::SIZE) as *mut Link;
                    (&mut *new_link).next = (&mut *link).next;
                    (&mut *new_link).size = required_size;
                    (&mut *link).next = new_link;

                    trace!("Allocated memory: ptr = {:p}, size = {:#x}", aligned_pointer as *mut u8, layout.size());
                    return aligned_pointer as *mut _;
                }
            }
            link = (&mut *link).next;
        }

        ptr::null_mut()
    }

    /// Deallocates memory within the linked list heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to be deallocated.
    /// * `layout` - The layout of the memory to be deallocated.
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let link = &mut *(ptr.sub(size_of::<Link>()) as *mut Link);

        if link.is_last() {
            return;
        }

        let mut prev = self.first_link();
        while (&*prev).next != link {
            prev = (&*prev).next;
        }

        (&mut *prev).next = link.next;
    }

    /// Allocates zeroed memory from the linked list heap.
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

    /// Reallocates memory within the linked list heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to be reallocated.
    /// * `layout` - The current layout of the memory.
    /// * `new_size` - The new size of the memory to be allocated.
    ///
    /// # Returns
    ///
    /// A pointer to the reallocated memory.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let link = &mut *(ptr.sub(size_of::<Link>()) as *mut Link);

        if link.max_size() > new_size as isize {
            link.size = new_size as isize;
            return ptr;
        }

        let nlayout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(nlayout);

        if new_ptr.is_null() {
            return new_ptr;
        }

        ptr::copy_nonoverlapping(ptr, new_ptr, layout.size());
        self.dealloc(ptr, layout);

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

/// Allocates and zeros memory for a given type, returning a boxed instance.
///
/// # Safety
///
/// This function allocates memory and initializes it to zero. It must be called
/// in a safe context where allocation errors and uninitialized memory access are handled.
///
/// # Returns
///
/// Returns a `Box<T>` pointing to the zero-initialized memory of type `T`.
///
/// # Panics
///
/// Panics if memory allocation fails.
pub unsafe fn box_zeroed<T>() -> Box<T> {
    let layout = Layout::new::<T>();
    let ptr = unsafe { alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}
