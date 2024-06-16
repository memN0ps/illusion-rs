//! This module provides a global allocator using a linked list heap allocation strategy.
//! The allocator is initialized with a fixed-size memory pool and supports memory allocation,
//! deallocation, and reallocation operations. The allocator tracks memory usage and provides
//! debugging information.

use {
    crate::global_const::HEAP_SIZE,
    alloc::boxed::Box,
    core::alloc::{GlobalAlloc, Layout},
    log::debug,
};

/// Global allocator instance with a heap size of `HEAP_SIZE`.
#[global_allocator]
pub static mut HEAP: ListHeap<HEAP_SIZE> = ListHeap::new();

/// A heap allocator based on a linked list of free chunks.
///
/// This struct manages a heap of a fixed size using a linked list
/// of free chunks. It supports memory allocation, deallocation, and
/// reallocation.
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

    /// Returns the heap as a slice.
    ///
    /// # Returns
    ///
    /// A slice representing the heap.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { &self.0.assume_init_ref()[..] }
    }

    /// Resets the heap to its default state. This must be called at the start.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it must be called exactly once before any allocations are made.
    pub unsafe fn reset(&mut self) {
        let start = self.first_link();
        let last = self.last_link();
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
    /// # Returns
    ///
    /// A pointer to the last link in the heap.
    fn last_link(&self) -> *mut Link {
        unsafe { (self.0.as_ptr() as *const u8).add(SIZE).sub(Link::SIZE) as *mut _ }
    }

    /// Debugging function to print the current state of the heap.
    pub fn _debug(&self) {
        unsafe {
            let mut total_freespace = 0usize;
            let mut total_allocations = 0usize;
            let mut total_allocation_size = 0usize;

            let mut max_freespace = 0usize;
            let mut largest_allocation = 0usize;

            let mut link = self.first_link();
            while (*link).next != link {
                let free = (&*link).free_space() as usize;
                let used = (&*link).size as usize;

                total_allocations += 1;
                total_allocation_size += used;
                total_freespace += free;
                max_freespace = max_freespace.max(free);
                largest_allocation = largest_allocation.max(used);

                link = (*link).next;
            }

            // Skip the first link
            total_allocations -= 1;

            let wasted = (total_allocations + 2) * Link::SIZE;
            debug!("Total Heap Size:                     0x{:X}", SIZE);
            debug!("Space wasted on memory management:   0x{wasted:X} bytes");
            debug!("Total memory allocated:              0x{total_allocation_size:X} bytes");
            debug!("Total memory available:              0x{total_freespace:X} bytes");
            debug!("Largest allocated buffer:            0x{largest_allocation:X} bytes");
            debug!("Largest available buffer:            0x{max_freespace:X} bytes");
            debug!("Total allocation count:              0x{total_allocations:X}");
        }
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

        // The required alignment and size for this type
        // We don't support alignments less than 0x10 because of the Link
        let required_align = layout.align().max(Link::ALIGN);
        let required_size = layout.size() as isize;

        while !(&*link).is_last() {
            if ((*link).next as usize) < (&*link).position() {
                debug!("Last: {:p}", self.last_link());
                debug!("link: {:p}", link);
                debug!("next: {:p}", (*link).next);
                debug!("size: 0x{:x}", (*link).size);
            }

            if (&*link).free_space() > required_size {
                // The effective size and start address after we account for our link
                let effective_start = (&*link).free_space_start() + Link::SIZE;
                let effective_size = (&*link).free_space() - Link::SIZE as isize;

                // Align the pointer, and adjust the size to account for the bytes we lost
                let mask = required_align - 1;
                let aligned_pointer = (effective_start + mask) & !mask;
                let aligned_size = effective_size - (aligned_pointer - effective_start) as isize;

                // If the required size is less than the effective size after alignment, use it
                if required_size < aligned_size {
                    let new_link = (aligned_pointer - Link::SIZE) as *mut Link;
                    (&mut *new_link).next = (&mut *link).next;
                    (&mut *new_link).size = required_size;
                    (&mut *link).next = new_link;

                    return aligned_pointer as *mut _;
                }
            }

            // Not enough room, keep looking
            link = (&mut *link).next;
        }

        self._debug();
        // No free memory for this allocation
        0 as *mut _
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

        // Sanity check, don't deallocate the last link
        if link.is_last() {
            return;
        }

        // Find the previous link
        let mut prev = self.first_link();
        while (&*prev).next != link {
            prev = (&*prev).next;
        }

        // Remove the link from the list, and it's deallocated
        (&mut *prev).next = link.next;
    }

    /// Tries to grow the current allocator if it can,
    /// if not just reallocates and copies the buffer to the new allocation.
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

        // Just resize the buffer
        if link.max_size() > new_size as isize {
            link.size = new_size as isize;
            return ptr;
        }

        // Construct the new layout and try to allocate it
        let nlayout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(nlayout);

        // Failed to allocate a new buffer, don't alter original data and abort
        if new_ptr.is_null() {
            return new_ptr;
        }

        // Copy data to the new array
        core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size());

        self.dealloc(ptr, layout);

        new_ptr
    }
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
    unsafe { Box::<T>::new_zeroed().assume_init() }
}
