#![allow(unused)]

use core::alloc::{GlobalAlloc, Layout};
use log::debug;

#[global_allocator]
pub static mut HEAP: ListHeap<0x180000> = ListHeap::new();

#[repr(align(0x10))]
pub struct ListHeap<const SIZE: usize>(core::mem::MaybeUninit<[u8; SIZE]>);

impl<const SIZE: usize> ListHeap<SIZE> {
    pub const fn new() -> Self {
        Self(core::mem::MaybeUninit::uninit())
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { &self.0.assume_init_ref()[..] }
    }

    /// resets the heap to its default state, this MUST be called at the start
    pub unsafe fn reset(&mut self) {
        let start = self.first_link();
        let last = self.last_link();
        (&mut *start).size = 0;
        (&mut *start).next = last;
        (&mut *last).size = 0;
        (&mut *last).next = last;
    }

    fn first_link(&self) -> *mut Link {
        self.0.as_ptr() as *mut _
    }

    fn last_link(&self) -> *mut Link {
        unsafe { (self.0.as_ptr() as *const u8).add(SIZE).sub(Link::SIZE) as *mut _ }
    }

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

            // skip the first link
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

#[repr(C, align(0x10))]
struct Link {
    next: *mut Link,
    size: isize,
}

impl Link {
    const SIZE: usize = core::mem::size_of::<Link>();
    const ALIGN: usize = core::mem::align_of::<Link>();

    // gets the start of the buffer
    pub fn position(&self) -> usize {
        self as *const _ as usize + Link::SIZE
    }

    pub fn is_last(&self) -> bool {
        self.next as *const _ == self
    }

    pub fn max_size(&self) -> isize {
        (self.next as usize - self.position()) as isize
    }

    pub fn free_space(&self) -> isize {
        self.max_size() - self.size
    }

    pub fn free_space_start(&self) -> usize {
        self.position() + self.size as usize
    }
}

unsafe impl<const SIZE: usize> GlobalAlloc for ListHeap<SIZE> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut link = self.first_link();

        // the required alignment and size for this type
        // we don't support alignments less than 0x10 because of the Link
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
                // the effective size and start address after we account for our link
                let effective_start = (&*link).free_space_start() + Link::SIZE;
                let effective_size = (&*link).free_space() - Link::SIZE as isize;

                // align the pointer, and adjust the size to account for the bytes we lost
                let mask = required_align - 1;
                let aligned_pointer = (effective_start + mask) & !mask;
                let aligned_size = effective_size - (aligned_pointer - effective_start) as isize;

                // if the required size is less than the effect size after alignment... use it
                if required_size < aligned_size {
                    let new_link = (aligned_pointer - Link::SIZE) as *mut Link;
                    (&mut *new_link).next = (&mut *link).next;
                    (&mut *new_link).size = required_size;
                    (&mut *link).next = new_link;

                    return aligned_pointer as *mut _;
                }
            }

            // not enough room, keep looking
            link = (&mut *link).next;
        }

        self._debug();
        // no free memory for this allocation :(
        0 as *mut _
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let link = &mut *(ptr.sub(core::mem::size_of::<Link>()) as *mut Link);

        // sanity check, don't de-alloc the last link
        if link.is_last() {
            return;
        }

        // find the previous link
        let mut prev = self.first_link();
        while (&*prev).next != link {
            prev = (&*prev).next
        }

        // remove the link from the list, and its de-allocated
        (&mut *prev).next = link.next;
    }

    /// Tries to grow the current allocator if it can,
    /// if not just re-allocates and copies the buffer to the new allocation
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let link = &mut *(ptr.sub(core::mem::size_of::<Link>()) as *mut Link);

        // just resize the buffer
        if link.max_size() > new_size as isize {
            link.size = new_size as isize;
            return ptr;
        }

        // construct the new layout and try to allocate it
        let nlayout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(nlayout);

        // failed to alloc a new buffer, don't alter original data and abort
        if new_ptr.is_null() {
            return new_ptr;
        }

        // copy data to the new array
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
    let layout = Layout::new::<T>();
    let ptr = unsafe { alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}