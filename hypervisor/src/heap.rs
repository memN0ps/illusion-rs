//! This crate provides a fixed-size heap implementation and utilities for memory allocation in Rust.
//! It includes a zero-initialized memory allocation function for safe and efficient memory management.

use {crate::global_const::TOTAL_HEAP_SIZE, alloc::boxed::Box};

/// A static mutable heap of fixed size. This heap is used for memory allocation.
///
/// # Safety
///
/// This static mutable heap should be used with caution. Ensure proper synchronization
/// if accessed from multiple threads.
pub static mut HEAP: Heap<TOTAL_HEAP_SIZE> = Heap::new();

/// A heap structure with a fixed size, aligned to 4096 bytes.
///
/// This structure represents a heap with a fixed size, which can be used for
/// memory allocations within the hypervisor or other low-level system components.
///
/// # Generics
///
/// - `SIZE`: The size of the heap in bytes.
#[repr(C, align(4096))]
pub struct Heap<const SIZE: usize> {
    /// The underlying byte array representing the heap memory.
    heap: [u8; SIZE],
}

impl<const SIZE: usize> Heap<SIZE> {
    /// Creates a new instance of the heap, initialized to zero.
    ///
    /// # Returns
    ///
    /// Returns a new `Heap` instance with the specified size.
    pub const fn new() -> Self {
        Self { heap: [0u8; SIZE] }
    }

    /// Returns a mutable pointer to the heap.
    ///
    /// # Returns
    ///
    /// Returns a mutable pointer to the `Heap` instance.
    pub const fn as_mut_ptr(&mut self) -> *mut Heap<SIZE> {
        self
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
