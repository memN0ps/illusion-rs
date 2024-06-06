//! Provides utilities for stack allocation and zero-initialized memory in hypervisor contexts.
//! Supports dynamic stack management and safe memory initialization for virtualization.
//! Tracks allocated memory regions for enhanced stealth capabilities.

use {
    crate::intel::page::Page,
    alloc::{
        alloc::{alloc_zeroed, handle_alloc_error},
        boxed::Box,
        collections::BTreeSet,
    },
    core::alloc::Layout,
    spin::Mutex,
};

/// A global set to keep track of allocated memory regions.
pub static ALLOCATED_MEMORY: Mutex<BTreeSet<(u64, u64)>> = Mutex::new(BTreeSet::new());

/// Records an allocated memory region.
///
/// # Arguments
///
/// * `base` - The base address of the allocated memory region.
/// * `size` - The size of the allocated memory region.
fn record_allocation(base: u64, size: u64) {
    let mut allocated_memory = ALLOCATED_MEMORY.lock();
    allocated_memory.insert((base, base + size));
}

/// Allocates stack space and returns the base address of the stack.
///
/// # Arguments
///
/// * `n` - The number of pages to allocate.
///
/// # Returns
///
/// The base address of the allocated stack space.
pub fn allocate_stack_space(n: usize) -> u64 {
    let layout = Layout::array::<Page>(n).unwrap();
    let stack = unsafe { alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + layout.size() as u64 - 0x10;
    record_allocation(stack as u64, layout.size() as u64);
    stack_base
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
    let base = ptr as u64;
    let size = layout.size() as u64;
    record_allocation(base, size);
    unsafe { Box::from_raw(ptr) }
}

/// Records an image allocation in the global memory set.
/// This function is useful for tracking allocated memory regions for enhanced stealth capabilities.
///
/// # Arguments
///
/// * `base` - The base address of the allocated memory region.
/// * `size` - The size of the allocated memory region.
pub fn record_image_allocation(base: u64, size: u64) {
    let mut allocated_memory = ALLOCATED_MEMORY.lock();
    allocated_memory.insert((base, base + size));
}
