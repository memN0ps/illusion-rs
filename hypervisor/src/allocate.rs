//! Provides utilities for stack allocation and zero-initialized memory in hypervisor contexts.
//! Supports dynamic stack management and safe memory initialization for virtualization.

use {
    crate::intel::page::Page,
    alloc::{
        alloc::{alloc_zeroed, handle_alloc_error},
        boxed::Box,
    },
    core::alloc::Layout,
    log::debug,
};

/// Allocates stack space and returns the base address of the stack.
///
/// # Arguments
///
/// * `n` - The number of pages to allocate.
///
/// # Returns
///
/// * The base address of the allocated stack space.
pub fn allocate_stack_space(n: usize) -> u64 {
    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(n).unwrap();
    let stack = unsafe { alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + layout.size() as u64 - 0x10;
    debug!("Stack range: {:#x?}", stack as u64..stack_base);

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
    unsafe { Box::from_raw(ptr) }
}
