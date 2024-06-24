use {
    alloc::boxed::Box,
    core::{
        ptr::null_mut,
        sync::atomic::{AtomicPtr, Ordering},
    },
    log::trace,
};

/// Structure to represent a memory range.
///
/// This struct holds the start address and size of an allocated memory range.
/// It also includes an atomic pointer to the next memory range in a linked list.
#[derive(Debug)]
pub struct MemoryRangeTracker {
    pub start: usize,
    pub size: usize,
    pub next: AtomicPtr<MemoryRangeTracker>,
}

/// Global atomic pointer to the head of the allocated memory list.
///
/// This static variable holds the head of the linked list that keeps track of all allocated memory ranges.
/// It is initialized to a null pointer.
pub static ALLOCATED_MEMORY_HEAD: AtomicPtr<MemoryRangeTracker> = AtomicPtr::new(null_mut());

/// Records an allocation by adding the memory range to the global list.
///
/// This function is called whenever a new memory block is allocated. It stores the start address
/// and size of the allocated memory in the global list.
///
/// # Arguments
///
/// * `start` - The start address of the allocated memory range.
/// * `size` - The size of the allocated memory range.
pub fn record_allocation(start: usize, size: usize) {
    // Create a new memory range node.
    let new_node = Box::into_raw(Box::new(MemoryRangeTracker {
        start,
        size,
        next: AtomicPtr::new(null_mut()),
    }));

    // Update the head of the list in a lock-free manner.
    let mut current_head = ALLOCATED_MEMORY_HEAD.load(Ordering::Acquire);
    loop {
        // Set the new node's next pointer to the current head.
        unsafe { (*new_node).next.store(current_head, Ordering::Release) };

        // Attempt to update the head to the new node.
        match ALLOCATED_MEMORY_HEAD.compare_exchange(current_head, new_node, Ordering::AcqRel, Ordering::Acquire) {
            // If the head was successfully updated, break out of the loop.
            Ok(_) => break,
            // If the head was changed by another thread, update current_head and retry.
            Err(head) => current_head = head,
        }
    }
}

/// Prints the entire allocated memory range one by one.
///
/// This function iterates through the linked list of allocated memory ranges
/// and prints the start address and size of each range.
pub fn print_allocated_memory() {
    // Load the head of the allocated memory list.
    let mut current_node = ALLOCATED_MEMORY_HEAD.load(Ordering::Acquire);

    // Iterate through the linked list and print each memory range.
    while !current_node.is_null() {
        unsafe {
            // Get a reference to the current node.
            let node = &*current_node;

            // Print the memory range.
            trace!("Memory Range: Start = {:#X}, Size = {}", node.start, node.size);

            // Move to the next node.
            current_node = node.next.load(Ordering::Acquire);
        }
    }
}
