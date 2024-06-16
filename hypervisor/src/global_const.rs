use uefi::table::boot::MemoryType;

/// The size of the heap in bytes.
pub const HEAP_SIZE: usize = 0x180000;

/// The size of the stack in bytes.
pub const STACK_NUMBER_OF_PAGES: usize = 0x300;

/// The memory type for the stack allocated pages
pub const STACK_MEMORY_TYPE: MemoryType = MemoryType::RUNTIME_SERVICES_DATA;
