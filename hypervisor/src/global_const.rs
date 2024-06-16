use uefi::table::boot::MemoryType;

/// The size of the heap in bytes.
pub const HEAP_SIZE: usize = 0x180000;

/// The size of the stack in bytes.
pub const STACK_NUMBER_OF_PAGES: usize = 0x80;

/// The memory type for the stack allocated pages
pub const STACK_MEMORY_TYPE: MemoryType = MemoryType::RUNTIME_SERVICES_DATA;

/// The maximum number of hooks supported by the hypervisor. Change this value as needed.
pub const MAX_HOOK_ENTRIES: usize = 64;

/// The maximum number of hooks per page supported by the hypervisor. Change this value as needed.
pub const MAX_HOOKS_PER_PAGE: usize = 16;
