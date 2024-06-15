/// The size of the heap in bytes.
pub const HEAP_SIZE: usize = 0x5000000; // 80 MB

/// The size of the stack in bytes.
pub const STACK_SIZE: usize = 0x3000; // 48 MB

/// The maximum number of hooks supported by the hypervisor. Change this value as needed.
pub const MAX_HOOK_ENTRIES: usize = 64;

/// The maximum number of hooks per page supported by the hypervisor. Change this value as needed.
pub const MAX_HOOKS_PER_PAGE: usize = 16;
