/// The default number of logical processors for a high-end desktop system.
///
/// This value is set to 1 for testing purposes but can be adjusted up to 32 or more based on the system.
/// Adjusting this value will increase the total heap size accordingly.
const DEFAULT_LOGICAL_PROCESSORS: usize = 1;

/// The total size of the heap in bytes, shared among all processors.
///
/// This base heap size is for 1 processor, calculated as:
/// 64 * 1024 * 1024 = 67,108,864 bytes (64 MB)
///
/// For 32 processors, the heap size would be:
/// 64 * 1024 * 1024 * 32 = 2,147,483,648 bytes (2 GB)
///
/// By adjusting the number of logical processors, the heap size will scale accordingly.
pub const TOTAL_HEAP_SIZE: usize = 64 * 1024 * 1024 * DEFAULT_LOGICAL_PROCESSORS;

/// The number of pages for the stack per processor/core.
///
/// Each processor/core gets its own stack. The default stack size per processor is calculated as:
/// STACK_PAGES_PER_PROCESSOR * BASE_PAGE_SIZE (4096 bytes per page)
/// 0x100 * 4096 = 1,048,576 bytes (1 MB)
///
/// This stack size is allocated individually for each processor.
pub const STACK_PAGES_PER_PROCESSOR: usize = 0x100;
