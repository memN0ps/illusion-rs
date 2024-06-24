/// The default number of logical processors for a high-end desktop system.
///
/// This value is set to 1 for testing purposes but can be adjusted up to 32 or more based on the system.
/// Adjusting this value will increase the total heap size accordingly.
const DEFAULT_LOGICAL_PROCESSORS: usize = 32;

/// The total size of the heap in bytes, shared among all processors.
///
/// This base heap size is for 1 processor, calculated as:
/// 16 * 1024 * 1024 = 16,777,216 bytes (16 MB)
///
/// For 16 processors, the heap size would be:
/// 16 * 1024 * 1024 * 16 = 268,435,456 bytes (256 MB)
///
/// For 32 processors, the heap size would be:
/// 16 * 1024 * 1024 * 32 = 536,870,912 bytes (512 MB)
///
/// By adjusting the number of logical processors, the heap size will scale accordingly.
pub const TOTAL_HEAP_SIZE: usize = 16 * 1024 * 1024 * DEFAULT_LOGICAL_PROCESSORS;

/// The number of pages for the stack per processor/core.
///
/// Each processor/core gets its own stack. The default stack size per processor is calculated as:
/// STACK_PAGES_PER_PROCESSOR * BASE_PAGE_SIZE (4096 bytes per page)
/// 0x4000 * 4096 = 67,108,864 bytes (64 MB)
///
/// This stack size is allocated individually for each processor.
pub const STACK_PAGES_PER_PROCESSOR: usize = 0x4000;
