/// The default number of logical processors for a high-end desktop system.
///
/// This value is set to 1 for testing purposes but can be adjusted up to 64 or more based on the system.
/// Adjusting this value will increase the total heap size accordingly.
const DEFAULT_LOGICAL_PROCESSORS: usize = 16;

/// The number of pages for the stack per processor/core.
///
/// Each processor/core gets its own stack. The default stack size per processor is calculated as:
/// STACK_PAGES_PER_PROCESSOR * BASE_PAGE_SIZE (4096 bytes per page)
/// 0x4000 * 4096 = 67,108,864 bytes (64 MB)
///
/// This stack size is allocated individually for each processor.
pub const STACK_PAGES_PER_PROCESSOR: usize = 0x2000;

/// The size of a page table in bytes.
const PAGE_TABLE_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// The total number of page tables needed per processor to split the stack.
///
/// This is calculated as:
/// STACK_SIZE / PAGE_TABLE_SIZE
/// 64 MB / 2 MB = 32 page tables
const PAGE_TABLES_PER_PROCESSOR: usize = 32;

/// The padding added to the heap size for other allocations (e.g., vectors, boxes).
///
/// This is an additional memory buffer to ensure there's enough space for other dynamic allocations.
const HEAP_PADDING: usize = 8 * 1024 * 1024; // 8 MB

/// The total size of the heap in bytes, shared among all processors.
///
/// This base heap size is for 1 processor, calculated as:
/// 32 * 2 * 1024 * 1024 + 8 * 1024 * 1024 = 72,237,568 bytes (68 MB)
///
/// For 4 processors, the heap size would be:
/// (32 * 2 * 1024 * 1024 * 4) + 8 * 1024 * 1024 = 288,957,440 bytes (276 MB)
///
/// For 8 processors, the heap size would be:
/// (32 * 2 * 1024 * 1024 * 8) + 8 * 1024 * 1024 = 577,874,944 bytes (552 MB)
///
/// For 16 processors, the heap size would be:
/// (32 * 2 * 1024 * 1024 * 16) + 8 * 1024 * 1024 = 1,155,685,888 bytes (1.08 GB)
///
/// For 32 processors, the heap size would be:
/// (32 * 2 * 1024 * 1024 * 32) + 8 * 1024 * 1024 = 2,311,371,776 bytes (2.16 GB)
///
/// For 64 processors, the heap size would be:
/// (32 * 2 * 1024 * 1024 * 64) + 8 * 1024 * 1024 = 4,622,743,552 bytes (4.32 GB)
///
/// By adjusting the number of logical processors, the heap size will scale accordingly.
pub const TOTAL_HEAP_SIZE: usize = (PAGE_TABLES_PER_PROCESSOR * PAGE_TABLE_SIZE * DEFAULT_LOGICAL_PROCESSORS) + HEAP_PADDING;
