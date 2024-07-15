use {crate::intel::vm::Vm, core::mem::size_of};

/// Maximum number of stack memory allocations that can be recorded per logical processor (128),
/// plus one additional allocation for the image base itself.
pub const MAX_RECORDABLE_STACK_ALLOCATIONS: usize = 128 + 1;

/// Number of stack pages per logical processor.
/// Includes size of `Vm` in pages plus 0x1000 (4096) pages for padding.
/// - Size of `Vm`: 1027 pages (0x403 pages).
/// - Padding: 4096 pages (0x1000 pages).
/// - Total: 1027 + 4096 pages = 5123 pages (0x1403 pages).
/// - Total size in bytes: 5123 * 4096 = 20,971,520 bytes (20 MB).
pub const STACK_PAGES_PER_PROCESSOR: usize = (size_of::<Vm>() / 0x1000) + 0x1000;

/// Total heap size (64 MB) shared across all logical processors.
/// - Total size in bytes: 64 * 1024 * 1024 = 67,108,864 bytes (64 MB).
/// - Total size in hexadecimal: 0x4000000 bytes.
/// Increase this value if additional heap memory is needed or if more hooks are required.
pub const TOTAL_HEAP_SIZE: usize = 0x4000000;
