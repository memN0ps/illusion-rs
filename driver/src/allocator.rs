//! The module containing the [`BootTimeAllocator`] type.

use {
    core::{
        alloc::{GlobalAlloc, Layout},
        ffi::c_void,
        ptr,
        sync::atomic::{AtomicPtr, Ordering},
    },
    uefi::table::{
        boot::{AllocateType, MemoryType},
        Boot, SystemTable,
    },
};

pub const BASE_PAGE_SHIFT: usize = 12;

pub fn init(system_table: &SystemTable<Boot>) {
    SYSTEM_TABLE.store(system_table.as_ptr().cast_mut(), Ordering::Release);
}

fn system_table() -> SystemTable<Boot> {
    let ptr = SYSTEM_TABLE.load(Ordering::Acquire);
    unsafe { SystemTable::from_ptr(ptr) }.unwrap()
}

static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The global allocator based on the UEFI boot services. Any memory allocated
/// by this cannot be used after the `ExitBootServices` UEFI runtime service is
/// called. This project never lets a bootloader call that service, so not an
/// issue.
struct BootTimeAllocator;

unsafe impl GlobalAlloc for BootTimeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        // If the requested alignment is a multiple of 4KB, use `allocate_pages`
        // which allocates 4KB aligned memory with 4KB granularity.
        if (align % 0x1000) == 0 {
            system_table()
                .boot_services()
                .allocate_pages(
                    AllocateType::AnyPages,
                    MemoryType::RUNTIME_SERVICES_DATA,
                    size_to_pages(size),
                )
                .unwrap_or(0) as *mut u8
        } else if align > 8 {
            // Allocate more space for alignment.
            let Ok(ptr) = system_table()
                .boot_services()
                .allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, size + align)
            else {
                return ptr::null_mut();
            };
            // Calculate align offset.
            let mut offset = ptr.align_offset(align);
            if offset == 0 {
                offset = align;
            }
            let return_ptr = unsafe { ptr.add(offset) };
            // Store allocated pointer before the struct.
            unsafe { return_ptr.cast::<*mut u8>().sub(1).write(ptr) };
            return_ptr
        } else {
            system_table()
                .boot_services()
                .allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, size)
                .unwrap_or(ptr::null_mut())
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if (layout.align() % 0x1000) == 0 {
            unsafe {
                system_table()
                    .boot_services()
                    .free_pages(ptr as u64, size_to_pages(layout.size()))
                    .unwrap();
            };
        } else if layout.align() > 8 {
            let ptr = unsafe { ptr.cast::<*mut u8>().sub(1).read() };
            unsafe {
                system_table().boot_services().free_pool(ptr).unwrap();
            };
        } else {
            unsafe {
                system_table().boot_services().free_pool(ptr).unwrap();
            };
        }
    }
}

fn size_to_pages(size: usize) -> usize {
    const PAGE_MASK: usize = 0xfff;

    (size >> BASE_PAGE_SHIFT) + usize::from((size & PAGE_MASK) != 0)
}

#[global_allocator]
static ALLOCATOR: BootTimeAllocator = BootTimeAllocator;
