//! Memory page management for low-level system programming and virtualization.
//!
//! Provides the `Page` struct to represent and manage 4KB memory pages, with a focus on alignment and direct memory access.
//! Essential for operations requiring precise control over memory layout, such as virtual memory management, hypervisor development, and hardware interfacing.

use x86::bits64::paging::BASE_PAGE_SIZE;

/// The structure representing a single memory page (4KB).
//
// This does not _always_ have to be allocated at the page aligned address, but
// very often it is, so let us specify the alignment.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub struct Page([u8; BASE_PAGE_SIZE]);
