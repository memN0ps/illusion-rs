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
pub struct Page(pub [u8; BASE_PAGE_SIZE]);

impl Page {
    /// Creates a new `Page` instance.
    ///
    /// # Returns
    ///
    /// * `Self` - The new `Page` instance.
    pub fn new() -> Self {
        Self([0; BASE_PAGE_SIZE])
    }

    /// Returns a mutable reference to the underlying page buffer.
    ///
    /// # Returns
    ///
    /// * `&mut [u8; 4096]` - A mutable reference to the underlying page buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8; BASE_PAGE_SIZE] {
        &mut self.0
    }

    /// Returns a reference to the underlying page buffer.
    ///
    /// # Returns
    ///
    /// * `&[u8; 4096]` - A reference to the underlying page buffer.
    pub fn as_slice(&self) -> &[u8; BASE_PAGE_SIZE] {
        &self.0
    }

    /// Returns the size of the page.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the page.
    pub fn size() -> usize {
        BASE_PAGE_SIZE
    }
}
