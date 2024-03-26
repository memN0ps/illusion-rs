use {
    crate::windows::hooks::{
        addresses::PhysicalAddress,
        ept::inline::{InlineHook, InlineHookType},
    },
    alloc::boxed::Box,
    core::ptr::copy_nonoverlapping,
    x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE},
    x86_64::instructions::interrupts::without_interrupts,
};

/// Enum representing different types of hooks that can be applied.
pub enum HookType {
    /// Hook for intercepting and possibly modifying function execution.
    Function { inline_hook: InlineHook },

    /// Hook for hiding or monitoring access to a specific page.
    Page,
}

/// Represents a hook in the system, either on a function or a page.
pub struct Hook {
    /// Original virtual address of the target function or page.
    pub original_va: u64,

    /// Original physical address of the target function or page.
    pub original_pa: PhysicalAddress,

    /// Virtual address where the hook is placed.
    pub shadow_va: u64,

    /// Physical address of the hook.
    pub shadow_pa: PhysicalAddress,

    /// Contents of the original page where the hook is placed.
    pub shadow_page: Box<[u8]>,

    /// Virtual address of the page containing the hook.
    pub shadow_page_va: u64,

    /// Physical address of the page containing the hook.
    pub shadow_page_pa: PhysicalAddress,

    /// Type of the hook (Function or Page).
    pub hook_type: HookType,
}

impl Hook {
    /// Creates a hook on a function by its pointer.
    ///
    /// This function sets up a hook directly using the function's pointer. It copies the page where the function resides,
    /// installs a hook on that page, and then returns a `Hook` struct representing this setup.
    ///
    /// # Arguments
    ///
    /// * `original_va` - The virtual address of the function to be hooked.
    /// * `hook_handler` - The handler function to be called when the hooked function is executed.
    /// * `hook_type` - The type of hook to be installed.
    ///
    /// # Returns
    ///
    /// * `Option<Self>` - An instance of `Hook` if successful, or `None` if an error occurred.
    ///
    /// # Example
    ///
    /// `hook_function(original_va, hook_handler, hook_type)`
    pub fn hook_function(
        original_va: u64,
        hook_handler: *const (),
        hook_type: InlineHookType,
    ) -> Option<Self> {
        let original_pa = PhysicalAddress::from_va(original_va);

        // Copy the page where the function resides to prevent modifying the original page.
        let shadow_page = Self::copy_page(original_va)?;
        let shadow_page_va = shadow_page.as_ptr() as *mut u64 as u64;
        let shadow_page_pa = PhysicalAddress::from_va(shadow_page_va);

        // Calculate the virtual and physical address of the function in the copied page.
        let shadow_va = Self::address_in_page(shadow_page_va, original_va);
        let shadow_pa = PhysicalAddress::from_va(shadow_va);

        log::debug!("Hook Handler: {:#x}", hook_handler as u64);

        log::debug!("Original VA: {:#x}", original_va);
        log::debug!("Original PA: {:#x}", original_pa.as_u64());

        log::debug!("Shadow Page VA: {:#x}", shadow_page_va);
        log::debug!("Shadow Page PA: {:#x}", shadow_page_pa.as_u64());

        log::debug!("Shadow VA: {:#x}", shadow_va);
        log::debug!("Shadow PA: {:#x}", shadow_pa.as_u64());

        // Create an inline hook at the new address in the copied page.
        let inline_hook =
            InlineHook::new(original_va, Some(shadow_va), hook_handler as _, hook_type)?;

        Some(Self {
            original_va,
            original_pa,
            shadow_va,
            shadow_pa,
            shadow_page,
            shadow_page_va,
            shadow_page_pa,
            hook_type: HookType::Function { inline_hook },
        })
    }

    /// Creates a hook on a specific page.
    ///
    /// This function sets up a hook on a specific memory page, allowing for monitoring or altering the page's content.
    ///
    /// # Arguments
    ///
    /// * `original_va` - The virtual address of the page to be hooked.
    ///
    /// # Returns
    ///
    /// * `Option<Self>` - An instance of `Hook` if successful, or `None` if an error occurred.
    pub fn hook_page(original_va: u64) -> Option<Self> {
        let original_pa = PhysicalAddress::from_va(original_va);

        // Copy the target page for hooking.
        let shadow_page = Self::copy_page(original_va)?;
        let shadow_page_va = shadow_page.as_ptr() as *mut u64 as u64;
        let shadow_page_pa = PhysicalAddress::from_va(shadow_page_va);

        // In case of a page hook, the virtual and physical addresses are the same as the copied page.
        Some(Self {
            original_va,
            original_pa,
            shadow_page_va,
            shadow_page_pa,
            shadow_va: shadow_page_va,
            shadow_pa: shadow_page_pa,
            shadow_page,
            hook_type: HookType::Page,
        })
    }

    /// Creates a copy of a page in memory.
    ///
    /// This function copies the contents of a page in memory to a new location.
    ///
    /// # Arguments
    ///
    /// * `original_va` - The virtual address of the page to be copied.
    ///
    /// # Returns
    ///
    /// * `Option<Box<[u8]>>` - A boxed slice containing the copied page data.
    fn copy_page(original_va: u64) -> Option<Box<[u8]>> {
        let original_pa = PAddr::from(original_va).align_down_to_base_page();

        if original_pa.is_zero() {
            log::error!("Invalid page address: {:#x}", original_va);
            return None;
        }

        let mut shadow_page = Box::new_uninit_slice(BASE_PAGE_SIZE);

        // Perform the memory copy operation without interruptions.
        without_interrupts(|| {
            unsafe {
                copy_nonoverlapping(
                    original_pa.as_u64() as *mut u64,
                    shadow_page.as_mut_ptr() as _,
                    BASE_PAGE_SIZE,
                )
            };
        });

        Some(unsafe { shadow_page.assume_init() })
    }

    /// Calculates the address of a function within the copied page.
    ///
    /// # Arguments
    ///
    /// * `shadow_page_va` - The virtual address of the copied page.
    /// * `original_va` - The virtual address of the original function.
    ///
    /// # Returns
    ///
    /// * `u64` - The adjusted address of the function within the new page.
    fn address_in_page(shadow_page_va: u64, original_va: u64) -> u64 {
        let base_offset = VAddr::from(original_va).base_page_offset();
        shadow_page_va + base_offset
    }
}
