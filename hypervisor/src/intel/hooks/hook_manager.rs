use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{ept::Pt, hooks::hook::EptHook, page::Page},
        windows::kernel::KernelHook,
    },
    alloc::{boxed::Box, vec::Vec},
    log::trace,
};

/// The maximum number of hooks supported by the hypervisor. Change this value as needed
pub const MAX_HOOKS: usize = 64;

/// Represents hook manager structures for hypervisor operations.
#[repr(C)]
pub struct HookManager {
    /// The EPT hook manager.
    pub ept_hooks: Vec<Box<EptHook>>,

    /// The current hook index.
    pub current_hook_index: usize,

    /// The hook instance for the Windows kernel, storing the VA and PA of ntoskrnl.exe. This is retrieved from the first LSTAR_MSR write operation, intercepted by the hypervisor.
    pub kernel_hook: KernelHook,

    /// A flag indicating whether the CPUID cache information has been called. This will be used to perform hooks at boot time when SSDT has been initialized.
    /// KiSetCacheInformation -> KiSetCacheInformationIntel -> KiSetStandardizedCacheInformation -> __cpuid(4, 0)
    pub has_cpuid_cache_info_been_called: bool,
}

impl HookManager {
    /// Creates a new instance of `HookManager`.
    ///
    /// # Returns
    /// A result containing a boxed `HookManager` instance or an error of type `HypervisorError`.
    #[rustfmt::skip]
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        trace!("Initializing hook manager");

        let mut ept_hooks = Vec::new();

        // Pre-Allocated buffers for hooks
        for _ in 0..MAX_HOOKS {
            // Create a pre-allocated shadow page for the hook.
            let host_shadow_page = unsafe { box_zeroed::<Page>() };

            // Create a pre-allocated Page Table (PT) for splitting the 2MB page into 4KB pages for the primary EPT.
            let primary_ept_pre_alloc_pt = unsafe { box_zeroed::<Pt>() };

            // Create a pre-allocated trampoline page for the hook.
            let trampoline_page = unsafe { box_zeroed::<Page>() };

            // Create a new ept hook and push it to the hook manager.
            let ept_hook = EptHook::new(host_shadow_page, primary_ept_pre_alloc_pt, trampoline_page);

            // Save the hook in the hook manager.
            ept_hooks.push(ept_hook);
        }

        Ok(Box::new(Self {
            ept_hooks,
            current_hook_index: 0,
            has_cpuid_cache_info_been_called: false,
            kernel_hook: Default::default(),
        }))
    }

    /// Tries to find a hook for the specified hook guest virtual address.
    ///
    /// # Arguments
    ///
    /// * `guest_va` - The hook guest virtual address to search for.
    ///
    /// # Returns
    ///
    /// * `Option<&mut EptHook>` - A mutable reference to the hook if found, or `None` if not found.
    pub fn find_hook_by_guest_va_as_mut(&mut self, guest_va: u64) -> Option<&mut EptHook> {
        self.ept_hooks.iter_mut().find_map(|hook| {
            if hook.guest_va.as_u64() == guest_va {
                Some(&mut **hook) // Dereference the Box to get a mutable reference to EptHook
            } else {
                None
            }
        })
    }

    /// Tries to find a hook for the specified hook guest virtual address.
    ///
    /// # Arguments
    ///
    /// * `guest_va` - The hook guest virtual address to search for.
    ///
    /// # Returns
    ///
    /// * `Option<&mut EptHook>` - A reference to the hook if found, or `None` if not found.
    pub fn find_hook_by_guest_va_as_ref(&mut self, guest_va: u64) -> Option<&EptHook> {
        self.ept_hooks.iter_mut().find_map(|hook| {
            if hook.guest_va.as_u64() == guest_va {
                Some(&**hook) // Dereference the Box to get a mutable reference to EptHook
            } else {
                None
            }
        })
    }

    /// Tries to find a hook for the specified hook guest page physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_page_pa` - The hook guest page physical address to search for.
    ///
    /// # Returns
    ///
    /// * `Option<&mut EptHook>` - A mutable reference to the hook if found, or `None` if not found.
    pub fn find_hook_by_guest_page_pa_as_mut(
        &mut self,
        guest_page_pa: u64,
    ) -> Option<&mut EptHook> {
        self.ept_hooks.iter_mut().find_map(|hook| {
            if hook.guest_pa.align_down_to_base_page().as_u64() == guest_page_pa {
                Some(&mut **hook)
            } else {
                None
            }
        })
    }

    /// Tries to find a hook for the specified hook guest page physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_page_pa` - The hook guest page physical address to search for.
    ///
    /// # Returns
    ///
    /// * `Option<&mut EptHook>` - A reference to the hook if found, or `None` if not found.
    pub fn find_hook_by_guest_page_pa_as_ref(&mut self, guest_page_pa: u64) -> Option<&EptHook> {
        self.ept_hooks.iter_mut().find_map(|hook| {
            if hook.guest_pa.align_down_to_base_page().as_u64() == guest_page_pa {
                Some(&**hook)
            } else {
                None
            }
        })
    }
}
