use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{
            ept::{AccessType, Pt},
            hooks::hook::{EptHook, EptHookType},
            invept::invept_all_contexts,
            invvpid::invvpid_all_contexts,
            page::Page,
            vm::Vm,
        },
        windows::kernel::KernelHook,
    },
    alloc::{boxed::Box, vec::Vec},
    log::trace,
};

/// The maximum number of hooks supported by the hypervisor. Change this value as needed
pub const MAX_HOOKS: usize = 64;

/// Represents hook manager structures for hypervisor operations.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HookManager {
    /// The EPT hook manager.
    pub ept_hooks: Vec<Box<EptHook>>,

    /// The current EPT hook being used.
    pub current_hook_index: usize,

    /// The index of the hook, used to retrieve the next available pre-allocated hook,
    /// so we don't have to allocate memory on the fly and can call `ept_hook` multiple times.
    pub next_hook_index: usize,

    /// The hook instance for the Windows kernel, storing the VA and PA of ntoskrnl.exe. This is retrieved from the first LSTAR_MSR write operation, intercepted by the hypervisor.
    pub kernel_hook: KernelHook,

    /// A flag indicating whether the CPUID cache information has been called. This will be used to perform hooks at boot time when SSDT has been initialized.
    /// KiSetCacheInformation -> KiSetCacheInformationIntel -> KiSetStandardizedCacheInformation -> __cpuid(4, 0)
    pub has_cpuid_cache_info_been_called: bool,

    /// The old RFLAGS value before turning off the interrupt flag.
    /// Used for restoring the RFLAGS register after handling the Monitor Trap Flag (MTF) VM exit.
    pub old_rflags: Option<u64>,
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

            // Create a new ept hook and push it to the hook manager.
            let ept_hook = EptHook::new(host_shadow_page, primary_ept_pre_alloc_pt);

            // Save the hook in the hook manager.
            ept_hooks.push(ept_hook);
        }

        Ok(Box::new(Self {
            ept_hooks,
            current_hook_index: 0,
            next_hook_index: 0,
            has_cpuid_cache_info_been_called: false,
            kernel_hook: Default::default(),
            old_rflags: None,
        }))
    }

    /// Installs an EPT hook for a function.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine instance of the hypervisor.
    /// * guest_va - The virtual address of the function or page to be hooked.
    /// * hook_handler - The handler function to be called when the hooked function is executed.
    /// * ept_hook_type - The type of EPT hook to be installed.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    #[rustfmt::skip]
    pub fn ept_hook(vm: &mut Vm, guest_va: u64, hook_handler: *const (), ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        trace!("Creating EPT hook for function at VA: {:#x}", guest_va);

        let ept_hook = &mut vm.hook_manager.ept_hooks[vm.hook_manager.next_hook_index];

        // Set the current hook index
        trace!("Current Hook Index: {}", vm.hook_manager.current_hook_index);
        vm.hook_manager.current_hook_index = vm.hook_manager.next_hook_index;

        // Increment index to prepare for the next ept_hook call
        vm.hook_manager.next_hook_index += 1;
        trace!("Next Hook Index: {}", vm.hook_manager.next_hook_index);

        // Setup the hook based on the type
        match ept_hook_type {
            EptHookType::Function(inline_hook_type) => {
                ept_hook.hook_function(guest_va, hook_handler, inline_hook_type).ok_or(HypervisorError::HookError)?;
            },
            EptHookType::Page => {
                ept_hook.hook_page(guest_va, hook_handler, ept_hook_type).ok_or(HypervisorError::HookError)?;
            }
        }

        // Align the guest function or page address to the large page size.
        let guest_large_page_pa = ept_hook.guest_pa.align_down_to_large_page().as_u64();

        // Split the guest 2MB page into 4KB pages for the primary EPT.
        trace!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
        vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa, ept_hook.primary_ept_pre_alloc_pt.as_mut())?;

        // Align the guest function or page address to the base page size.
        let guest_page_pa = ept_hook.guest_pa.align_down_to_base_page().as_u64();

        // Modify the page permission in the primary EPT to ReadWrite for the guest page.
        trace!("Changing Primary EPT permissions for page to Read-Write (RW) only: {:#x}", guest_page_pa);
        vm.primary_ept.modify_page_permissions(guest_page_pa, AccessType::READ_WRITE, ept_hook.primary_ept_pre_alloc_pt.as_mut())?;

        // Invalidate the EPT cache for all contexts.
        invept_all_contexts();

        // Invalidate the VPID cache for all contexts.
        invvpid_all_contexts();

        trace!("EPT hook created and enabled successfully");

        Ok(())
    }

    /// Tries to find a hook by its index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the hook to retrieve.
    ///
    /// # Returns
    ///
    /// * `Option<&mut EptHook>` - A mutable reference to the hook if found, or `None` if the index is out of bounds.
    pub fn find_hook_by_index(&mut self, index: usize) -> Option<&mut EptHook> {
        self.ept_hooks.get_mut(index).map(|hook| &mut **hook)
    }

    /// Tries to find a hook by its index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the hook to retrieve.
    ///
    /// # Returns
    ///
    /// * `Option<&EptHook>` - A reference to the hook if found, or `None` if the index is out of bounds.
    pub fn find_hook_by_index_as_ref(&self, index: usize) -> Option<&EptHook> {
        self.ept_hooks.get(index).map(|hook| &**hook)
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
