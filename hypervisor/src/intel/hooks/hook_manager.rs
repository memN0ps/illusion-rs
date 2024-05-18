use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            ept::AccessType,
            hooks::{
                inline::{InlineHook, InlineHookType},
                memory_manager::MemoryManager,
            },
            invept::invept_all_contexts,
            invvpid::invvpid_all_contexts,
            vm::Vm,
        },
        windows::kernel::KernelHook,
    },
    alloc::boxed::Box,
    core::intrinsics::copy_nonoverlapping,
    log::*,
    x86::bits64::paging::{PAddr, BASE_PAGE_SIZE},
};

/// Enum representing different types of hooks that can be applied.
#[derive(Debug, Clone, Copy)]
pub enum EptHookType {
    /// Hook for intercepting and possibly modifying function execution.
    /// Requires specifying the type of inline hook to use.
    Function(InlineHookType),

    /// Hook for hiding or monitoring access to a specific page.
    /// No inline hook type is required for page hooks.
    Page,
}

/// The maximum number of hooks supported by the hypervisor. Change this value as needed.
const MAX_ENTRIES: usize = 64;

/// Represents hook manager structures for hypervisor operations.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HookManager {
    /// The memory manager instance for the pre-allocated shadow pages and page tables.
    pub memory_manager: Box<MemoryManager<MAX_ENTRIES>>,

    /// The hook instance for the Windows kernel, storing the VA and PA of ntoskrnl.exe. This is retrieved from the first LSTAR_MSR write operation, intercepted by the hypervisor.
    pub kernel_hook: KernelHook,

    /// A flag indicating whether the CPUID cache information has been called. This will be used to perform hooks at boot time when SSDT has been initialized.
    /// KiSetCacheInformation -> KiSetCacheInformationIntel -> KiSetStandardizedCacheInformation -> __cpuid(4, 0)
    pub has_cpuid_cache_info_been_called: bool,

    /// The old RFLAGS value before turning off the interrupt flag.
    /// Used for restoring the RFLAGS register after handling the Monitor Trap Flag (MTF) VM exit.
    pub old_rflags: Option<u64>,

    /// The number of times the MTF (Monitor Trap Flag) should be triggered before disabling it for restoring overwritten instructions.
    pub mtf_counter: Option<u64>,
}

impl HookManager {
    /// Creates a new instance of `HookManager`.
    ///
    /// # Arguments
    ///
    /// * `primary_ept_pre_alloc_pts` - A mutable reference to a vector of pre-allocated page tables.
    ///
    /// # Returns
    /// A result containing a boxed `HookManager` instance or an error of type `HypervisorError`.
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        trace!("Initializing hook manager");

        let memory_manager = Box::new(MemoryManager::<MAX_ENTRIES>::new()?);

        Ok(Box::new(Self {
            memory_manager,
            has_cpuid_cache_info_been_called: false,
            kernel_hook: Default::default(),
            old_rflags: None,
            mtf_counter: None,
        }))
    }

    /// Installs an EPT hook for a function.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine instance of the hypervisor.
    /// * `guest_function_va` - The virtual address of the function or page to be hooked.
    /// * `ept_hook_type` - The type of EPT hook to be installed.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    pub fn ept_hook_function(vm: &mut Vm, guest_function_va: u64, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        debug!("Creating EPT hook for function at VA: {:#x}", guest_function_va);

        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va(guest_function_va));
        debug!("Guest function PA: {:#x}", guest_function_pa.as_u64());

        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        debug!("Guest page PA: {:#x}", guest_page_pa.as_u64());

        let guest_large_page_pa = guest_function_pa.align_down_to_large_page();
        debug!("Guest large page PA: {:#x}", guest_large_page_pa.as_u64());

        // Check and possibly split the page before fetching the shadow page
        if !vm.hook_manager.memory_manager.is_guest_page_split(guest_page_pa.as_u64()) {
            debug!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
            vm.hook_manager.memory_manager.map_guest_page_table(guest_page_pa.as_u64())?;

            let pre_alloc_pt = vm
                .hook_manager
                .memory_manager
                .get_page_table_as_mut(guest_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;
        }

        // Check and possibly copy the page before setting up the shadow function
        if !vm.hook_manager.memory_manager.is_shadow_page_copied(guest_page_pa.as_u64()) {
            debug!("Copying guest page to shadow page: {:#x}", guest_page_pa.as_u64());
            vm.hook_manager.memory_manager.map_shadow_page(guest_page_pa.as_u64())?;

            let shadow_page_pa = vm
                .hook_manager
                .memory_manager
                .get_shadow_page_as_ptr(guest_page_pa.as_u64())
                .ok_or(HypervisorError::ShadowPageNotFound)?;

            Self::unsafe_copy_guest_to_shadow(guest_page_pa, PAddr::from(shadow_page_pa));
        }

        let shadow_page_pa = PAddr::from(
            vm.hook_manager
                .memory_manager
                .get_shadow_page_as_ptr(guest_page_pa.as_u64())
                .ok_or(HypervisorError::ShadowPageNotFound)?,
        );

        let pre_alloc_pt = vm
            .hook_manager
            .memory_manager
            .get_page_table_as_mut(guest_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        match ept_hook_type {
            EptHookType::Function(inline_hook_type) => {
                let shadow_function_pa = PAddr::from(Self::calculate_function_offset_in_host_shadow_page(shadow_page_pa, guest_function_pa));
                debug!("Shadow Function PA: {:#x}", shadow_function_pa);

                debug!("Installing inline hook at shadow function PA: {:#x}", shadow_function_pa.as_u64());
                InlineHook::new(shadow_function_pa.as_u64() as *mut u8, inline_hook_type).detour64();
            }
            EptHookType::Page => {
                unimplemented!("Page hooks are not yet implemented");
            }
        }

        debug!("Changing Primary EPT permissions for page to Read-Write (RW) only: {:#x}", guest_page_pa);
        vm.primary_ept
            .modify_page_permissions(guest_page_pa.as_u64(), AccessType::READ_WRITE, pre_alloc_pt)?;

        invept_all_contexts();
        invvpid_all_contexts();

        debug!("EPT hook created and enabled successfully");

        Ok(())
    }

    /// Copies the guest page to the pre-allocated host shadow page.
    ///
    /// # Arguments
    ///
    /// * `guest_page_pa` - The physical address of the guest page.
    /// * `host_shadow_page_pa` - The physical address of the host shadow page.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs a raw memory copy from the guest page to the shadow page.
    pub fn unsafe_copy_guest_to_shadow(guest_page_pa: PAddr, host_shadow_page_pa: PAddr) {
        unsafe { copy_nonoverlapping(guest_page_pa.as_u64() as *mut u8, host_shadow_page_pa.as_u64() as *mut u8, BASE_PAGE_SIZE) };
    }

    /// Calculates the address of the function within the host shadow page.
    ///
    /// # Arguments
    ///
    /// * `host_shadow_page_pa` - The physical address of the host shadow page.
    /// * `guest_function_pa` - The physical address of the guest function.
    ///
    /// # Returns
    ///
    /// * `u64` - The adjusted address of the function within the new page.
    fn calculate_function_offset_in_host_shadow_page(host_shadow_page_pa: PAddr, guest_function_pa: PAddr) -> u64 {
        host_shadow_page_pa.as_u64() + guest_function_pa.base_page_offset()
    }
}
