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

/// Represents hook manager structures for hypervisor operations.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HookManager {
    /// The memory manager instance for the pre-allocated shadow pages and page tables.
    pub memory_manager: Box<MemoryManager>,

    /// The hook instance for the Windows kernel, storing the VA and PA of ntoskrnl.exe. This is retrieved from the first LSTAR_MSR write operation, intercepted by the hypervisor.
    pub kernel_hook: Option<Box<KernelHook>>,

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

        let memory_manager = Box::new(MemoryManager::new()?);
        let kernel_hook = Some(Box::new(KernelHook::new()?));

        Ok(Box::new(Self {
            memory_manager,
            has_cpuid_cache_info_been_called: false,
            kernel_hook,
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
    /// * `function_hash` - The hash of the function to be hooked.
    /// * `ept_hook_type` - The type of EPT hook to be installed.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    pub fn ept_hook_function(vm: &mut Vm, guest_function_va: u64, function_hash: u32, ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        debug!("Creating EPT hook for function at VA: {:#x}", guest_function_va);

        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va(guest_function_va));
        debug!("Guest function PA: {:#x}", guest_function_pa.as_u64());

        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        debug!("Guest page PA: {:#x}", guest_page_pa.as_u64());

        let guest_large_page_pa = guest_function_pa.align_down_to_large_page();
        debug!("Guest large page PA: {:#x}", guest_large_page_pa.as_u64());

        // Check if a guest page is already processed (split and copied).
        // If not, split the 2MB page to 4KB pages and copy the guest page to the shadow page.
        // Otherwise, the page has already been processed (split and copied) and the shadow page is ready for hooking.
        if !vm.hook_manager.memory_manager.is_guest_page_processed(guest_page_pa.as_u64()) {
            debug!("Mapping guest page and shadow page");
            vm.hook_manager.memory_manager.map_guest_page_and_shadow_page(
                guest_page_pa.as_u64(),
                guest_function_va,
                guest_function_pa.as_u64(),
                ept_hook_type,
                function_hash,
            )?;

            let pre_alloc_pt = vm
                .hook_manager
                .memory_manager
                .get_page_table_as_mut(guest_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            debug!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;

            debug!("Copying guest page to shadow page: {:#x}", guest_page_pa.as_u64());
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

        // Install the inline hook at the shadow function address, even if it's already installed (no check for now)
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

    /// Removes an EPT hook for a function.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine instance of the hypervisor.
    /// * `guest_function_va` - The virtual address of the function or page to be unhooked.
    /// * `ept_hook_type` - The type of EPT hook to be removed.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully removed, `Err(HypervisorError)` otherwise.
    pub fn ept_unhook_function(vm: &mut Vm, guest_function_va: u64, _ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        debug!("Removing EPT hook for function at VA: {:#x}", guest_function_va);

        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va(guest_function_va));
        debug!("Guest function PA: {:#x}", guest_function_pa.as_u64());

        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        debug!("Guest page PA: {:#x}", guest_page_pa.as_u64());

        let pre_alloc_pt = vm
            .hook_manager
            .memory_manager
            .get_page_table_as_mut(guest_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        // Swap the page back and restore the original page permissions
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;

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

    /// Returns the size of the hook code in bytes based on the EPT hook type.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the hook code in bytes, or 0 if the hook type is `Page`.
    pub fn hook_size(hook_type: EptHookType) -> usize {
        match hook_type {
            EptHookType::Function(inline_hook_type) => InlineHook::hook_size(inline_hook_type),
            EptHookType::Page => 0, // Assuming page hooks do not have a hook size
        }
    }

    /// Calculates the number of instructions that fit into the given number of bytes,
    /// adjusting for partial instruction overwrites by including the next full instruction.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs operations on raw pointers. The caller must
    /// ensure that the memory at `guest_pa` (converted properly to a virtual address if necessary)
    /// is valid and that reading beyond `hook_size` bytes does not cause memory violations.
    pub unsafe fn calculate_instruction_count(guest_pa: u64, hook_size: usize) -> usize {
        // Define a buffer size, typical maximum x86-64 instruction length is 15 bytes.
        let buffer_size = hook_size + 15; // Buffer size to read, slightly larger than hook_size to accommodate potential long instructions at the boundary.
        let bytes = core::slice::from_raw_parts(guest_pa as *const u8, buffer_size);

        let mut byte_count = 0;
        let mut instruction_count = 0;
        // Use a disassembler engine to iterate over the instructions within the bytes read.
        for (opcode, pa) in lde::X64.iter(bytes, guest_pa) {
            byte_count += opcode.len();
            instruction_count += 1;

            trace!("{:x}: {}", pa, opcode);
            if byte_count >= hook_size {
                break;
            }
        }

        trace!("Calculated byte count: {}", byte_count);
        trace!("Calculated instruction count: {}", instruction_count);

        instruction_count
    }
}
