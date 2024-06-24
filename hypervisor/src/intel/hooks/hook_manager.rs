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
        tracker::{print_allocated_memory, ALLOCATED_MEMORY_HEAD},
        windows::kernel::KernelHook,
    },
    core::{
        intrinsics::copy_nonoverlapping,
        sync::atomic::{AtomicU64, Ordering},
    },
    log::*,
    x86::bits64::paging::{PAddr, BASE_PAGE_SIZE},
};

/// Global variable to store the address of the created dummy page.
/// This variable can be accessed by multiple cores/threads/processors.
pub static DUMMY_PAGE_ADDRESS: AtomicU64 = AtomicU64::new(0);

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
    pub memory_manager: MemoryManager,

    /// The hook instance for the Windows kernel, storing the VA and PA of ntoskrnl.exe. This is retrieved from the first LSTAR_MSR write operation, intercepted by the hypervisor.
    pub kernel_hook: Option<KernelHook>,

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
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing hook manager");

        let memory_manager = MemoryManager::new();
        let kernel_hook = Some(KernelHook::new()?);

        Ok(Self {
            memory_manager,
            has_cpuid_cache_info_been_called: false,
            kernel_hook,
            old_rflags: None,
            mtf_counter: None,
        })
    }

    /// Hides the hypervisor memory from the guest by installing EPT hooks on all allocated memory regions.
    ///
    /// This function iterates through the recorded memory allocations and calls `ept_hide_hypervisor_memory`
    /// for each page to split the 2MB pages into 4KB pages and fill the shadow page with a specified value.
    /// It then swaps the guest page with the shadow page and sets the desired permissions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine instance of the hypervisor.
    /// * `page_permissions` - The desired permissions for the hooked page.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the hooks were successfully installed, `Err(HypervisorError)` otherwise.
    pub fn hide_hypervisor_memory(vm: &mut Vm, page_permissions: AccessType) -> Result<(), HypervisorError> {
        // Print the tracked memory allocations for debugging purposes.
        print_allocated_memory();

        // Load the head of the allocated memory list.
        let mut current_node = ALLOCATED_MEMORY_HEAD.load(Ordering::Acquire);

        // Iterate through the linked list and hide each memory range.
        while !current_node.is_null() {
            // Get a reference to the current node.
            let node = unsafe { &*current_node };

            // Print the memory range.
            trace!("Memory Range: Start = {:#X}, Size = {}", node.start, node.size);

            // Iterate through the memory range in 4KB steps.
            for offset in (0..node.size).step_by(BASE_PAGE_SIZE) {
                let guest_page_pa = node.start + offset;
                // Print the page address before hiding it.
                trace!("Hiding memory page at: {:#X}", guest_page_pa);
                HookManager::ept_hide_hypervisor_memory(vm, PAddr::from(guest_page_pa).align_down_to_base_page().as_u64(), page_permissions)?;
            }

            // Move to the next node.
            current_node = node.next.load(Ordering::Acquire);
        }

        Ok(())
    }

    /// Hide the hypervisor memory from the guest by installing an EPT hook.
    /// This function will split the 2MB page to 4KB pages and fill the shadow page with 0xff.
    /// The guest page will be swapped with the shadow page and the permissions will be set to the desired permissions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine instance of the hypervisor.
    /// * `page_permissions` - The desired permissions for the hooked page.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    fn ept_hide_hypervisor_memory(vm: &mut Vm, guest_page_pa: u64, page_permissions: AccessType) -> Result<(), HypervisorError> {
        let guest_page_pa = PAddr::from(guest_page_pa).align_down_to_base_page();
        trace!("Guest page PA: {:#x}", guest_page_pa.as_u64());

        let guest_large_page_pa = guest_page_pa.align_down_to_large_page();
        trace!("Guest large page PA: {:#x}", guest_large_page_pa.as_u64());

        let dummy_page_pa = DUMMY_PAGE_ADDRESS.load(Ordering::SeqCst);

        trace!("Dummy page PA: {:#x}", dummy_page_pa);

        trace!("Mapping large page");
        // Map the large page to the pre-allocated page table, if it hasn't been mapped already.
        vm.hook_manager.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        let pre_alloc_pt = vm
            .hook_manager
            .memory_manager
            .get_page_table_as_mut(guest_large_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        // Check if a guest page has already been split.
        if vm.primary_ept.is_large_page(guest_page_pa.as_u64()) {
            trace!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;
        }

        trace!("Swapping guest page: {:#x} with dummy page: {:#x}", guest_page_pa.as_u64(), dummy_page_pa);
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), dummy_page_pa, page_permissions, pre_alloc_pt)?;

        invept_all_contexts();
        invvpid_all_contexts();

        trace!("EPT hide hypervisor memory completed successfully");

        Ok(())
    }

    /// Installs an EPT hook for a function.
    ///
    /// # Steps:
    /// 1. Map the large page to the pre-allocated page table, if it hasn't been mapped already.
    ///
    /// 2. Check if the large page has already been split. If not, split it into 4KB pages.
    ///
    /// 3. Check if the guest page is already processed. If not, map the guest page to the shadow page.
    ///    Ensure the memory manager maintains a set of processed guest pages to track this mapping.
    ///
    /// 4. Copy the guest page to the shadow page if it hasn't been copied already, ensuring the
    ///    shadow page contains the original function code.
    ///
    /// 5. Install the inline hook at the shadow function address if the hook type is `Function`.
    ///
    /// 6. Change the permissions of the guest page to read-write only.
    ///
    /// 7. Invalidate the EPT and VPID contexts to ensure the changes take effect.
    ///
    /// These operations are performed only once per guest page to avoid overwriting existing hooks on the same page.
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

        // 1. Map the large page to the pre-allocated page table, if it hasn't been mapped already.
        // We must map the large page to the pre-allocated page table before accessing it.
        debug!("Mapping large page");
        vm.hook_manager.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        // 2. Check if the large page has already been split. If not, split it into 4KB pages.
        debug!("Checking if large page has already been split");
        if vm.primary_ept.is_large_page(guest_page_pa.as_u64()) {
            // We must map the large page to the pre-allocated page table before accessing it.
            let pre_alloc_pt = vm
                .hook_manager
                .memory_manager
                .get_page_table_as_mut(guest_large_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            debug!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;
        }

        // 3. Check if the guest page is already processed. If not, map the guest page to the shadow page.
        // Ensure the memory manager maintains a set of processed guest pages to track this mapping.
        if !vm.hook_manager.memory_manager.is_guest_page_processed(guest_page_pa.as_u64()) {
            // We must map the guest page to the shadow page before accessing it.
            debug!("Mapping guest page and shadow page");
            vm.hook_manager.memory_manager.map_guest_to_shadow_page(
                guest_page_pa.as_u64(),
                guest_function_va,
                guest_function_pa.as_u64(),
                ept_hook_type,
                function_hash,
            )?;

            // We must map the guest page to the shadow page before accessing it.
            let shadow_page_pa = PAddr::from(
                vm.hook_manager
                    .memory_manager
                    .get_shadow_page_as_ptr(guest_page_pa.as_u64())
                    .ok_or(HypervisorError::ShadowPageNotFound)?,
            );

            // 4. Copy the guest page to the shadow page if it hasn't been copied already, ensuring the shadow page contains the original function code.
            debug!("Copying guest page to shadow page: {:#x}", guest_page_pa.as_u64());
            Self::unsafe_copy_guest_to_shadow(guest_page_pa, shadow_page_pa);

            // 5. Install the inline hook at the shadow function address if the hook type is `Function`.
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

            let pre_alloc_pt = vm
                .hook_manager
                .memory_manager
                .get_page_table_as_mut(guest_large_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            // 6. Change the permissions of the guest page to read-write only.
            debug!("Changing Primary EPT permissions for page to Read-Write (RW) only: {:#x}", guest_page_pa);
            vm.primary_ept
                .modify_page_permissions(guest_page_pa.as_u64(), AccessType::READ_WRITE, pre_alloc_pt)?;

            // 7. Invalidate the EPT and VPID contexts to ensure the changes take effect.
            invept_all_contexts();
            invvpid_all_contexts();

            debug!("EPT hook created and enabled successfully");
        } else {
            debug!("Guest page already processed, skipping hook installation and permission modification.");
        }

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

        let guest_large_page_pa = guest_function_pa.align_down_to_large_page();
        debug!("Guest large page PA: {:#x}", guest_large_page_pa.as_u64());

        let pre_alloc_pt = vm
            .hook_manager
            .memory_manager
            .get_page_table_as_mut(guest_large_page_pa.as_u64())
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

    /// Fills the shadow page with a specific byte value.
    ///
    /// # Arguments
    ///
    /// * `shadow_page_pa` - The physical address of the shadow page.
    /// * `fill_byte` - The byte value to fill the page with.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs a raw memory fill operation on the shadow page.
    pub fn unsafe_fill_shadow_page(shadow_page_pa: PAddr, fill_byte: u8) {
        unsafe {
            core::ptr::write_bytes(shadow_page_pa.as_u64() as *mut u8, fill_byte, BASE_PAGE_SIZE);
        }
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
