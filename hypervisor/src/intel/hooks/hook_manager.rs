use {
    crate::{
        allocator::{box_zeroed, print_tracked_allocations, ALLOCATED_MEMORY},
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
            page::Page,
            vm::Vm,
        },
        windows::{
            nt::pe::{get_export_by_hash, get_image_base_address, get_size_of_image},
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    alloc::{boxed::Box, sync::Arc},
    core::intrinsics::copy_nonoverlapping,
    lazy_static::lazy_static,
    log::*,
    spin::{Mutex, MutexGuard},
    x86::bits64::paging::{PAddr, BASE_PAGE_SIZE},
};

lazy_static! {
    /// Global instance of HookManager wrapped in a Mutex for thread-safe access.
    pub static ref GLOBAL_HOOK_MANAGER: Arc<Mutex<HookManager>> = Arc::new(Mutex::new(HookManager::new().expect("Failed to create HookManager instance")));
}

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

    /// The base address of ntoskrnl.exe.
    pub ntoskrnl_base_va: u64,

    /// The physical address of ntoskrnl.exe.
    pub ntoskrnl_base_pa: u64,

    /// The size of ntoskrnl.exe.
    pub ntoskrnl_size: u64,

    /// A flag indicating whether the CPUID cache information has been called. This will be used to perform hooks at boot time when SSDT has been initialized.
    /// KiSetCacheInformation -> KiSetCacheInformationIntel -> KiSetStandardizedCacheInformation -> __cpuid(4, 0)
    pub has_cpuid_cache_info_been_called: bool,

    /// The old RFLAGS value before turning off the interrupt flag.
    /// Used for restoring the RFLAGS register after handling the Monitor Trap Flag (MTF) VM exit.
    pub old_rflags: Option<u64>,

    /// The number of times the MTF (Monitor Trap Flag) should be triggered before disabling it for restoring overwritten instructions.
    pub mtf_counter: Option<u64>,

    pub dummy_page: Box<Page>,
}

impl HookManager {
    /// Creates a new instance of `HookManager`.
    ///
    /// # Returns
    /// A result containing a boxed `HookManager` instance or an error of type `HypervisorError`.
    pub fn new() -> Result<Self, HypervisorError> {
        trace!("Initializing hook manager");

        let memory_manager = MemoryManager::new();
        let dummy_page = HookManager::create_dummy_page(0xff);

        Ok(Self {
            memory_manager,
            has_cpuid_cache_info_been_called: false,
            ntoskrnl_base_va: 0,
            ntoskrnl_base_pa: 0,
            ntoskrnl_size: 0,
            old_rflags: None,
            mtf_counter: None,
            dummy_page,
        })
    }

    /// Returns a reference to the global HookManager instance.
    pub fn get_hook_manager_ref() -> Arc<Mutex<HookManager>> {
        Arc::clone(&GLOBAL_HOOK_MANAGER)
    }

    /// Locks and returns a mutable reference to the global HookManager instance.
    pub fn get_hook_manager_mut() -> MutexGuard<'static, HookManager> {
        GLOBAL_HOOK_MANAGER.lock()
    }

    /// Creates a dummy page filled with a specific byte value.
    ///
    /// This function allocates a page of memory and fills it with a specified byte value.
    /// The address of the dummy page is stored in a global variable for access by multiple cores/threads/processors.
    ///
    /// # Arguments
    ///
    /// * `fill_byte` - The byte value to fill the page with.
    pub fn create_dummy_page(fill_byte: u8) -> Box<Page> {
        let mut dummy_page = unsafe { box_zeroed::<Page>() };
        dummy_page.0.iter_mut().for_each(|byte| *byte = fill_byte);
        dummy_page
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
    pub fn hide_hypervisor_memory(hook_manager: &mut HookManager, vm: &mut Vm, page_permissions: AccessType) -> Result<(), HypervisorError> {
        // Print the tracked memory allocations for debugging purposes.
        print_tracked_allocations();

        // Lock the allocated memory list to ensure thread safety.
        let allocated_memory = ALLOCATED_MEMORY.lock();

        // Iterate through the recorded memory allocations and hide each page.
        for range in allocated_memory.iter() {
            for offset in (0..range.size).step_by(BASE_PAGE_SIZE) {
                let guest_page_pa = range.start + offset;
                HookManager::ept_hide_hypervisor_memory(
                    hook_manager,
                    vm,
                    PAddr::from(guest_page_pa).align_down_to_base_page().as_u64(),
                    page_permissions,
                )?;
            }
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
    /// * `guest_page_pa` - The physical address of the guest page.
    /// * `page_permissions` - The desired permissions for the hooked page.
    ///
    /// # Returns
    ///
    /// * Returns `Ok(())` if the hook was successfully installed, `Err(HypervisorError)` otherwise.
    fn ept_hide_hypervisor_memory(
        hook_manager: &mut HookManager,
        vm: &mut Vm,
        guest_page_pa: u64,
        page_permissions: AccessType,
    ) -> Result<(), HypervisorError> {
        let guest_page_pa = PAddr::from(guest_page_pa).align_down_to_base_page();
        trace!("Guest page PA: {:#x}", guest_page_pa.as_u64());

        let guest_large_page_pa = guest_page_pa.align_down_to_large_page();
        trace!("Guest large page PA: {:#x}", guest_large_page_pa.as_u64());

        let dummy_page_pa = hook_manager.dummy_page.0.as_mut_ptr() as u64;
        trace!("Dummy page PA: {:#x}", dummy_page_pa);

        trace!("Mapping large page");
        // Map the large page to the pre-allocated page table, if it hasn't been mapped already.
        hook_manager.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        let pre_alloc_pt = hook_manager
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
    pub fn ept_hook_function(
        hook_manager: &mut HookManager,
        vm: &mut Vm,
        guest_function_va: u64,
        function_hash: u32,
        ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
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
        hook_manager.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        // 2. Check if the large page has already been split. If not, split it into 4KB pages.
        debug!("Checking if large page has already been split");
        if vm.primary_ept.is_large_page(guest_page_pa.as_u64()) {
            // We must map the large page to the pre-allocated page table before accessing it.
            let pre_alloc_pt = hook_manager
                .memory_manager
                .get_page_table_as_mut(guest_large_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            debug!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", guest_large_page_pa);
            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;
        }

        // 3. Check if the guest page is already processed. If not, map the guest page to the shadow page.
        // Ensure the memory manager maintains a set of processed guest pages to track this mapping.
        if !hook_manager.memory_manager.is_guest_page_processed(guest_page_pa.as_u64()) {
            // We must map the guest page to the shadow page before accessing it.
            debug!("Mapping guest page and shadow page");
            hook_manager.memory_manager.map_guest_to_shadow_page(
                guest_page_pa.as_u64(),
                guest_function_va,
                guest_function_pa.as_u64(),
                ept_hook_type,
                function_hash,
            )?;

            // We must map the guest page to the shadow page before accessing it.
            let shadow_page_pa = PAddr::from(
                hook_manager
                    .memory_manager
                    .get_shadow_page_as_ptr(guest_page_pa.as_u64())
                    .ok_or(HypervisorError::ShadowPageNotFound)?,
            );

            // 4. Copy the guest page to the shadow page if it hasn't been copied already, ensuring the shadow page contains the original function code.
            debug!("Copying guest page to shadow page: {:#x}", guest_page_pa.as_u64());
            HookManager::unsafe_copy_guest_to_shadow(guest_page_pa, shadow_page_pa);

            // 5. Install the inline hook at the shadow function address if the hook type is `Function`.
            match ept_hook_type {
                EptHookType::Function(inline_hook_type) => {
                    let shadow_function_pa =
                        PAddr::from(HookManager::calculate_function_offset_in_host_shadow_page(shadow_page_pa, guest_function_pa));
                    debug!("Shadow Function PA: {:#x}", shadow_function_pa);

                    debug!("Installing inline hook at shadow function PA: {:#x}", shadow_function_pa.as_u64());
                    InlineHook::new(shadow_function_pa.as_u64() as *mut u8, inline_hook_type).detour64();
                }
                EptHookType::Page => {
                    unimplemented!("Page hooks are not yet implemented");
                }
            }

            let pre_alloc_pt = hook_manager
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
    pub fn ept_unhook_function(
        hook_manager: &mut HookManager,
        vm: &mut Vm,
        guest_function_va: u64,
        _ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
        debug!("Removing EPT hook for function at VA: {:#x}", guest_function_va);

        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va(guest_function_va));
        debug!("Guest function PA: {:#x}", guest_function_pa.as_u64());

        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        debug!("Guest page PA: {:#x}", guest_page_pa.as_u64());

        let guest_large_page_pa = guest_function_pa.align_down_to_large_page();
        debug!("Guest large page PA: {:#x}", guest_large_page_pa.as_u64());

        let pre_alloc_pt = hook_manager
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

    /// Sets the base address and size of the Windows kernel.
    ///
    /// # Arguments
    ///
    /// * `guest_va` - The virtual address of the guest.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The kernel base and size were set successfully.
    pub fn set_kernel_base_and_size(&mut self, guest_va: u64) -> Result<(), HypervisorError> {
        // Get the base address of ntoskrnl.exe.
        self.ntoskrnl_base_va = unsafe { get_image_base_address(guest_va).ok_or(HypervisorError::FailedToGetImageBaseAddress)? };

        // Get the physical address of ntoskrnl.exe using GUEST_CR3 and the virtual address.
        self.ntoskrnl_base_pa = PhysicalAddress::pa_from_va(self.ntoskrnl_base_va);

        // Get the size of ntoskrnl.exe.
        self.ntoskrnl_size = unsafe { get_size_of_image(self.ntoskrnl_base_pa as _).ok_or(HypervisorError::FailedToGetKernelSize)? } as u64;

        Ok(())
    }

    /// Manages an EPT hook for a kernel function, enabling or disabling it.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to install/remove the hook on.
    /// * `function_hash` - The hash of the function to hook/unhook.
    /// * `syscall_number` - The syscall number to use if `get_export_by_hash` fails.
    /// * `ept_hook_type` - The type of EPT hook to use.
    /// * `enable` - A boolean indicating whether to enable (true) or disable (false) the hook.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The hook was managed successfully.
    /// * `Err(HypervisorError)` - If the hook management fails.
    pub fn manage_kernel_ept_hook(
        hook_manager: &mut HookManager,
        vm: &mut Vm,
        function_hash: u32,
        syscall_number: u16,
        ept_hook_type: EptHookType,
        enable: bool,
    ) -> Result<(), HypervisorError> {
        let action = if enable { "Enabling" } else { "Disabling" };
        debug!("{} EPT hook for function: {}", action, function_hash);

        let function_va = unsafe {
            if let Some(va) = get_export_by_hash(hook_manager.ntoskrnl_base_pa as _, hook_manager.ntoskrnl_base_va as _, function_hash) {
                va
            } else {
                let ssdt_function_address = SsdtHook::find_ssdt_function_address(
                    syscall_number as _,
                    false,
                    hook_manager.ntoskrnl_base_pa as _,
                    hook_manager.ntoskrnl_size as _,
                );
                match ssdt_function_address {
                    Ok(ssdt_hook) => ssdt_hook.guest_function_va as *mut u8,
                    Err(_) => return Err(HypervisorError::FailedToGetExport),
                }
            }
        };

        if enable {
            HookManager::ept_hook_function(hook_manager, vm, function_va as _, function_hash, ept_hook_type)?;
        } else {
            HookManager::ept_unhook_function(hook_manager, vm, function_va as _, ept_hook_type)?;
        }

        Ok(())
    }
}
