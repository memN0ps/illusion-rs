//! A crate for managing hypervisor functionality, particularly focused on
//! Extended Page Tables (EPT) and Model-Specific Register (MSR) bitmaps.
//! Includes support for primary and optional secondary EPTs.

use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{
            bitmap::MsrBitmap,
            ept::{Ept, Pt},
            hooks::hook::EptHook,
            page::Page,
        },
        windows::kernel::KernelHook,
    },
    alloc::{boxed::Box, vec::Vec},
};

/// The maximum number of hooks supported by the hypervisor. Change this value as needed
pub const MAX_HOOKS: usize = 64;

/// Represents shared data structures for hypervisor operations.
///
/// This struct manages the MSR (Model-Specific Register) bitmap and Extended Page Tables (EPT)
/// for the hypervisor, enabling memory virtualization and control over certain processor features.
#[repr(C)]
pub struct SharedData {
    /// A bitmap for handling MSRs.
    pub msr_bitmap: Box<MsrBitmap>,

    /// The primary EPT (Extended Page Tables) for the VM.
    pub primary_ept: Box<Ept>,

    /// The secondary EPTP (Extended Page Tables Pointer) for the VM.
    pub primary_eptp: u64,

    /// The secondary EPT (Extended Page Tables) for the VM.
    pub secondary_ept: Box<Ept>,

    /// The secondary EPTP (Extended Page Tables Pointer) for the VM.
    pub secondary_eptp: u64,

    /// The EPT hook manager.
    pub ept_hook_manager: Vec<Box<EptHook>>,

    /// The current hook index.
    pub current_hook_index: usize,

    /// The hook instance for the Windows kernel, storing the VA and PA of ntoskrnl.exe.
    /// This is retrieved from the first LSTAR_MSR write operation, intercepted by the hypervisor.
    pub kernel_hook: KernelHook,

    /// A flag indicating whether the CPUID cache information has been called.
    /// This will be used to perform hooks at boot time when SSDT has been initialized.
    /// KiSetCacheInformation -> KiSetCacheInformationIntel -> KiSetStandardizedCacheInformation
    /// __cpuid(4, 0)
    pub has_cpuid_cache_info_been_called: bool,
}

impl SharedData {
    /// Creates a new instance of `SharedData` with primary and optionally secondary EPTs.
    ///
    /// This function initializes the MSR bitmap and sets up the EPTs.
    ///
    /// # Arguments
    ///
    /// * `primary_ept`: The primary EPT to be used.
    /// * `secondary_ept`: The secondary EPT to be used if the feature is enabled.
    ///
    /// # Returns
    /// A result containing a boxed `SharedData` instance or an error of type `HypervisorError`.
    pub fn new(
        primary_ept: Box<Ept>,
        secondary_ept: Box<Ept>,
    ) -> Result<Box<Self>, HypervisorError> {
        log::trace!("Initializing shared data");

        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;
        let secondary_eptp = secondary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        #[allow(unused_mut)]
        let mut msr_bitmap = MsrBitmap::new();

        #[cfg(feature = "test-windows-uefi-hooks")]
        {
            //
            // Intercept read and write operations for the IA32_LSTAR MSR.
            //

            // msr_bitmap.modify_msr_interception(x86::msr::IA32_LSTAR, crate::intel::bitmap::MsrAccessType::Read, crate::intel::bitmap::MsrOperation::Hook);
            msr_bitmap.modify_msr_interception(
                x86::msr::IA32_LSTAR,
                crate::intel::bitmap::MsrAccessType::Write,
                crate::intel::bitmap::MsrOperation::Hook,
            );

            //
            // Intercept write operations for the IA32_GS_BASE MSR.
            //

            // msr_bitmap.modify_msr_interception(x86::msr::IA32_GS_BASE, crate::intel::bitmap::MsrAccessType::Write, crate::intel::bitmap::MsrOperation::Hook);
        }

        let mut ept_hook_manager = Vec::new();

        // Pre-Allocated buffers for hooks
        for _ in 0..MAX_HOOKS {
            // Create a pre-allocated shadow page for the hook.
            let host_shadow_page = unsafe { box_zeroed::<Page>() };

            // Create a pre-allocated Page Table (PT) for splitting the 2MB page into 4KB pages for the primary EPT.
            let primary_ept_pre_alloc_pt = unsafe { box_zeroed::<Pt>() };

            // Create a pre-allocated Page Table (PT) for splitting the 2MB page into 4KB pages for the secondary EPT.
            let secondary_ept_pre_alloc_pt = unsafe { box_zeroed::<Pt>() };

            // Create a pre-allocated trampoline page for the hook.
            let trampoline_page = unsafe { box_zeroed::<Page>() };

            // Create a new ept hook and push it to the hook manager.
            let ept_hook = EptHook::new(
                host_shadow_page,
                primary_ept_pre_alloc_pt,
                secondary_ept_pre_alloc_pt,
                trampoline_page,
            );

            // Save the hook in the hook manager.
            ept_hook_manager.push(ept_hook);
        }

        Ok(Box::new(Self {
            msr_bitmap,
            primary_ept,
            primary_eptp,
            secondary_ept,
            secondary_eptp,
            ept_hook_manager,
            current_hook_index: 0,
            has_cpuid_cache_info_been_called: false,
            kernel_hook: Default::default(),
        }))
    }
}
