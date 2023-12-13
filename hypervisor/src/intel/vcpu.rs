//! Module for handling Virtual CPU (VCPU) operations.
//! This module provides functionality to manage and control a virtualized CPU.
//! It provides mechanisms to virtualize a CPU, manage its state, and interact with its context.

extern crate alloc;

use {
    super::vmx::Vmx,
    crate::{
        error::HypervisorError,
        intel::support,
        utils::{capture::CONTEXT, processor::is_virtualized},
    },
    alloc::boxed::Box,
    core::mem::MaybeUninit,
    wdk_sys::ntddk::RtlCaptureContext,
};

/// Represents a Virtual CPU (VCPU) and its associated operations.
pub struct Vcpu {
    /// The processor's unique identifier.
    index: u32,

    /// The VMX instance associated with this VCPU.
    vmx: Box<Vmx>,
}

impl Vcpu {
    /// Creates and initializes a new VCPU instance for the specified processor index.
    ///
    /// # Arguments
    ///
    /// * `index` - Processor's unique identifier.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized VCPU instance or a `HypervisorError`.
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::info!("Creating processor {}", index);

        let vmx = Vmx::new()?;

        Ok(Self { index, vmx })
    }

    /// Virtualizes the current CPU.
    ///
    /// Captures the CPU's context, initializes VMX operation, adjusts control registers, and
    /// executes VMXON, VMCLEAR, VMPTRLD, and VMLAUNCH.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the virtualization process.
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("Virtualizing processor {}", self.index);

        // Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
        log::info!("Capturing context");
        let mut context: MaybeUninit<CONTEXT> = MaybeUninit::uninit();

        unsafe { RtlCaptureContext(context.as_mut_ptr() as _) };

        let context = unsafe { context.assume_init() };

        // Determine if we're operating as the Host (root) or Guest (non-root). Only proceed with system virtualization if operating as the Host.
        if !is_virtualized() {
            // If we are here as Guest (non-root) then that will lead to undefined behavior (UB).
            log::info!("Preparing for virtualization");
            crate::utils::processor::set_virtualized();

            self.vmx.setup_virtualization(&context)?;
            log::info!("Virtualization complete for processor {}", self.index);

            log::info!("Dumping VMCS: {:#x?}", self.vmx.vmcs_region);
            log::info!("Dumping _CONTEXT: ");
            CONTEXT::dump_context(&context);

            self.vmx.run();
            // We should never reach this point as the VM should have been launched.
        }

        Ok(())
    }

    /// Devirtualizes the current CPU.
    ///
    /// Attempts to turn off VMX operation for the processor on which it's called. If the processor is
    /// already in a non-root operation (devirtualized), the function will return early without performing
    /// the devirtualization again.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation. Returns `Ok(())` if the processor
    /// was successfully devirtualized or was already in a devirtualized state. Returns an `Err` if the
    /// `vmxoff` operation fails.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 30.3 VMXOFF—Leave VMX Operation.
    /// - Describes the `VMXOFF` instruction which is used to devirtualize a processor.
    pub fn devirtualize_cpu(&self) -> Result<(), HypervisorError> {
        // Determine if the processor is already devirtualized.
        if !is_virtualized() {
            log::info!("Processor {} is already devirtualized", self.index);
            return Ok(());
        }

        // Attempt to devirtualize the processor using the VMXOFF instruction.
        support::vmxoff()?;
        log::info!("Processor {} has been devirtualized", self.index);

        Ok(())
    }

    /// Retrieves the processor's unique identifier.
    ///
    /// # Returns
    ///
    /// The processor's unique identifier.
    pub fn id(&self) -> u32 {
        self.index
    }
}
