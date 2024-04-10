//! Manages the VMCS region for VMX operations within a virtualized environment.
//!
//! Offers functionality to configure and activate the VMCS (Virtual Machine Control Structure),
//! which is essential for executing and managing VMX operations on Intel CPUs. This includes
//! setting up guest and host states, managing memory with EPT (Extended Page Tables), and
//! handling VM-exit reasons for debugging and control purposes.

use {
    crate::{
        allocate::box_zeroed,
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            descriptor::Descriptors,
            paging::PageTables,
            shared::SharedData,
            support::{rdmsr, vmclear, vmptrld, vmread},
            vmcs::Vmcs,
            vmerror::{VmInstructionError, VmxBasicExitReason},
            vmlaunch::launch_vm,
        },
    },
    alloc::boxed::Box,
    bit_field::BitField,
    core::ptr::NonNull,
    log::*,
    x86::{bits64::rflags::RFlags, vmx::vmcs},
};

/// Represents a Virtual Machine (VM) instance, encapsulating its state and control mechanisms.
///
/// This structure manages the VM's lifecycle, including setup, execution, and handling of VM-exits.
/// It holds the VMCS region, guest and host descriptor tables, paging information, MSR bitmaps,
/// and the state of guest registers. Additionally, it tracks whether the VM has been launched.
pub struct Vm {
    /// The VMCS (Virtual Machine Control Structure) for the VM.
    pub vmcs_region: Box<Vmcs>,

    /// Descriptor tables for the guest state.
    pub guest_descriptor: Descriptors,

    /// Descriptor tables for the host state.
    pub host_descriptor: Descriptors,

    /// Paging tables for the host.
    pub host_paging: Box<PageTables>,

    /// State of guest general-purpose registers.
    pub guest_registers: GuestRegisters,

    /// Flag indicating if the VM has been launched.
    pub has_launched: bool,

    /// Shared data across processors for synchronization and state management.
    pub shared_data: NonNull<SharedData>,
}

impl Vm {
    /// Initializes a new VM instance with specified guest registers and shared data.
    ///
    /// Sets up the necessary environment for the VM, including VMCS initialization, host and guest
    /// descriptor tables, paging structures, and MSR bitmaps. Prepares the VM for execution.
    ///
    /// # Arguments
    ///
    /// - `guest_registers`: The initial state of guest registers for the VM.
    /// - `shared_data`: Mutable reference to shared data used across processors.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` with a newly created `Vm` instance, or an `Err(HypervisorError)` if
    /// any part of the setup fails.
    pub fn new(
        guest_registers: &GuestRegisters,
        shared_data: &mut SharedData,
    ) -> Result<Self, HypervisorError> {
        debug!("Creating VM");
        let mut vmcs_region = unsafe { box_zeroed::<Vmcs>() };
        vmcs_region.revision_id = rdmsr(x86::msr::IA32_VMX_BASIC) as u32;

        debug!("Allocating Memory for Host Paging");
        let mut host_paging = unsafe { box_zeroed::<PageTables>() };

        debug!("Building Identity Paging for Host");
        host_paging.build_identity();

        debug!("VM created");

        Ok(Self {
            vmcs_region,
            host_paging,
            host_descriptor: Descriptors::new_for_host(),
            guest_descriptor: Descriptors::new_from_current(),
            guest_registers: guest_registers.clone(),
            has_launched: false,
            shared_data: unsafe { NonNull::new_unchecked(shared_data as *mut _) },
        })
    }

    /// Activates the VMCS region for the VM, preparing it for execution.
    ///
    /// Clears and loads the VMCS region, setting it as the current VMCS for VMX operations.
    /// Calls `setup_vmcs` to configure the VMCS with guest, host, and control settings.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful activation, or an `Err(HypervisorError)` if activation fails.
    pub fn activate_vmcs(&mut self) -> Result<(), HypervisorError> {
        debug!("Activating VMCS");
        self.vmcs_region.revision_id.set_bit(31, false);

        // Clear the VMCS region.
        vmclear(self.vmcs_region.as_ref() as *const _ as _);
        trace!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(self.vmcs_region.as_ref() as *const _ as _);
        trace!("VMPTRLD successful!");

        self.setup_vmcs()?;

        debug!("VMCS activated successfully!");

        Ok(())
    }

    /// Configures the VMCS with necessary settings for guest and host state, and VM execution controls.
    ///
    /// Includes setting up guest registers, host state on VM-exits, and control fields for VM execution.
    /// Utilizes shared data for setting up Extended Page Tables (EPT) and MSR bitmaps.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if VMCS setup is successful, or an `Err(HypervisorError)` for setup failures.
    pub fn setup_vmcs(&mut self) -> Result<(), HypervisorError> {
        debug!("Setting up VMCS");

        let primary_eptp = unsafe { self.shared_data.as_ref().primary_eptp };
        let msr_bitmap =
            unsafe { self.shared_data.as_ref().msr_bitmap.as_ref() as *const _ as u64 };

        Vmcs::setup_guest_registers_state(&self.guest_descriptor, &self.guest_registers);
        Vmcs::setup_host_registers_state(&self.host_descriptor, &self.host_paging)?;
        Vmcs::setup_vmcs_control_fields(primary_eptp, msr_bitmap)?;

        debug!("VMCS setup successfully!");

        Ok(())
    }

    /// Executes the VM, running in a loop until a VM-exit occurs.
    ///
    /// Launches or resumes the VM based on its current state, handling VM-exits as they occur.
    /// Updates the VM's state based on VM-exit reasons and captures the guest register state post-exit.
    ///
    /// # Returns
    ///
    /// Returns `Ok(VmxBasicExitReason)` indicating the reason for the VM-exit, or an `Err(HypervisorError)`
    /// if the VM fails to launch or an unknown exit reason is encountered.
    pub fn run(&mut self) -> Result<VmxBasicExitReason, HypervisorError> {
        // Run the VM until the VM-exit occurs.
        let flags = unsafe { launch_vm(&mut self.guest_registers, u64::from(self.has_launched)) };
        Self::vm_succeed(RFlags::from_raw(flags))?;
        self.has_launched = true;
        // trace!("VM-exit occurred!");

        // VM-exit occurred. Copy the guest register values from VMCS so that
        // `self.registers` is complete and up to date.
        self.guest_registers.rip = vmread(vmcs::guest::RIP);
        self.guest_registers.rsp = vmread(vmcs::guest::RSP);
        self.guest_registers.rflags = vmread(vmcs::guest::RFLAGS);

        let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u32;

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            error!("Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        return Ok(basic_exit_reason);
    }

    /// Verifies that the `launch_vm` function executed successfully.
    ///
    /// This method checks the RFlags for indications of failure from the `launch_vm` function.
    /// If a failure is detected, it will panic with a detailed error message.
    ///
    /// # Arguments
    ///
    /// * `flags`: The RFlags value post-execution of the `launch_vm` function.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// - 31.2 CONVENTIONS
    /// - 31.4 VM INSTRUCTION ERROR NUMBERS
    fn vm_succeed(flags: RFlags) -> Result<(), HypervisorError> {
        if flags.contains(RFlags::FLAGS_ZF) {
            let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;
            return match VmInstructionError::from_u32(instruction_error) {
                Some(error) => {
                    error!("VM instruction error: {:?}", error);
                    Err(HypervisorError::VmInstructionError)
                }
                None => {
                    error!("Unknown VM instruction error: {:#x}", instruction_error);
                    Err(HypervisorError::UnknownVMInstructionError)
                }
            };
        } else if flags.contains(RFlags::FLAGS_CF) {
            error!("VM instruction failed due to carry flag being set");
            return Err(HypervisorError::VMFailToLaunch);
        }

        Ok(())
    }
}
