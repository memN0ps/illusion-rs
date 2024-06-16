//! Manages the VMCS region for VMX operations within a virtualized environment.
//!
//! Offers functionality to configure and activate the VMCS (Virtual Machine Control Structure),
//! which is essential for executing and managing VMX operations on Intel CPUs. This includes
//! setting up guest and host states, managing memory with EPT (Extended Page Tables), and
//! handling VM-exit reasons for debugging and control purposes.

use {
    crate::{
        error::HypervisorError,
        intel::{
            bitmap::{MsrAccessType, MsrBitmap, MsrOperation},
            capture::GuestRegisters,
            descriptor::Descriptors,
            ept::Ept,
            hooks::hook_manager::HookManager,
            page::Page,
            paging::PageTables,
            support::{vmclear, vmptrld, vmread, vmxon},
            vmcs::Vmcs,
            vmerror::{VmInstructionError, VmxBasicExitReason},
            vmlaunch::launch_vm,
            vmxon::Vmxon,
        },
    },
    log::*,
    x86::{bits64::rflags::RFlags, msr, vmx::vmcs},
};

/// Represents a Virtual Machine (VM) instance, encapsulating its state and control mechanisms.
///
/// This structure manages the VM's lifecycle, including setup, execution, and handling of VM-exits.
/// It holds the VMCS region, guest and host descriptor tables, paging information, MSR bitmaps,
/// and the state of guest registers. Additionally, it tracks whether the VM has been launched.
pub struct Vm {
    /// The VMXON (Virtual Machine Extensions On) region for the VM.
    pub vmxon_region: Vmxon,

    /// The VMCS (Virtual Machine Control Structure) for the VM.
    pub vmcs_region: Vmcs,

    /// Descriptor tables for the guest state.
    pub guest_descriptor: Descriptors,

    /// Descriptor tables for the host state.
    pub host_descriptor: Descriptors,

    /// Paging tables for the host.
    pub host_paging: PageTables,

    /// The hook manager for the VM.
    pub hook_manager: HookManager,

    /// A bitmap for handling MSRs.
    pub msr_bitmap: MsrBitmap,

    /// The primary EPT (Extended Page Tables) for the VM.
    pub primary_ept: Ept,

    /// The primary EPTP (Extended Page Tables Pointer) for the VM.
    pub primary_eptp: u64,

    /// State of guest general-purpose registers.
    pub guest_registers: GuestRegisters,

    /// Flag indicating if the VM has been launched.
    pub has_launched: bool,

    /// The dummy page to use for hooking.
    pub dummy_page: Page,
}

impl Vm {
    /// Initializes a new VM instance with specified guest registers.
    ///
    /// Sets up the necessary environment for the VM, including VMCS initialization, host and guest
    /// descriptor tables, paging structures, and MSR bitmaps. Prepares the VM for execution.
    ///
    /// # Arguments
    ///
    /// - `guest_registers`: The initial state of guest registers for the VM.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` with a newly created `Vm` instance, or an `Err(HypervisorError)` if
    /// any part of the setup fails.
    pub fn new(guest_registers: &GuestRegisters) -> Result<Self, HypervisorError> {
        trace!("Creating VM");

        trace!("Allocating VMXON region");
        let vmxon_region = Vmxon::new();

        trace!("Allocating VMCS region");
        let vmcs_region = Vmcs::new();

        trace!("Allocating Memory for Host Paging");
        let mut host_paging = PageTables::new();

        trace!("Building Identity Paging for Host");
        host_paging.build_identity();

        trace!("Allocating MSR Bitmap");
        let mut msr_bitmap = MsrBitmap::new();

        trace!("Allocating Primary EPT");
        let mut primary_ept = Ept::new();

        trace!("Identity Mapping Primary EPT");
        primary_ept.build_identity()?;

        trace!("Creating primary EPTP with WB and 4-level walk");
        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        trace!("Modifying MSR interception for LSTAR MSR write access");
        msr_bitmap.modify_msr_interception(msr::IA32_LSTAR, MsrAccessType::Write, MsrOperation::Hook);

        trace!("Creating EPT hook manager");
        let hook_manager = HookManager::new()?;

        trace!("Creating dummy page filled with 0xffs");
        let dummy_page = Page::new();

        trace!("VM created");

        Ok(Self {
            vmxon_region,
            vmcs_region,
            host_paging,
            hook_manager,
            host_descriptor: Descriptors::new_for_host(),
            guest_descriptor: Descriptors::new_from_current(),
            msr_bitmap,
            primary_ept,
            primary_eptp,
            guest_registers: guest_registers.clone(),
            has_launched: false,
            dummy_page,
        })
    }

    /// Activates the VMXON region to enable VMX operation.
    ///
    /// Sets up the VMXON region and executes the VMXON instruction. This involves configuring control registers,
    /// adjusting the IA32_FEATURE_CONTROL MSR, and validating the VMXON region's revision ID to ensure the CPU is ready
    /// for VMX operation mode.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful activation, or an `Err(HypervisorError)` if any step in the activation process fails.
    pub fn activate_vmxon(&mut self) -> Result<(), HypervisorError> {
        trace!("Setting up VMXON region");
        self.setup_vmxon()?;
        trace!("VMXON region setup successfully!");

        trace!("Executing VMXON instruction");
        vmxon(&self.vmxon_region as *const _ as _);
        trace!("VMXON executed successfully!");

        Ok(())
    }

    /// Prepares the system for VMX operation by configuring necessary control registers and MSRs.
    ///
    /// Ensures that the system meets all prerequisites for VMX operation as defined by Intel's specifications.
    /// This includes enabling VMX operation through control register modifications, setting the lock bit in
    /// IA32_FEATURE_CONTROL MSR, and adjusting mandatory CR0 and CR4 bits.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all configurations are successfully applied, or an `Err(HypervisorError)` if adjustments fail.
    fn setup_vmxon(&mut self) -> Result<(), HypervisorError> {
        trace!("Enabling Virtual Machine Extensions (VMX)");
        Vmxon::enable_vmx_operation();
        trace!("VMX enabled");

        trace!("Adjusting IA32_FEATURE_CONTROL MSR");
        Vmxon::adjust_feature_control_msr()?;
        trace!("IA32_FEATURE_CONTROL MSR adjusted");

        trace!("Setting CR0 bits");
        Vmxon::set_cr0_bits();
        trace!("CR0 bits set");

        trace!("Setting CR4 bits");
        Vmxon::set_cr4_bits();
        trace!("CR4 bits set");

        Ok(())
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
        trace!("Activating VMCS");
        // Clear the VMCS region.
        vmclear(&self.vmcs_region as *const _ as _);
        trace!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(&self.vmcs_region as *const _ as _);
        trace!("VMPTRLD successful!");

        self.setup_vmcs()?;

        trace!("VMCS activated successfully!");

        Ok(())
    }

    /// Configures the VMCS with necessary settings for guest and host state, and VM execution controls.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if VMCS setup is successful, or an `Err(HypervisorError)` for setup failures.
    pub fn setup_vmcs(&mut self) -> Result<(), HypervisorError> {
        trace!("Setting up VMCS");

        let primary_eptp = self.primary_eptp;
        let msr_bitmap = &self.msr_bitmap as *const _ as u64;

        Vmcs::setup_guest_registers_state(&self.guest_descriptor, &self.guest_registers);
        Vmcs::setup_host_registers_state(&self.host_descriptor, &self.host_paging)?;
        Vmcs::setup_vmcs_control_fields(primary_eptp, msr_bitmap)?;

        trace!("VMCS setup successfully!");

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
