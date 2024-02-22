use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            descriptor::Descriptors,
            page::Page,
            paging::PageTables,
            shared::SharedData,
            support::{rdmsr, vmclear, vmptrld, vmread},
            vmcs::Vmcs,
            vmerror::{VmInstructionError, VmxBasicExitReason},
            vmlaunch::launch_vm,
        },
    },
    alloc::alloc::handle_alloc_error,
    alloc::boxed::Box,
    bit_field::BitField,
    core::alloc::Layout,
    core::ptr::NonNull,
    log::*,
    x86::{bits64::rflags::RFlags, vmx::vmcs},
};

pub struct Vm {
    /// The VMCS (Virtual Machine Control Structure) for the VM.
    pub vmcs_region: Box<Vmcs>,

    /// The guest's descriptor tables.
    pub guest_descriptor: Descriptors,

    /// The host's descriptor tables.
    pub host_descriptor: Descriptors,

    /// The host's paging tables.
    pub host_paging: Box<PageTables>,

    /// The guest's general-purpose registers state.
    pub guest_registers: GuestRegisters,

    /// The MSR bitmaps.
    pub msr_bitmap: Box<Page>,

    /// Whether the VM has been launched.
    pub has_launched: bool,

    /// The shared data between processors.
    pub shared_data: NonNull<SharedData>,
}

impl Vm {
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
            msr_bitmap: unsafe { box_zeroed::<Page>() },
            has_launched: false,
            shared_data: unsafe { NonNull::new_unchecked(shared_data as *mut _) },
        })
    }

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

    pub fn setup_vmcs(&mut self) -> Result<(), HypervisorError> {
        debug!("Setting up VMCS");

        let primary_eptp = unsafe { self.shared_data.as_ref().primary_eptp };

        Vmcs::setup_guest_registers_state(&self.guest_descriptor, &self.guest_registers);
        Vmcs::setup_host_registers_state(&self.host_descriptor, &self.host_paging)?;
        Vmcs::setup_vmcs_control_fields(primary_eptp, &self.msr_bitmap)?;

        debug!("VMCS setup successfully!");

        Ok(())
    }

    // launches in a loop returns the types of vmexits
    pub fn run(&mut self) -> Result<VmxBasicExitReason, HypervisorError> {
        // Run the VM until the VM-exit occurs.
        let flags = unsafe { launch_vm(&mut self.guest_registers, u64::from(self.has_launched)) };
        Self::vm_succeed(RFlags::from_raw(flags))?;
        self.has_launched = true;
        trace!("VM-exit occurred!");

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

/// Allocates memory for a type and initializes it to zero.
pub unsafe fn box_zeroed<T>() -> Box<T> {
    let layout = Layout::new::<T>();
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}
