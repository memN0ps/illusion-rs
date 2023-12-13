//! A crate responsible for managing the VMCS region for VMX operations.
//!
//! This crate provides functionality to set up the VMCS region in memory, which
//! is vital for VMX operations on the CPU. It also offers utility functions for
//! adjusting VMCS entries and displaying VMCS state for debugging purposes.

use {
    // Internal crate usages
    crate::{
        error::HypervisorError,
        intel::{
            controls::{adjust_vmx_controls, VmxControl},
            descriptor::DescriptorTables,
            ept::Ept,
            msr_bitmap::MsrBitmap,
            segmentation::SegmentDescriptor,
            support::{vmclear, vmptrld, vmread, vmwrite},
        },
        utils::capture::GuestRegisters,
        utils::{
            addresses::PhysicalAddress,
            alloc::{KernelAlloc, PhysicalAllocator},
            capture::CONTEXT,
            nt::NTOSKRNL_CR3,
        },
    },

    // External crate usages
    alloc::boxed::Box,
    bitfield::BitMut,
    core::fmt,
    x86::{
        controlregs,
        dtables::{self},
        msr::{self},
        segmentation::SegmentSelector,
        task,
        vmx::vmcs::{self},
    },
};

pub const PAGE_SIZE: usize = 0x1000;

/// Represents the VMCS region in memory.
///
/// The VMCS region is essential for VMX operations on the CPU.
/// This structure offers methods for setting up the VMCS region, adjusting VMCS entries,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; PAGE_SIZE - 8],
}

impl Vmcs {
    /// Sets up the VMCS region.
    ///
    /// # Arguments
    /// * `vmcs_region` - A mutable reference to the VMCS region in memory.
    ///
    /// # Returns
    /// A result indicating success or an error.
    pub fn setup(vmcs_region: &mut Box<Vmcs, PhysicalAllocator>) -> Result<(), HypervisorError> {
        log::info!("Setting up VMCS region");

        let vmcs_region_physical_address =
            PhysicalAddress::pa_from_va(vmcs_region.as_ref() as *const _ as _);

        if vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("VMCS Region Virtual Address: {:p}", vmcs_region);
        log::info!(
            "VMCS Region Physical Addresss: 0x{:x}",
            vmcs_region_physical_address
        );

        vmcs_region.revision_id = Self::get_vmcs_revision_id();
        vmcs_region.as_mut().revision_id.set_bit(31, false);

        // Clear the VMCS region.
        vmclear(vmcs_region_physical_address);
        log::info!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(vmcs_region_physical_address);
        log::info!("VMPTRLD successful!");

        log::info!("VMCS setup successful!");

        Ok(())
    }

    /// Initialize the guest state for the currently loaded VMCS.
    ///
    /// The method sets up various guest state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA.
    ///
    /// # Arguments
    /// * `context` - Context containing the guest's register states.
    /// * `guest_descriptor_table` - Descriptor tables for the guest.
    /// * `guest_registers` - Guest registers for the guest.
    #[rustfmt::skip]
    pub fn setup_guest_registers_state(context: &CONTEXT, guest_descriptor_table: &Box<DescriptorTables, KernelAlloc>, guest_registers: &mut GuestRegisters) {
        unsafe { vmwrite(vmcs::guest::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(vmcs::guest::CR3, controlregs::cr3()) };
        unsafe { vmwrite(vmcs::guest::CR4, controlregs::cr4().bits() as u64) };

        vmwrite(vmcs::guest::DR7, context.Dr7);

        vmwrite(vmcs::guest::RSP, context.Rsp);
        vmwrite(vmcs::guest::RIP, context.Rip);
        vmwrite(vmcs::guest::RFLAGS, context.EFlags);

        vmwrite(vmcs::guest::CS_SELECTOR, context.SegCs);
        vmwrite(vmcs::guest::SS_SELECTOR, context.SegSs);
        vmwrite(vmcs::guest::DS_SELECTOR, context.SegDs);
        vmwrite(vmcs::guest::ES_SELECTOR, context.SegEs);
        vmwrite(vmcs::guest::FS_SELECTOR, context.SegFs);
        vmwrite(vmcs::guest::GS_SELECTOR, context.SegGs);
        unsafe { vmwrite(vmcs::guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64) };
        unsafe { vmwrite(vmcs::guest::TR_SELECTOR, task::tr().bits() as u64) };

        vmwrite(vmcs::guest::CS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).base_address);
        vmwrite(vmcs::guest::SS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).base_address);
        vmwrite(vmcs::guest::DS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).base_address);
        vmwrite(vmcs::guest::ES_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).base_address);
        unsafe { vmwrite(vmcs::guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(vmcs::guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(vmcs::guest::LDTR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).base_address) };
        unsafe { vmwrite(vmcs::guest::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).base_address) };

        vmwrite(vmcs::guest::CS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::SS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::DS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::ES_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::FS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::GS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &guest_descriptor_table.gdtr).segment_limit);
        unsafe { vmwrite(vmcs::guest::LDTR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).segment_limit) };
        unsafe { vmwrite(vmcs::guest::TR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).segment_limit) };

        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &guest_descriptor_table.gdtr).access_rights.bits());
        unsafe { vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).access_rights.bits()) };
        unsafe { vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).access_rights.bits()) };

        vmwrite(vmcs::guest::GDTR_BASE, guest_descriptor_table.gdtr.base as u64);
        vmwrite(vmcs::guest::IDTR_BASE, guest_descriptor_table.idtr.base as u64);

        vmwrite(vmcs::guest::GDTR_LIMIT, guest_descriptor_table.gdtr.limit as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, guest_descriptor_table.idtr.limit as u64);

        unsafe {
            vmwrite(vmcs::guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL));
            vmwrite(vmcs::guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(vmcs::guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(vmcs::guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
            vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);
        }

        let xmm_context = unsafe { context.Anonymous.Anonymous };

        // Note: VMCS does not manage all registers; some require manual intervention for saving and loading.
        // This includes general-purpose registers and xmm registers, which must be explicitly preserved and restored by the software.
        guest_registers.xmm0 = xmm_context.Xmm0;
        guest_registers.xmm1 = xmm_context.Xmm1;
        guest_registers.xmm2 = xmm_context.Xmm2;
        guest_registers.xmm3 = xmm_context.Xmm3;
        guest_registers.xmm4 = xmm_context.Xmm4;
        guest_registers.xmm5 = xmm_context.Xmm5;
        guest_registers.xmm6 = xmm_context.Xmm6;
        guest_registers.xmm7 = xmm_context.Xmm7;
        guest_registers.xmm8 = xmm_context.Xmm8;
        guest_registers.xmm9 = xmm_context.Xmm9;
        guest_registers.xmm10 = xmm_context.Xmm10;
        guest_registers.xmm11 = xmm_context.Xmm11;
        guest_registers.xmm12 = xmm_context.Xmm12;
        guest_registers.xmm13 = xmm_context.Xmm13;
        guest_registers.xmm14 = xmm_context.Xmm14;
        guest_registers.xmm15 = xmm_context.Xmm15;

        guest_registers.rax = context.Rax;
        guest_registers.rbx = context.Rbx;
        guest_registers.rcx = context.Rcx;
        guest_registers.rdx = context.Rdx;
        guest_registers.rdi = context.Rdi;
        guest_registers.rsi = context.Rsi;
        guest_registers.rbp = context.Rbp;
        guest_registers.r8 = context.R8;
        guest_registers.r9 = context.R9;
        guest_registers.r10 = context.R10;
        guest_registers.r11 = context.R11;
        guest_registers.r12 = context.R12;
        guest_registers.r13 = context.R13;
        guest_registers.r14 = context.R14;
        guest_registers.r15 = context.R15;
    }

    /// Initialize the host state for the currently loaded VMCS.
    ///
    /// The method sets up various host state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.5 HOST-STATE AREA.
    ///
    /// # Arguments
    /// * `context` - Context containing the host's register states.
    /// * `host_descriptor_table` - Descriptor tables for the host.
    #[rustfmt::skip]
    pub fn setup_host_registers_state(context: &CONTEXT, host_descriptor_table: &Box<DescriptorTables, KernelAlloc>) {
        unsafe { vmwrite(vmcs::host::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(vmcs::host::CR3, NTOSKRNL_CR3) };
        unsafe { vmwrite(vmcs::host::CR4, controlregs::cr4().bits() as u64) };

        // The RIP/RSP registers are set within `launch_vm`.

        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite(vmcs::host::CS_SELECTOR, context.SegCs & SELECTOR_MASK);
        vmwrite(vmcs::host::SS_SELECTOR, context.SegSs & SELECTOR_MASK);
        vmwrite(vmcs::host::DS_SELECTOR, context.SegDs & SELECTOR_MASK);
        vmwrite(vmcs::host::ES_SELECTOR, context.SegEs & SELECTOR_MASK);
        vmwrite(vmcs::host::FS_SELECTOR, context.SegFs & SELECTOR_MASK);
        vmwrite(vmcs::host::GS_SELECTOR, context.SegGs & SELECTOR_MASK);
        unsafe { vmwrite(vmcs::host::TR_SELECTOR, task::tr().bits() & SELECTOR_MASK) };

        unsafe { vmwrite(vmcs::host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(vmcs::host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(vmcs::host::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &host_descriptor_table.gdtr).base_address) };

        vmwrite(vmcs::host::GDTR_BASE, host_descriptor_table.gdtr.base as u64);
        vmwrite(vmcs::host::IDTR_BASE, host_descriptor_table.idtr.base as u64);

        unsafe {
            vmwrite(vmcs::host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(vmcs::host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(vmcs::host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
        }
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    ///
    /// The method sets up various VMX control fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual sections:
    /// - 25.6 VM-EXECUTION CONTROL FIELDS
    /// - 25.7 VM-EXIT CONTROL FIELDS
    /// - 25.8 VM-ENTRY CONTROL FIELDS
    ///
    /// # Arguments
    /// * `msr_bitmap` - Bitmap for Model-Specific Registers.
    #[rustfmt::skip]
    pub fn setup_vmcs_control_fields(msr_bitmap: &Box<MsrBitmap, PhysicalAllocator>, epts: &Box<Ept, PhysicalAllocator>) -> Result<(), HypervisorError> {
        const PRIMARY_CTL: u64 = (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits() | vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits()) as u64;
        const SECONDARY_CTL: u64 = (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
            | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
            | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
            | vmcs::control::SecondaryControls::ENABLE_EPT.bits()) as u64;
        const ENTRY_CTL: u64 = vmcs::control::EntryControls::IA32E_MODE_GUEST.bits() as u64;
        const EXIT_CTL: u64 = vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64;
        const PINBASED_CTL: u64 = 0;

        vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmcs::control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        unsafe {
            vmwrite(vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64);
            vmwrite(vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64);
        };

        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, PhysicalAddress::pa_from_va(msr_bitmap.as_ref() as *const _ as _));

        let eptp = Ept::create_eptp_with_wb_and_4lvl_walk(PhysicalAddress::pa_from_va(epts.as_ref() as *const _ as _))?;
        vmwrite(vmcs::control::EPTP_FULL, eptp);

        Ok(())
    }

    /// Retrieves the VMCS revision ID.
    pub fn get_vmcs_revision_id() -> u32 {
        unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}

/// Debug implementation to dump the VMCS fields.
impl fmt::Debug for Vmcs {
    /// Formats the VMCS for display.
    ///
    /// # Arguments
    /// * `format` - Formatter instance.
    ///
    /// # Returns
    /// Formatting result.
    #[rustfmt::skip]
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {

        format.debug_struct("Vmcs")
            .field("Current VMCS: ", &(self as *const _))
            .field("Revision ID: ", &self.revision_id)

            /* VMCS Guest state fields */
            .field("Guest CR0: ", &vmread(vmcs::guest::CR0))
            .field("Guest CR3: ", &vmread(vmcs::guest::CR3))
            .field("Guest CR4: ", &vmread(vmcs::guest::CR4))
            .field("Guest DR7: ", &vmread(vmcs::guest::DR7))
            .field("Guest RSP: ", &vmread(vmcs::guest::RSP))
            .field("Guest RIP: ", &vmread(vmcs::guest::RIP))
            .field("Guest RFLAGS: ", &vmread(vmcs::guest::RFLAGS))

            .field("Guest CS Selector: ", &vmread(vmcs::guest::CS_SELECTOR))
            .field("Guest SS Selector: ", &vmread(vmcs::guest::SS_SELECTOR))
            .field("Guest DS Selector: ", &vmread(vmcs::guest::DS_SELECTOR))
            .field("Guest ES Selector: ", &vmread(vmcs::guest::ES_SELECTOR))
            .field("Guest FS Selector: ", &vmread(vmcs::guest::FS_SELECTOR))
            .field("Guest GS Selector: ", &vmread(vmcs::guest::GS_SELECTOR))
            .field("Guest LDTR Selector: ", &vmread(vmcs::guest::LDTR_SELECTOR))
            .field("Guest TR Selector: ", &vmread(vmcs::guest::TR_SELECTOR))

            .field("Guest CS Base: ", &vmread(vmcs::guest::CS_BASE))
            .field("Guest SS Base: ", &vmread(vmcs::guest::SS_BASE))
            .field("Guest DS Base: ", &vmread(vmcs::guest::DS_BASE))
            .field("Guest ES Base: ", &vmread(vmcs::guest::ES_BASE))
            .field("Guest FS Base: ", &vmread(vmcs::guest::FS_BASE))
            .field("Guest GS Base: ", &vmread(vmcs::guest::GS_BASE))
            .field("Guest LDTR Base: ", &vmread(vmcs::guest::LDTR_BASE))
            .field("Guest TR Base: ", &vmread(vmcs::guest::TR_BASE))

            .field("Guest CS Limit: ", &vmread(vmcs::guest::CS_LIMIT))
            .field("Guest SS Limit: ", &vmread(vmcs::guest::SS_LIMIT))
            .field("Guest DS Limit: ", &vmread(vmcs::guest::DS_LIMIT))
            .field("Guest ES Limit: ", &vmread(vmcs::guest::ES_LIMIT))
            .field("Guest FS Limit: ", &vmread(vmcs::guest::FS_LIMIT))
            .field("Guest GS Limit: ", &vmread(vmcs::guest::GS_LIMIT))
            .field("Guest LDTR Limit: ", &vmread(vmcs::guest::LDTR_LIMIT))
            .field("Guest TR Limit: ", &vmread(vmcs::guest::TR_LIMIT))

            .field("Guest CS Access Rights: ", &vmread(vmcs::guest::CS_ACCESS_RIGHTS))
            .field("Guest SS Access Rights: ", &vmread(vmcs::guest::SS_ACCESS_RIGHTS))
            .field("Guest DS Access Rights: ", &vmread(vmcs::guest::DS_ACCESS_RIGHTS))
            .field("Guest ES Access Rights: ", &vmread(vmcs::guest::ES_ACCESS_RIGHTS))
            .field("Guest FS Access Rights: ", &vmread(vmcs::guest::FS_ACCESS_RIGHTS))
            .field("Guest GS Access Rights: ", &vmread(vmcs::guest::GS_ACCESS_RIGHTS))
            .field("Guest LDTR Access Rights: ", &vmread(vmcs::guest::LDTR_ACCESS_RIGHTS))
            .field("Guest TR Access Rights: ", &vmread(vmcs::guest::TR_ACCESS_RIGHTS))

            .field("Guest GDTR Base: ", &vmread(vmcs::guest::GDTR_BASE))
            .field("Guest IDTR Base: ", &vmread(vmcs::guest::IDTR_BASE))
            .field("Guest GDTR Limit: ", &vmread(vmcs::guest::GDTR_LIMIT))
            .field("Guest IDTR Limit: ", &vmread(vmcs::guest::IDTR_LIMIT))

            .field("Guest IA32_DEBUGCTL_FULL: ", &vmread(vmcs::guest::IA32_DEBUGCTL_FULL))
            .field("Guest IA32_SYSENTER_CS: ", &vmread(vmcs::guest::IA32_SYSENTER_CS))
            .field("Guest IA32_SYSENTER_ESP: ", &vmread(vmcs::guest::IA32_SYSENTER_ESP))
            .field("Guest IA32_SYSENTER_EIP: ", &vmread(vmcs::guest::IA32_SYSENTER_EIP))
            .field("Guest VMCS Link Pointer: ", &vmread(vmcs::guest::LINK_PTR_FULL))

            /* VMCS Host state fields */
            .field("Host CR0: ", &vmread(vmcs::host::CR0))
            .field("Host CR3: ", &vmread(vmcs::host::CR3))
            .field("Host CR4: ", &vmread(vmcs::host::CR4))
            .field("Host RSP: ", &vmread(vmcs::host::RSP))
            .field("Host RIP: ", &vmread(vmcs::host::RIP))
            .field("Host CS Selector: ", &vmread(vmcs::host::CS_SELECTOR))
            .field("Host SS Selector: ", &vmread(vmcs::host::SS_SELECTOR))
            .field("Host DS Selector: ", &vmread(vmcs::host::DS_SELECTOR))
            .field("Host ES Selector: ", &vmread(vmcs::host::ES_SELECTOR))
            .field("Host FS Selector: ", &vmread(vmcs::host::FS_SELECTOR))
            .field("Host GS Selector: ", &vmread(vmcs::host::GS_SELECTOR))
            .field("Host TR Selector: ", &vmread(vmcs::host::TR_SELECTOR))
            .field("Host FS Base: ", &vmread(vmcs::host::FS_BASE))
            .field("Host GS Base: ", &vmread(vmcs::host::GS_BASE))
            .field("Host TR Base: ", &vmread(vmcs::host::TR_BASE))
            .field("Host GDTR Base: ", &vmread(vmcs::host::GDTR_BASE))
            .field("Host IDTR Base: ", &vmread(vmcs::host::IDTR_BASE))
            .field("Host IA32_SYSENTER_CS: ", &vmread(vmcs::host::IA32_SYSENTER_CS))
            .field("Host IA32_SYSENTER_ESP: ", &vmread(vmcs::host::IA32_SYSENTER_ESP))
            .field("Host IA32_SYSENTER_EIP: ", &vmread(vmcs::host::IA32_SYSENTER_EIP))

            /* VMCS Control fields */
            .field("Primary Proc Based Execution Controls: ", &vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS))
            .field("Secondary Proc Based Execution Controls: ", &vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS))
            .field("VM Entry Controls: ", &vmread(vmcs::control::VMENTRY_CONTROLS))
            .field("VM Exit Controls: ", &vmread(vmcs::control::VMEXIT_CONTROLS))
            .field("Pin Based Execution Controls: ", &vmread(vmcs::control::PINBASED_EXEC_CONTROLS))
            .field("CR0 Read Shadow: ", &vmread(vmcs::control::CR0_READ_SHADOW))
            .field("CR4 Read Shadow: ", &vmread(vmcs::control::CR4_READ_SHADOW))
            .field("MSR Bitmaps Address: ", &vmread(vmcs::control::MSR_BITMAPS_ADDR_FULL))
            .finish_non_exhaustive()
    }
}
