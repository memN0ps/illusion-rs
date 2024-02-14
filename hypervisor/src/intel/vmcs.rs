use alloc::boxed::Box;
use core::fmt;
use core::ptr::NonNull;
use bit_field::BitField;
use x86::bits64::paging::BASE_PAGE_SIZE;
use x86::{controlregs, dtables, msr, task};
use x86::bits64::rflags;
use x86::debugregs::dr7;
use x86::segmentation::{cs, ds, es, fs, gs, SegmentSelector, ss};
use x86::vmx::vmcs;
use x86_64::registers::control::Cr4;
use crate::error::HypervisorError;
use crate::intel::capture::GuestRegisters;
use crate::intel::controls::{adjust_vmx_controls, VmxControl};
use crate::intel::descriptor::DescriptorTables;
use crate::intel::paging::PageTables;
use crate::intel::segmentation::SegmentDescriptor;
use crate::intel::shared_data::SharedData;
use crate::intel::support::{rdmsr, vmclear, vmptrld, vmread, vmwrite};
use crate::intel::vmxon::Vmxon;

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
    pub reserved: [u8; BASE_PAGE_SIZE - 8],
}

impl Default for Vmcs {
    fn default() -> Self {
        Self {
            revision_id: rdmsr(msr::IA32_VMX_BASIC) as u32,
            abort_indicator: 0,
            reserved: [0; BASE_PAGE_SIZE - 8],
        }
    }
}

impl Vmcs {
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
    pub fn setup_guest_registers_state(guest_descriptor_table: &Box<DescriptorTables>, guest_registers: &mut GuestRegisters) {
        log::debug!("Setting up Guest Registers State");

        unsafe { vmwrite(vmcs::guest::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(vmcs::guest::CR3, controlregs::cr3()) };
        vmwrite(vmcs::guest::CR4, Cr4::read_raw());

        vmwrite(vmcs::guest::DR7, unsafe { dr7().0.bits() });

        vmwrite(vmcs::guest::RSP, guest_registers.rsp);
        vmwrite(vmcs::guest::RIP, guest_registers.rip);
        vmwrite(vmcs::guest::RFLAGS, rflags::read().bits());

        vmwrite(vmcs::guest::CS_SELECTOR, cs().bits());
        vmwrite(vmcs::guest::SS_SELECTOR, ss().bits());
        vmwrite(vmcs::guest::DS_SELECTOR, ds().bits());
        vmwrite(vmcs::guest::ES_SELECTOR, es().bits());
        vmwrite(vmcs::guest::FS_SELECTOR, fs().bits());
        vmwrite(vmcs::guest::GS_SELECTOR, gs().bits());
        unsafe { vmwrite(vmcs::guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64) };
        unsafe { vmwrite(vmcs::guest::TR_SELECTOR, task::tr().bits() as u64) };

        vmwrite(vmcs::guest::CS_BASE, SegmentDescriptor::from_selector(cs(), &guest_descriptor_table.gdtr).base_address);
        vmwrite(vmcs::guest::SS_BASE, SegmentDescriptor::from_selector(ss(), &guest_descriptor_table.gdtr).base_address);
        vmwrite(vmcs::guest::DS_BASE, SegmentDescriptor::from_selector(ds(), &guest_descriptor_table.gdtr).base_address);
        vmwrite(vmcs::guest::ES_BASE, SegmentDescriptor::from_selector(es(), &guest_descriptor_table.gdtr).base_address);
        unsafe { vmwrite(vmcs::guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(vmcs::guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(vmcs::guest::LDTR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).base_address) };
        unsafe { vmwrite(vmcs::guest::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).base_address) };

        vmwrite(vmcs::guest::CS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(ss().bits()), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::SS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(ss().bits()), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::DS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(ds().bits()), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::ES_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(es().bits()), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::FS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(fs().bits()), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(vmcs::guest::GS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(gs().bits()), &guest_descriptor_table.gdtr).segment_limit);
        unsafe { vmwrite(vmcs::guest::LDTR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).segment_limit) };
        unsafe { vmwrite(vmcs::guest::TR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).segment_limit) };

        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(cs().bits()), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(ss().bits()), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(ds().bits()), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(es().bits()), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(fs().bits()), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(gs().bits()), &guest_descriptor_table.gdtr).access_rights.bits());
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

        //let xmm_context = unsafe { context.Anonymous.Anonymous };

        // Note: VMCS does not manage all registers; some require manual intervention for saving and loading.
        // This includes general-purpose registers and xmm registers, which must be explicitly preserved and restored by the software.
        /*
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
        */

        guest_registers.rax = guest_registers.rax;
        guest_registers.rbx = guest_registers.rbx;
        guest_registers.rcx = guest_registers.rcx;
        guest_registers.rdx = guest_registers.rdx;
        guest_registers.rdi = guest_registers.rdi;
        guest_registers.rsi = guest_registers.rsi;
        guest_registers.rbp = guest_registers.rbp;
        guest_registers.r8 = guest_registers.r8;
        guest_registers.r9 = guest_registers.r9;
        guest_registers.r10 = guest_registers.r10;
        guest_registers.r11 = guest_registers.r11;
        guest_registers.r12 = guest_registers.r12;
        guest_registers.r13 = guest_registers.r13;
        guest_registers.r14 = guest_registers.r14;
        guest_registers.r15 = guest_registers.r15;

        log::debug!("Guest Registers State setup successfully!");
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
    pub fn setup_host_registers_state(host_descriptor_table: &Box<DescriptorTables>, host_paging: &Box<PageTables>) -> Result<(), HypervisorError> {
        log::debug!("Setting up Host Registers State");

        unsafe { vmwrite(vmcs::host::CR0, controlregs::cr0().bits() as u64) };

        let pml4_pa = host_paging.get_pml4_pa()?;
        vmwrite(vmcs::host::CR3, pml4_pa);

        vmwrite(vmcs::host::CR4, Cr4::read_raw());

        // The RIP/RSP registers are set within `launch_vm`.

        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite(vmcs::host::CS_SELECTOR, cs().bits() & SELECTOR_MASK);
        vmwrite(vmcs::host::SS_SELECTOR, ss().bits() & SELECTOR_MASK);
        vmwrite(vmcs::host::DS_SELECTOR, ds().bits() & SELECTOR_MASK);
        vmwrite(vmcs::host::ES_SELECTOR, es().bits() & SELECTOR_MASK);
        vmwrite(vmcs::host::FS_SELECTOR, fs().bits() & SELECTOR_MASK);
        vmwrite(vmcs::host::GS_SELECTOR, gs().bits() & SELECTOR_MASK);
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

        log::debug!("Host Registers State setup successfully!");

        Ok(())
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
    /// * `shared_data` - Shared data between processors.
    #[rustfmt::skip]
    pub fn setup_vmcs_control_fields(shared_data: &mut NonNull<SharedData>) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS Control Fields");

        const PRIMARY_CTL: u64 = (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits() | vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits()) as u64;
        const SECONDARY_CTL: u64 = (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
            | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
            | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
            | vmcs::control::SecondaryControls::ENABLE_VPID.bits()
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
            vmwrite(vmcs::control::CR4_READ_SHADOW, Cr4::read_raw());
        };

        //vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, unsafe { shared_data.msr_bitmap.as_ref() as *const _ as _ });
        //vmwrite(vmcs::control::EXCEPTION_BITMAP, 1u64 << (ExceptionInterrupt::Breakpoint as u32));

        vmwrite(vmcs::control::EPTP_FULL, unsafe { shared_data.as_mut().primary_eptp });
        //vmwrite(vmcs::control::VPID, VPID_TAG);

        //invept_single_context(unsafe { shared_data.as_mut().primary_eptp });
        //invvpid_single_context(VPID_TAG);

        log::debug!("VMCS Control Fields setup successfully!");

        Ok(())
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
            .field("EPT Pointer: ", &vmread(vmcs::control::EPTP_FULL))
            .finish_non_exhaustive()
    }
}