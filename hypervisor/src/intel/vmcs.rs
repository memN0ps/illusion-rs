//! A crate responsible for managing the VMCS region for VMX operations.
//!
//! This crate provides functionality to set up the VMCS region in memory, which
//! is vital for VMX operations on the CPU. It also offers utility functions for
//! adjusting VMCS entries and displaying VMCS state for debugging purposes.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            controls::{adjust_vmx_controls, VmxControl},
            descriptor::Descriptors,
            invept::invept_single_context,
            invvpid::{invvpid_single_context, VPID_TAG},
            segmentation::{access_rights_from_native, lar, lsl},
            support::{cr3, rdmsr, sidt, vmread, vmwrite},
        },
    },
    bit_field::BitField,
    core::fmt,
    x86::{
        bits64::{paging::BASE_PAGE_SIZE, rflags},
        debugregs::dr7,
        msr,
        segmentation::{cs, ds, es, fs, gs, ss},
        vmx::vmcs,
    },
    x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

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

impl Vmcs {
    /// Initializes the VMCS region.
    pub fn init(&mut self) {
        self.revision_id = rdmsr(msr::IA32_VMX_BASIC) as u32;
        self.revision_id.set_bit(31, false);
    }

    /// Initialize the guest state for the currently loaded VMCS.
    ///
    /// The method sets up various guest state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA.
    ///
    /// # Arguments
    /// * `guest_descriptor` - Descriptor tables for the guest.
    /// * `guest_registers` - Guest registers for the guest.
    pub fn setup_guest_registers_state(guest_descriptor: &Descriptors, guest_registers: &GuestRegisters) {
        log::debug!("Setting up Guest Registers State");

        let idtr = sidt();

        vmwrite(vmcs::guest::CR0, Cr0::read_raw());
        vmwrite(vmcs::guest::CR3, cr3());
        vmwrite(vmcs::guest::CR4, Cr4::read_raw());

        vmwrite(vmcs::guest::DR7, unsafe { dr7().0 as u64 });

        vmwrite(vmcs::guest::RSP, guest_registers.rsp);
        vmwrite(vmcs::guest::RIP, guest_registers.rip);
        vmwrite(vmcs::guest::RFLAGS, rflags::read().bits());

        vmwrite(vmcs::guest::CS_SELECTOR, cs().bits());
        vmwrite(vmcs::guest::SS_SELECTOR, ss().bits());
        vmwrite(vmcs::guest::DS_SELECTOR, ds().bits());
        vmwrite(vmcs::guest::ES_SELECTOR, es().bits());
        vmwrite(vmcs::guest::FS_SELECTOR, fs().bits());
        vmwrite(vmcs::guest::GS_SELECTOR, gs().bits());

        vmwrite(vmcs::guest::LDTR_SELECTOR, 0u16);
        vmwrite(vmcs::guest::TR_SELECTOR, guest_descriptor.tr.bits());

        // All segment base registers are assumed to be zero, except that of TR.
        vmwrite(vmcs::guest::TR_BASE, guest_descriptor.tss.base);

        vmwrite(vmcs::guest::CS_LIMIT, lsl(ss()));
        vmwrite(vmcs::guest::SS_LIMIT, lsl(ss()));
        vmwrite(vmcs::guest::DS_LIMIT, lsl(ds()));
        vmwrite(vmcs::guest::ES_LIMIT, lsl(es()));
        vmwrite(vmcs::guest::FS_LIMIT, lsl(fs()));
        vmwrite(vmcs::guest::GS_LIMIT, lsl(gs()));
        vmwrite(vmcs::guest::LDTR_LIMIT, 0u32);
        vmwrite(vmcs::guest::TR_LIMIT, guest_descriptor.tr.bits());

        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, access_rights_from_native(lar(cs())) as u64);
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, access_rights_from_native(lar(ss())) as u64);
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, access_rights_from_native(lar(ds())) as u64);
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, access_rights_from_native(lar(es())) as u64);
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, access_rights_from_native(lar(fs())) as u64);
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, access_rights_from_native(lar(gs())) as u64);
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, access_rights_from_native(0u32));
        vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, access_rights_from_native(guest_descriptor.tss.ar));

        vmwrite(vmcs::guest::GDTR_BASE, guest_descriptor.gdtr.base as u64);
        vmwrite(vmcs::guest::IDTR_BASE, idtr.base as u64);

        vmwrite(vmcs::guest::GDTR_LIMIT, guest_descriptor.gdtr.limit as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, idtr.limit as u64);

        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        log::debug!("Guest Registers State setup successfully!");
    }

    /// Initialize the host state for the currently loaded VMCS.
    ///
    /// The method sets up various host state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.5 HOST-STATE AREA.
    ///
    /// # Arguments
    /// * `host_descriptor` - Descriptor tables for the host.
    /// * `host_paging` - Paging tables for the host.
    pub fn setup_host_registers_state(host_descriptor: &Descriptors, pml4_pa: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up Host Registers State");

        vmwrite(vmcs::host::CR0, Cr0::read_raw());
        vmwrite(vmcs::host::CR3, pml4_pa);
        vmwrite(vmcs::host::CR4, Cr4::read_raw());

        vmwrite(vmcs::host::CS_SELECTOR, host_descriptor.cs.bits());
        vmwrite(vmcs::host::TR_SELECTOR, host_descriptor.tr.bits());

        vmwrite(vmcs::host::TR_BASE, host_descriptor.tss.base);
        vmwrite(vmcs::host::GDTR_BASE, host_descriptor.gdtr.base as u64);
        vmwrite(vmcs::host::IDTR_BASE, u64::MAX); // Bogus. No proper exception handling.

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
    ///
    /// * `primary_eptp` - The EPTP value for the primary EPT.
    /// * `msr_bitmap` - The physical address of the MSR bitmap.
    ///
    /// # Returns
    ///
    /// * `Result<(), HypervisorError>` - A result indicating the success or failure of the operation.
    pub fn setup_vmcs_control_fields(primary_eptp: u64, msr_bitmap: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS Control Fields");

        const PRIMARY_CTL: u64 =
            (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits() | vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits()) as u64;
        const SECONDARY_CTL: u64 = (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
            | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
            | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
            | vmcs::control::SecondaryControls::ENABLE_VPID.bits()
            | vmcs::control::SecondaryControls::ENABLE_EPT.bits()
            | vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits()
            | vmcs::control::SecondaryControls::UNRESTRICTED_GUEST.bits()) as u64;
        const ENTRY_CTL: u64 = (vmcs::control::EntryControls::IA32E_MODE_GUEST.bits()
            | vmcs::control::EntryControls::LOAD_DEBUG_CONTROLS.bits()
            | vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits()) as u64;
        const EXIT_CTL: u64 = (vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits()
            | vmcs::control::ExitControls::SAVE_DEBUG_CONTROLS.bits()
            | vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits()) as u64;
        const PINBASED_CTL: u64 = 0;

        vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmcs::control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        let vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        // Credits to @vmctx
        vmwrite(
            vmcs::control::CR0_GUEST_HOST_MASK,
            vmx_cr0_fixed0 | !vmx_cr0_fixed1 | Cr0Flags::CACHE_DISABLE.bits() | Cr0Flags::WRITE_PROTECT.bits(),
        );
        vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, vmx_cr4_fixed0 | !vmx_cr4_fixed1);

        vmwrite(vmcs::control::CR0_READ_SHADOW, Cr0::read_raw());
        vmwrite(vmcs::control::CR4_READ_SHADOW, Cr4::read_raw() & !Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits());

        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap);
        //vmwrite(vmcs::control::EXCEPTION_BITMAP, 1u64 << (ExceptionInterrupt::Breakpoint as u32));

        vmwrite(vmcs::control::EPTP_FULL, primary_eptp);
        vmwrite(vmcs::control::VPID, VPID_TAG);

        invept_single_context(primary_eptp);
        invvpid_single_context(VPID_TAG);

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
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {
        format
            .debug_struct("Vmcs")
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
            .field("Guest IA32_EFER_FULL: ", &vmread(vmcs::guest::IA32_EFER_FULL))
            .field("Guest VMCS Link Pointer: ", &vmread(vmcs::guest::LINK_PTR_FULL))
            .field("Guest Activity State: ", &vmread(vmcs::guest::ACTIVITY_STATE))
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
            .field("VPID: ", &vmread(vmcs::control::VPID))
            .finish_non_exhaustive()
    }
}
