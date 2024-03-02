//! Provides VMX signal handling and control register adjustment.
//!
//! Includes functionality for responding to INIT signals in a virtualized environment and adjusting
//! control registers (CR0, CR4) to meet VMX operation requirements. Essential for virtual machine initialization
//! and maintaining correct processor states.

use {
    crate::intel::{
        capture::GuestRegisters,
        invvpid::invvpid_single_context,
        support::{
            cr2_write, dr0_write, dr1_write, dr2_write, dr3_write, dr6_write, rdmsr, vmread,
            vmwrite,
        },
        vmexit::ExitType,
    },
    bitflags::Flags,
    x86::{
        bits64::rflags,
        controlregs::Cr0,
        msr::{IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1},
        segmentation::{CodeSegmentType, DataSegmentType, Descriptor, SystemDescriptorTypes64},
        vmx::vmcs::{self, control::SecondaryControls},
    },
    x86_64::registers::control::Cr4Flags,
};

/// Handles the INIT signal by initializing processor state according to Intel SDM.
///
/// Initializes the guest's processor state to mimic the state after receiving an INIT signal, including
/// setting registers and segment selectors to their startup values. This ensures the guest VM is correctly
/// initialized in line with the MP initialization protocol.
///
/// # Arguments
///
/// - `guest_registers`: A mutable reference to the guest's general-purpose registers.
///
/// # Returns
///
/// Returns `ExitType::Continue` to indicate the VM should continue execution post-initialization.
pub fn handle_init_signal(guest_registers: &mut GuestRegisters) -> ExitType {
    //
    // Initializes the processor to the state after INIT as described in the Intel SDM.
    //

    //
    // See: Table 9-1. IA-32 and Intel 64 Processor States Following Power-up, Reset, or INIT
    //
    guest_registers.rflags = rflags::RFlags::FLAGS_A1.bits();
    vmwrite(vmcs::guest::RFLAGS, guest_registers.rflags);
    guest_registers.rip = 0xfff0u64;
    vmwrite(vmcs::guest::RIP, guest_registers.rip);
    vmwrite(vmcs::control::CR0_READ_SHADOW, 0u64);
    cr2_write(0);
    vmwrite(vmcs::guest::CR3, 0u64);
    vmwrite(vmcs::control::CR4_READ_SHADOW, 0u64);

    //
    // Actual guest CR0 and CR4 must fulfill requirements for VMX. Apply those.
    //
    vmwrite(vmcs::guest::CR0, adjust_guest_cr0(Cr0::CR0_EXTENSION_TYPE));
    vmwrite(vmcs::guest::CR4, adjust_cr4());

    //
    // Set the CS segment registers to their initial state (ExecuteReadAccessed).
    //
    let mut descriptor: Descriptor = Descriptor::default();
    descriptor.set_type(CodeSegmentType::ExecuteReadAccessed as u8);
    descriptor.set_s();
    descriptor.set_p();
    vmwrite(vmcs::guest::CS_SELECTOR, 0xf000u64);
    vmwrite(vmcs::guest::CS_BASE, 0xffff0000u64);
    vmwrite(vmcs::guest::CS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Set the SS segment registers to their initial state (ReadWriteAccessed).
    //
    descriptor.set_type(DataSegmentType::ReadWriteAccessed as u8);
    vmwrite(vmcs::guest::SS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::SS_BASE, 0u64);
    vmwrite(vmcs::guest::SS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Set the DS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::DS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::DS_BASE, 0u64);
    vmwrite(vmcs::guest::DS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Set the ES segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::ES_SELECTOR, 0u64);
    vmwrite(vmcs::guest::ES_BASE, 0u64);
    vmwrite(vmcs::guest::ES_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Set the FS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::FS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::FS_BASE, 0u64);
    vmwrite(vmcs::guest::FS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Set the GS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::GS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::GS_BASE, 0u64);
    vmwrite(vmcs::guest::GS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Execute CPUID instruction on the host and retrieve the result
    //
    let extended_model_id = get_cpuid_feature_info().extended_model_id();
    guest_registers.rdx = 0x600 | ((extended_model_id as u64) << 16);
    guest_registers.rax = 0x0;
    guest_registers.rbx = 0x0;
    guest_registers.rcx = 0x0;
    guest_registers.rsi = 0x0;
    guest_registers.rdi = 0x0;
    guest_registers.rbp = 0x0;

    // RSP
    guest_registers.rsp = 0x0u64;
    vmwrite(vmcs::guest::RSP, guest_registers.rsp);

    //
    // Handle GDTR and IDTR
    //
    vmwrite(vmcs::guest::GDTR_BASE, 0u64);
    vmwrite(vmcs::guest::GDTR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::IDTR_BASE, 0u64);
    vmwrite(vmcs::guest::IDTR_LIMIT, 0xffffu64);

    //
    // Handle LDTR
    //
    let mut descriptor: Descriptor = Descriptor::default();
    descriptor.set_type(SystemDescriptorTypes64::LDT as u8);
    descriptor.set_p();
    vmwrite(vmcs::guest::LDTR_SELECTOR, 0u64);
    vmwrite(vmcs::guest::LDTR_BASE, 0u64);
    vmwrite(vmcs::guest::LDTR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // Handle TR
    //
    descriptor.set_type(SystemDescriptorTypes64::TssBusy as u8);
    vmwrite(vmcs::guest::TR_SELECTOR, 0u64);
    vmwrite(vmcs::guest::TR_BASE, 0u64);
    vmwrite(vmcs::guest::TR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, descriptor.as_u64());

    //
    // DR0, DR1, DR2, DR3, DR6, DR7
    //
    dr0_write(0u64);
    dr1_write(0u64);
    dr2_write(0u64);
    dr3_write(0u64);
    dr6_write(0xffff0ff0u64);
    vmwrite(vmcs::guest::DR7, 0x400u64);

    //
    // Set the guest registers r8-r15 to 0.
    //
    guest_registers.r8 = 0u64;
    guest_registers.r9 = 0u64;
    guest_registers.r10 = 0u64;
    guest_registers.r11 = 0u64;
    guest_registers.r12 = 0u64;
    guest_registers.r13 = 0u64;
    guest_registers.r14 = 0u64;
    guest_registers.r15 = 0u64;

    //
    // Those registers are supposed to be cleared but that is not implemented here.
    //  - IA32_XSS
    //  - BNDCFGU
    //  - BND0-BND3
    //  - IA32_BNDCFGS

    //
    // Set Guest EFER, FS_BASE and GS_BASE to 0.
    //
    vmwrite(vmcs::guest::IA32_EFER_FULL, 0u64);
    vmwrite(vmcs::guest::FS_BASE, 0u64);
    vmwrite(vmcs::guest::GS_BASE, 0u64);

    //
    // Set IA32E_MODE_GUEST to 0.
    //
    let mut vmentry_controls = vmread(vmcs::control::VMENTRY_CONTROLS);
    vmentry_controls &= !(1 << 9); // Clear the IA32E_MODE_GUEST bit
    vmwrite(vmcs::control::VMENTRY_CONTROLS, vmentry_controls);

    //
    // Invalidate TLB for current VPID
    //
    invvpid_single_context(vmread(vmcs::control::VPID) as _);

    //
    // Set the activity state to "Wait for SIPI".
    //
    let vmx_wait_for_sipi = 0x3u64;
    vmwrite(vmcs::guest::ACTIVITY_STATE, vmx_wait_for_sipi);

    ExitType::Continue
}

/// Adjusts guest CR0 considering UnrestrictedGuest feature and fixed MSRs.
///
/// Modifies the guest's CR0 register to ensure it meets VMX operation constraints, particularly
/// when the UnrestrictedGuest feature is enabled. Adjusts for protection and paging enable bits.
///
/// # Arguments
///
/// - `cr0`: The original CR0 register value from the guest.
///
/// # Returns
///
/// Returns the adjusted CR0 value as a `u64`.
fn adjust_guest_cr0(cr0: Cr0) -> u64 {
    // Adjust the CR0 register according to the fixed0 and fixed1 MSR values.
    let mut new_cr0 = adjust_cr0(cr0);

    // Fetch the fixed0 value for CR0 from the MSR to use in UnrestrictedGuest logic.
    let fixed0_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED0) as usize);

    // Read the secondary processor-based VM-execution controls to check for UnrestrictedGuest support.
    let secondary_proc_based_ctls2 = vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS);
    let unrestricted_guest =
        secondary_proc_based_ctls2 & SecondaryControls::UNRESTRICTED_GUEST.bits() as u64 != 0;

    if unrestricted_guest {
        let protection_enable = Cr0::CR0_PROTECTED_MODE;
        let paging_enable = Cr0::CR0_ENABLE_PAGING;

        if cr0.contains(protection_enable) && fixed0_cr0.contains(protection_enable) {
            new_cr0.insert(protection_enable);
        } else {
            new_cr0.remove(protection_enable);
        }

        if cr0.contains(paging_enable) && fixed0_cr0.contains(paging_enable) {
            new_cr0.insert(paging_enable);
        } else {
            new_cr0.remove(paging_enable);
        }
    }

    new_cr0.bits() as u64
}

/// Adjusts guest CR0 considering UnrestrictedGuest feature and fixed MSRs.
///
/// Modifies the guest's CR0 register to ensure it meets VMX operation constraints, particularly
/// when the UnrestrictedGuest feature is enabled. Adjusts for protection and paging enable bits.
///
/// # Arguments
///
/// - `cr0`: The original CR0 register value from the guest.
///
/// # Returns
///
/// Returns the adjusted CR0 value as a `u64`.
fn adjust_cr0(cr0: Cr0) -> Cr0 {
    let fixed0_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED0) as usize);
    let fixed1_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED1) as usize);
    let new_cr0 = (cr0 & fixed1_cr0) | fixed0_cr0;
    new_cr0
}

/// Adjusts CR4 for VMX operation, considering fixed bit requirements.
///
/// Sets or clears CR4 bits based on the IA32_VMX_CR4_FIXED0/1 MSRs to ensure the register
/// meets VMX operation constraints.
///
/// # Returns
///
/// Returns the adjusted CR4 value as a `u64`.
fn adjust_cr4() -> u64 {
    let fixed0_cr4 = Cr4Flags::from_bits_truncate(rdmsr(IA32_VMX_CR4_FIXED0));
    let zero_cr4 = Cr4Flags::empty();
    let new_cr4 =
        (zero_cr4 & Cr4Flags::from_bits_truncate(rdmsr(IA32_VMX_CR4_FIXED1))) | fixed0_cr4;
    new_cr4.bits()
}

/// Retrieves CPU feature information using the CPUID instruction.
///
/// Executes the CPUID instruction to obtain various feature information about the processor,
/// which can be used for further adjustments and checks in the virtualization context.
///
/// # Returns
///
/// Returns a `FeatureInfo` struct containing the CPU feature information.
pub fn get_cpuid_feature_info() -> x86::cpuid::FeatureInfo {
    let cpuid = x86::cpuid::CpuId::new();
    let cpu_version_info = cpuid.get_feature_info().unwrap();
    cpu_version_info
}
