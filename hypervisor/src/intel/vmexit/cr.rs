use {
    crate::{
        error::HypervisorError,
        intel::{
            events::EventInjection,
            invvpid::{invvpid_single_context, VPID_TAG},
            support::{rdmsr, read_effective_guest_cr0, read_effective_guest_cr4, vmread, vmwrite},
            vm::Vm,
            vmerror::{ControlRegAccessExitQualification, CrAccessReg, CrAccessType},
            vmexit::ExitType,
        },
    },
    bit_field::BitField,
    core::{ops::Range, ptr::addr_of},
    x86::vmx::{
        vmcs,
        vmcs::{control, guest},
    },
    x86_64::registers::control::{Cr0Flags, Cr4Flags},
};

/// Handles the `ControlRegisterAccess` VM-exit.
///
/// This function is invoked when the guest executes certain instructions
/// that read or write to control registers.
///
/// # Arguments
///
/// * `vm`: A mutable reference to the VM.
///
/// # Returns
///
/// * `Result<ExitType, HypervisorError>`: Ok with the appropriate exit type or an error.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.3 Instructions That Cause VM Exits Conditionally
pub fn handle_cr_reg_access(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    let qual = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let cr = ControlRegAccessExitQualification::from_exit_qualification(qual);
    match cr.access_type {
        CrAccessType::MovToCr => match cr.control_reg {
            CrAccessReg::Cr2 | CrAccessReg::Cr3 | CrAccessReg::Cr8 => Err(HypervisorError::UnhandledVmExit),
            CrAccessReg::Cr0 => Ok(handle_mov_to_cr0(vm, cr.gpr_mov_cr)),
            CrAccessReg::Cr4 => Ok(handle_mov_to_cr4(vm, cr.gpr_mov_cr)?),
        },
        CrAccessType::MovFromCr | CrAccessType::Clts | CrAccessType::Lmsw => Err(HypervisorError::UnhandledVmExit),
    }
}

/// The MOV to CR0 instruction causes a VM exit unless the value of its source operand matches, for
/// the position of each bit set in the CR0 guest/host mask, the corresponding bit in the CR0 read shadow. (If every
/// bit is clear in the CR0 guest/host mask, MOV to CR0 cannot cause a VM exit.)
///
/// # Arguments
///
/// * `vm`: A mutable reference to the VM.
/// * `gpr`: The general-purpose register index.
///
/// # Returns
///
/// * `ExitType`: The appropriate exit type.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.3 Instructions That Cause VM Exits Conditionally
fn handle_mov_to_cr0(vm: &mut Vm, gpr: u64) -> ExitType {
    let mut new_cr0 = unsafe { Cr0Flags::from_bits_retain(addr_of!(vm.guest_registers).cast::<u64>().add(gpr as usize).read_unaligned()) };

    let curr_cr0 = Cr0Flags::from_bits_retain(read_effective_guest_cr0());
    let curr_cr4 = Cr4Flags::from_bits_retain(read_effective_guest_cr4());

    let mut new_cr0_raw = new_cr0.bits();

    // CR0[15:6] is always 0
    new_cr0_raw.set_bits(6..16, 0);

    // CR0[17] is always 0
    new_cr0_raw.set_bit(17, false);

    // CR0[28:19] is always 0
    new_cr0_raw.set_bits(19..29, 0);

    new_cr0 = Cr0Flags::from_bits_retain(new_cr0_raw);

    // CR0.ET is always 1
    new_cr0.set(Cr0Flags::EXTENSION_TYPE, true);

    // #GP(0) if setting any reserved bits in CR0[63:32]
    if new_cr0.bits().get_bits(32..64) != 0 {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if setting CR0.PG while CR0.PE is clear
    if new_cr0.contains(Cr0Flags::PAGING) && !new_cr0.contains(Cr0Flags::PROTECTED_MODE_ENABLE) {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if invalid bit combination
    if !new_cr0.contains(Cr0Flags::CACHE_DISABLE) && new_cr0.contains(Cr0Flags::NOT_WRITE_THROUGH) {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if an attempt is made to clear CR0.PG
    if !new_cr0.contains(Cr0Flags::PAGING) {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if an attempt is made to clear CR0.WP while CR4.CET is set
    if !new_cr0.contains(Cr0Flags::WRITE_PROTECT) && curr_cr4.contains(Cr4Flags::CONTROL_FLOW_ENFORCEMENT) {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    if new_cr0.contains(Cr0Flags::CACHE_DISABLE) != new_cr0.contains(Cr0Flags::CACHE_DISABLE)
        || new_cr0.contains(Cr0Flags::NOT_WRITE_THROUGH) != curr_cr0.contains(Cr0Flags::NOT_WRITE_THROUGH)
    {
        // https://github.com/jonomango/hv/blob/cd4d4022351b5d762045a02108973c697a79bb34/hv/exit-handlers.cpp#L284

        unimplemented!()
        //invept_all_contexts();
    }

    vmwrite(control::CR0_READ_SHADOW, new_cr0.bits());

    let vmx_cr0_fixed0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED0);
    let vmx_cr0_fixed1 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED1);

    // make sure to account for VMX reserved bits when setting the real CR0
    new_cr0 |= Cr0Flags::from_bits_retain(vmx_cr0_fixed0);
    new_cr0 &= Cr0Flags::from_bits_retain(vmx_cr0_fixed1);

    vmwrite(guest::CR0, new_cr0.bits());

    ExitType::IncrementRIP
}

/// The MOV to CR4 instruction causes a VM exit unless the value of its source operand matches, for
/// the position of each bit set in the CR4 guest/host mask, the corresponding bit in the CR4 read shadow.
///
/// # Arguments
///
/// * `vm`: A mutable reference to the VM.
/// * `gpr`: The general-purpose register index.
///
/// # Returns
///
/// * `Result<ExitType, HypervisorError>`: Ok with the appropriate exit type or an error.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.3 Instructions That Cause VM Exits Conditionally
fn handle_mov_to_cr4(vm: &mut Vm, gpr: u64) -> Result<ExitType, HypervisorError> {
    const CR4_RESERVED_1: usize = 15;
    const CR4_RESERVED_2: Range<usize> = 32..64;

    let mut new_cr4 = unsafe { Cr4Flags::from_bits_retain(addr_of!(vm.guest_registers).cast::<u64>().add(gpr as usize).read_unaligned()) };

    let curr_cr3 = vmread(guest::CR3);

    let curr_cr0 = Cr0Flags::from_bits_retain(read_effective_guest_cr0());
    let curr_cr4 = Cr4Flags::from_bits_retain(read_effective_guest_cr4());

    // #GP(0) if an attempt is made to set CR4.SMXE when SMX is not supported
    if vm.cpuid_feature_info.has_smx() && new_cr4.contains(Cr4Flags::SAFER_MODE_EXTENSIONS) {
        EventInjection::vmentry_inject_gp(0);
        return Ok(ExitType::Continue);
    }

    // #GP(0) if an attempt is made to write to any reserved bits
    if new_cr4.bits().get_bit(CR4_RESERVED_1) || new_cr4.bits().get_bits(CR4_RESERVED_2) != 0 {
        EventInjection::vmentry_inject_gp(0);
        return Ok(ExitType::Continue);
    }

    // #GP(0) if an attempt is made to change CR4.PCIDE from 0 to 1 while CR3[11:0] != 000H
    if new_cr4.contains(Cr4Flags::PCID) && !curr_cr4.contains(Cr4Flags::PCID) && curr_cr3.get_bits(0..12) != 0 {
        EventInjection::vmentry_inject_gp(0);
        return Ok(ExitType::Continue);
    }

    // #GP(0) if CR4.PAE is cleared
    if !new_cr4.contains(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION) {
        EventInjection::vmentry_inject_gp(0);
        return Ok(ExitType::Continue);
    }

    // #GP(0) if CR4.LA57 is enabled
    if new_cr4.contains(Cr4Flags::L5_PAGING) {
        EventInjection::vmentry_inject_gp(0);
        return Ok(ExitType::Continue);
    }

    // #GP(0) if CR4.CET == 1 and CR0.WP == 0
    if new_cr4.contains(Cr4Flags::CONTROL_FLOW_ENFORCEMENT) && !curr_cr0.contains(Cr0Flags::WRITE_PROTECT) {
        EventInjection::vmentry_inject_gp(0);
        return Ok(ExitType::Continue);
    }

    // invalidate TLB entries if required
    if (new_cr4.contains(Cr4Flags::PAGE_GLOBAL) != curr_cr4.contains(Cr4Flags::PAGE_GLOBAL))
        || !new_cr4.contains(Cr4Flags::PCID) && curr_cr4.contains(Cr4Flags::PCID)
        || new_cr4.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION) && !curr_cr4.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION)
    {
        invvpid_single_context(VPID_TAG);
    }

    vmwrite(control::CR4_READ_SHADOW, new_cr4.bits());

    let vmx_cr4_fixed0 = rdmsr(x86::msr::IA32_VMX_CR4_FIXED0);
    let vmx_cr4_fixed1 = rdmsr(x86::msr::IA32_VMX_CR4_FIXED1);

    // make sure to account for VMX reserved bits when setting the real CR4
    new_cr4 |= Cr4Flags::from_bits_retain(vmx_cr4_fixed0);
    new_cr4 &= Cr4Flags::from_bits_retain(vmx_cr4_fixed1);

    vmwrite(guest::CR4, new_cr4.bits());

    Ok(ExitType::IncrementRIP)
}
