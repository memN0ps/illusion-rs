use x86::bits64::rflags;
use x86::controlregs::Cr0;
use x86::cpuid::{cpuid, CpuId};
use x86::msr::{IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1};
use x86::segmentation::{CodeSegmentType, DataSegmentType, SystemDescriptorTypes64};
use x86::vmx::vmcs;
use x86::vmx::vmcs::control::{SecondaryControls, VPID};
use crate::intel::capture::GuestRegisters;
use crate::intel::invvpid::{invvpid_single_context, VPID_TAG};
use crate::intel::support::{cr0, cr2_write, cr4, dr0_write, dr1_write, dr2_write, dr3_write, dr6_write, rdmsr, vmread, vmwrite};

pub fn handle_init_signal(guest_registers: &mut GuestRegisters) {
    //
    // Initializes the processor to the state after INIT as described in the Intel SDM.
    //

    //
    // See: Table 9-1. IA-32 and Intel 64 Processor States Following Power-up, Reset, or INIT
    //
    vmwrite(vmcs::guest::RFLAGS, rflags::RFlags::FLAGS_A1.bits());
    vmwrite(vmcs::guest::RIP, 0xfff0u64);
    vmwrite(vmcs::control::CR0_READ_SHADOW, 0u64);
    cr2_write(0);
    vmwrite(vmcs::guest::CR3, 0u64);
    vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, 0u64);

    //
    // Actual guest CR0 and CR4 must fulfill requirements for VMX. Apply those.
    //
    vmwrite(vmcs::guest::CR0, adjust_guest_cr0(Cr0::from_bits_truncate(cr0().bits())));
    vmwrite(vmcs::guest::CR4, adjust_cr4(cr4().bits() as u64));

    //
    // Set the CS segment registers to their initial state (ExecuteReadAccessed).
    //
    vmwrite(vmcs::guest::CS_SELECTOR, 0xf000u64);
    vmwrite(vmcs::guest::CS_BASE, 0xffff0000u64);
    vmwrite(vmcs::guest::CS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, CodeSegmentType::ExecuteReadAccessed as u64);

    //
    // Set the SS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::SS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::SS_BASE, 0u64);
    vmwrite(vmcs::guest::SS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, DataSegmentType::ReadWriteAccessed as u64);

    //
    // Set the DS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::DS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::DS_BASE, 0u64);
    vmwrite(vmcs::guest::DS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, DataSegmentType::ReadWriteAccessed as u64);

    //
    // Set the ES segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::ES_SELECTOR, 0u64);
    vmwrite(vmcs::guest::ES_BASE, 0u64);
    vmwrite(vmcs::guest::ES_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, DataSegmentType::ReadWriteAccessed as u64);

    //
    // Set the FS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::FS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::FS_BASE, 0u64);
    vmwrite(vmcs::guest::FS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, DataSegmentType::ReadWriteAccessed as u64);

    //
    // Set the GS segment registers to their initial state (ReadWriteAccessed).
    //
    vmwrite(vmcs::guest::GS_SELECTOR, 0u64);
    vmwrite(vmcs::guest::GS_BASE, 0u64);
    vmwrite(vmcs::guest::GS_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, DataSegmentType::ReadWriteAccessed as u64);

    //
    // Execute CPUID instruction on the host and retrieve the result
    //
    let leaf = guest_registers.rax as u32;
    let sub_leaf = guest_registers.rcx as u32;
    let mut cpuid_result = cpuid!(leaf, sub_leaf);
    let extended_model_id = (cpuid_result.edx >> 16) & 0xF;
    let model_specific_value = 0x600 | ((extended_model_id as u64) << 16);

    guest_registers.rdx = 0x600 | ((extended_model_id as u64) << 16);
    guest_registers.rax = 0x0;
    guest_registers.rbx = 0x0;
    guest_registers.rcx = 0x0;
    guest_registers.rsi = 0x0;
    guest_registers.rdi = 0x0;
    guest_registers.rbp = 0x0;
    vmwrite(vmcs::guest::RSP, 0u64);

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
    vmwrite(vmcs::guest::LDTR_SELECTOR, 0u64);
    vmwrite(vmcs::guest::LDTR_BASE, 0u64);
    vmwrite(vmcs::guest::LDTR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, SystemDescriptorTypes64::LDT as u64);

    //
    // Handle TR
    //

    vmwrite(vmcs::guest::TR_SELECTOR, 0u64);
    vmwrite(vmcs::guest::TR_BASE, 0u64);
    vmwrite(vmcs::guest::TR_LIMIT, 0xffffu64);
    vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, SystemDescriptorTypes64::TssBusy as u64);

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

    //
    // Set Guest EFER, FS_BASE and GS_BASE to 0.
    //

    vmwrite(vmcs::guest::IA32_EFER_FULL, 0u64);
    vmwrite(vmcs::guest::FS_BASE, 0u64);
    vmwrite(vmcs::guest::GS_BASE, 0u64);

    //
    // Set IA32E_MODE_GUEST to 0.
    //
    vmwrite(vmcs::guest::IA32_EFER_HIGH, 0u64);

    //
    // Invalidate TLBs to be on the safe side. It is unclear whether TLBs are
    // invalidated on INIT, as the Intel SDM contradicts itself. However, doing
    // so is harmless, while failure to invalidate them when necessary can cause
    // issues.
    //
    // "Asserting the INIT# pin on the processor invokes a similar response to a
    //  hardware reset. ... the TLBs and BTB are invalidated as with a hardware
    //  reset)."
    //
    // See: 9.1 INITIALIZATION OVERVIEW
    //
    // "
    //  | Register                  | Power up | Reset   | INIT      |
    //  +---------------------------+----------+---------+-----------+
    //  | Data and Code Cache, TLBs | Invalid  | Invalid | Unchanged |
    // ""
    //
    // See: Table 9-1. IA-32 and Intel 64 Processor States Following Power-up, Reset, or INIT
    //
    invvpid_single_context(VPID_TAG);

    //
    // "All the processors on the system bus (...) execute the multiple processor
    //  (MP) initialization protocol. ... The application (non-BSP) processors
    //  (APs) go into a Wait For Startup IPI (SIPI) state while the BSP is executing
    //  initialization code."
    // See: 10.1 INITIALIZATION OVERVIEW
    //
    // "Upon receiving an INIT ..., the processor responds by beginning the
    //  initialization process of the processor core and the local APIC. The state
    //  of the local APIC following an INIT reset is the same as it is after a
    //  power-up or hardware reset ... . This state is also referred to at the
    //  "wait-for-SIPI" state."
    //
    // See: 10.4.7.3 Local APIC State After an INIT Reset ("Wait-for-SIPI" State)
    //
    let vmx_wait_for_sipi = 0x3u64;
    vmwrite(vmcs::guest::ACTIVITY_STATE, vmx_wait_for_sipi);
}

/// Further adjusts CR0 considering the UnrestrictedGuest feature.
fn adjust_guest_cr0(cr0: Cr0) -> u64 {
    // Adjust the CR0 register according to the fixed0 and fixed1 MSR values.
    let mut new_cr0 = adjust_cr0(cr0);

    // Fetch the fixed0 value for CR0 from the MSR to use in UnrestrictedGuest logic.
    let fixed0_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED0) as usize);

    // Read the secondary processor-based VM-execution controls to check for UnrestrictedGuest support.
    let secondary_proc_based_ctls2 = vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS);
    let unrestricted_guest = secondary_proc_based_ctls2 & SecondaryControls::UNRESTRICTED_GUEST.bits() as u64 != 0;

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

/// Adjusts CR0 for VMX operation based on fixed MSRs.
fn adjust_cr0(cr0: Cr0) -> Cr0 {
    let fixed0_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED0) as usize);
    let fixed1_cr0 = Cr0::from_bits_truncate(rdmsr(IA32_VMX_CR0_FIXED1) as usize);
    (cr0 & fixed1_cr0) | fixed0_cr0
}

/// Adjusts CR4 register values based on fixed bits.
fn adjust_cr4(cr4: u64) -> u64 {
    let fixed0 = rdmsr(IA32_VMX_CR4_FIXED0);
    let fixed1 = rdmsr(IA32_VMX_CR4_FIXED1);
    (cr4 & fixed1) | fixed0
}