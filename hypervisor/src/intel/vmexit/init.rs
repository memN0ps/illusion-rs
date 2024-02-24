use x86::bits64::rflags;
use x86::controlregs::Cr0;
use x86::cpuid::{cpuid, CpuId};
use x86::msr::{IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1};
use x86::segmentation::{CodeSegmentType, DataSegmentType};
use x86::vmx::vmcs;
use x86::vmx::vmcs::control::SecondaryControls;
use crate::intel::capture::GuestRegisters;
use crate::intel::support::{cr0, cr2_write, cr4, rdmsr, vmread, vmwrite};

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
    // Handle GDTR and IDTR and LDTR
    //
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