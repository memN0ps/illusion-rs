//! This crate includes functionalities to handle virtual machine (VM) exit events in a hypervisor environment, particularly focusing on VMCALL instructions
//! which are used for hypercalls or VM-to-hypervisor communication.

use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            ept::AccessType,
            events::EventInjection,
            vm::Vm,
            vmexit::{
                mtf::{set_monitor_trap_flag, update_guest_interrupt_flag},
                ExitType,
            },
        },
    },
    log::*,
    x86::bits64::paging::PAddr,
};

/// Represents various VMCALL commands that a guest can issue to the hypervisor.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmcallCommand {
    /// Command to indicate an unknown or unimplemented VMCALL command.
    Unknown = 0,
}

/// Handles a VMCALL VM exit by executing the corresponding action based on the VMCALL command.
///
/// # Parameters
///
/// * `vm`: A mutable reference to the virtual machine instance encountering the VMCALL exit.
///
/// # Returns
///
/// * `Ok(ExitType)`: The continuation exit type after handling the VMCALL, usually indicates that VM execution should continue.
/// * `Err(HypervisorError)`: An error if the VMCALL command is unknown or if there's a failure in handling the command.
///
/// # Errors
///
/// * `HypervisorError::UnknownVmcallCommand`: Returned if the VMCALL command is not recognized.
pub fn handle_vmcall(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    debug!("Handling VMCALL VM exit...");
    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    let vmcall_number = vm.guest_registers.rax;
    trace!("Guest RAX - VMCALL command number: {:#x}", vmcall_number);
    trace!("Guest RIP: {:#x}", vm.guest_registers.rip);

    let guest_pa = PAddr::from(PhysicalAddress::pa_from_va(vm.guest_registers.rip));
    trace!("Guest PA: {:#x}", guest_pa.as_u64());

    let guest_page_pa = guest_pa.align_down_to_base_page();
    trace!("Guest Page PA: {:#x}", guest_page_pa.as_u64());

    // Set the current hook to the EPT hook for handling MTF exit
    let exit_type = if let Some(shadow_page_pa) = vm.hook_manager.memory_manager.get_shadow_page_as_ptr(guest_page_pa.as_u64()) {
        trace!("Shadow Page PA: {:#x}", shadow_page_pa);

        trace!("Executing VMCALL hook on shadow page for EPT hook at PA: {:#x} with VA: {:#x}", guest_pa, vm.guest_registers.rip);
        // crate::windows::log::log_nt_query_system_information_params(&vm.guest_registers);
        // crate::windows::log::log_nt_create_file_params(&vm.guest_registers);
        // crate::windows::log::log_nt_open_process_params(&vm.guest_registers);
        // crate::windows::log::log_mm_is_address_valid_params(&vm.guest_registers);

        let pre_alloc_pt = vm
            .hook_manager
            .memory_manager
            .get_page_table_as_mut(guest_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        // Perform swap_page before the mutable borrow for update_guest_interrupt_flag
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;

        // Calculate the number of instructions in the function to set the MTF counter for restoring overwritten instructions by single-stepping.
        // (NOTE: CHANGE HOOK SIZE IF YOU MOVE THIS INTO CPUID OR INT3)
        let instruction_count = unsafe { calculate_instruction_count(guest_pa.as_u64(), 3) as u64 };
        vm.hook_manager.mtf_counter = Some(instruction_count);

        // Set the monitor trap flag and initialize counter to the number of overwritten instructions
        set_monitor_trap_flag(true);

        // Ensure all data mutations to vm are done before calling this.
        // This function will update the guest interrupt flag to prevent interrupts while single-stepping
        update_guest_interrupt_flag(vm, false)?;

        Ok(ExitType::Continue)
    } else {
        EventInjection::vmentry_inject_gp(0);
        Ok(ExitType::Continue)
    };

    exit_type
}

/// Calculates the number of instructions that fit into the given number of bytes,
/// adjusting for partial instruction overwrites by including the next full instruction.
///
/// # Safety
///
/// This function is unsafe because it performs operations on raw pointers. The caller must
/// ensure that the memory at `guest_pa` (converted properly to a virtual address if necessary)
/// is valid and that reading beyond `hook_size` bytes does not cause memory violations.
pub unsafe fn calculate_instruction_count(guest_pa: u64, hook_size: usize) -> usize {
    // Define a buffer size, typical maximum x86-64 instruction length is 15 bytes.
    let buffer_size = hook_size + 15; // Buffer size to read, slightly larger than hook_size to accommodate potential long instructions at the boundary.
    let bytes = core::slice::from_raw_parts(guest_pa as *const u8, buffer_size);

    let mut byte_count = 0;
    let mut instruction_count = 0;
    // Use a disassembler engine to iterate over the instructions within the bytes read.
    for (opcode, pa) in lde::X64.iter(bytes, guest_pa) {
        byte_count += opcode.len();
        instruction_count += 1;

        trace!("{:x}: {}", pa, opcode);
        if byte_count >= hook_size {
            break;
        }
    }

    trace!("Calculated byte count: {}", byte_count);
    trace!("Calculated instruction count: {}", instruction_count);

    instruction_count
}
