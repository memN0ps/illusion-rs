//! Provides a mechanism to virtualize the system by installing a hypervisor on the current processor,
//! utilizing custom stack allocation and low-level assembly for context switching. Essential for
//! enabling hardware-assisted virtualization with specific guest register configurations and shared data.
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/switch_stack.rs

use {
    core::arch::global_asm,
    hypervisor::{
        allocate::allocate_stack_space,
        intel::{capture::GuestRegisters, shared::SharedData},
        vmm::start_hypervisor,
    },
    log::debug,
};

/// Installs the hypervisor on the current processor.
///
/// # Arguments
///
/// * `guest_registers` - The guest registers to use for the hypervisor.
/// * `shared_data` - The shared data to use for the hypervisor.
pub fn virtualize_system(guest_registers: &GuestRegisters, shared_data: &mut SharedData) -> ! {
    debug!("Allocating stack space for host");
    let host_stack = allocate_stack_space(0x10);

    unsafe {
        switch_stack(
            guest_registers,
            shared_data as *mut _ as *mut u8,
            start_hypervisor as usize,
            host_stack,
        )
    };
}

extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(
        guest_registers: &GuestRegisters,
        shared_data: *mut u8,
        landing_code: usize,
        host_stack: u64,
    ) -> !;
}

global_asm!(
    r#"
// The module containing the `switch_stack` function. Jumps to the landing code with the new stack pointer.
.global switch_stack
switch_stack:
    xchg    bx, bx
    mov     rsp, r9
    jmp     r8
"#
);
