use {
    alloc::alloc::{alloc_zeroed, handle_alloc_error},
    core::{alloc::Layout, arch::global_asm},
    hypervisor::{
        intel::{capture::GuestRegisters, page::Page},
        vmm::start_hypervisor,
    },
    log::debug,
};

/// Installs the hypervisor on the current processor.
pub fn virtualize_system(guest_registers: &GuestRegisters) -> ! {
    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(0x10).unwrap();
    let stack = unsafe { alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + layout.size() as u64 - 0x10;
    debug!("Stack range: {:#x?}", (stack as u64..stack_base));

    unsafe { switch_stack(guest_registers, start_hypervisor as usize, stack_base) };
}

extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(guest_registers: &GuestRegisters, landing_code: usize, stack_base: u64) -> !;
}

global_asm!(
    r#"
// The module containing the `switch_stack` function. Jumps to the landing code with the new stack pointer.
// fn switch_stack(guest_registers: &GuestRegisters, landing_code: usize, stack_base: u64) -> !
.global switch_stack
switch_stack:
    xchg    bx, bx
    mov     rsp, r8
    jmp     rdx
"#
);
