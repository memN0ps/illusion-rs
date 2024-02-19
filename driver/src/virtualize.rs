use core::ffi::c_void;
use {
    alloc::alloc::{alloc_zeroed, handle_alloc_error},
    core::{alloc::Layout, arch::global_asm},
    hypervisor::{global::GlobalState, intel::page::Page, vmm::start_hypervisor},
    log::debug,
    uefi::{
        proto::loaded_image::LoadedImage,
        table::{Boot, SystemTable},
    },
};

pub fn zap_relocations(system_table: &SystemTable<Boot>) {
    let boot_service = system_table.boot_services();

    // Open the loaded image protocol to get the current image base and image size.
    let loaded_image = boot_service
        .open_protocol_exclusive::<LoadedImage>(boot_service.image_handle())
        .unwrap();

    // Get the current image base and image size.
    let (image_base, image_size) = loaded_image.info();

    let image_base = image_base as usize;

    let image_range = image_base..image_base + image_size as usize;
    debug!("Image base: {:#x?}", image_range);

    // Prevent relocation by zapping the Relocation Table in the PE header. UEFI
    // keeps the list of runtime drivers and applies patches into their code and
    // data according to relocation information, as address translation switches
    // from physical-mode to virtual-mode when the OS starts. This causes a problem
    // with us because the host part keeps running under physical-mode, as the
    // host has its own page tables. Relocation ends up breaking the host code.
    // The easiest way is prevented this from happening is to nullify the relocation
    // table.
    unsafe {
        *((image_base + 0x128) as *mut u32) = 0;
        *((image_base + 0x12c) as *mut u32) = 0;
    }
}

pub fn allocate_stack() -> u64 {
    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(0x10).unwrap();

    let stack = unsafe { alloc_zeroed(layout) };

    if stack.is_null() {
        handle_alloc_error(layout);
    }

    let stack_base = stack as u64 + layout.size() as u64 - 0x10;
    debug!("Stack range: {:#x?}", stack_base..stack as u64);

    stack_base
}

pub extern "efiapi" fn switch_stack_and_virtualize_core(procedure_argument: *mut c_void) {
    let global_state = unsafe { &mut *(procedure_argument as *mut GlobalState) };
    let stack_base = allocate_stack();

    unsafe { switch_stack(global_state, start_hypervisor as usize, stack_base) };
}

extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(global_state: &mut GlobalState, landing_code: usize, stack_base: u64) -> !;
}

global_asm!(
    r#"
// The module containing the `switch_stack` function.
// Jumps to the landing code with the new stack pointer.
//
// fn switch_stack(global_state: &mut GlobalState, landing_code: usize, stack_base: u64) -> !
.global switch_stack
switch_stack:
    xchg    bx, bx
    mov     rsp, r8
    jmp     rdx
"#
);
