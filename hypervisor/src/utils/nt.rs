#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use {
    crate::error::HypervisorError,
    alloc::vec::Vec,
    wdk_sys::{
        ntddk::{
            KeLowerIrql, KeStackAttachProcess, KeUnstackDetachProcess, MmGetSystemRoutineAddress,
        },
        KIRQL, PEPROCESS, PRKPROCESS, PVOID, UNICODE_STRING, _KAPC_STATE,
    },
};

/// Gets a pointer to a function from ntoskrnl.exe exports.
///
/// # Arguments
/// * `function_name` - The name of the function to retrieve.
///
/// # Returns
/// A pointer to the requested function, or null if not found.
fn get_ntoskrnl_export(function_name: &str) -> PVOID {
    let wide_string: Vec<u16> = function_name
        .encode_utf16()
        .chain(core::iter::once(0)) // Add null terminator
        .collect();

    let unicode_string = UNICODE_STRING {
        Length: ((wide_string.len() - 1) * 2) as u16, // Length in bytes, excluding the null terminator
        MaximumLength: (wide_string.len() * 2) as u16,
        Buffer: wide_string.as_ptr() as *mut _,
    };

    // Using a local variable to hold the wide string ensures it is not dropped prematurely.
    let routine_address =
        unsafe { MmGetSystemRoutineAddress(&unicode_string as *const _ as *mut _) };

    // The wide_string will be dropped here, after the UNICODE_STRING is no longer needed.
    routine_address
}

/// Raises the current IRQL to DISPATCH_LEVEL and returns the previous IRQL.
///
/// # Returns
/// * `Ok(KIRQL)` with the previous IRQL on success, or `Err(HypervisorError::KeRaiseIrqlToDpcLevelNull)` if the function pointer is null.
pub fn raise_irql_to_dpc_level() -> Result<KIRQL, HypervisorError> {
    type FnKeRaiseIrqlToDpcLevel = unsafe extern "system" fn() -> KIRQL;

    // Get the address of the function from ntoskrnl
    let routine_address = get_ntoskrnl_export("KeRaiseIrqlToDpcLevel");

    // Ensure that the address is valid
    let pKeRaiseIrqlToDpcLevel = if !routine_address.is_null() {
        unsafe { core::mem::transmute::<PVOID, FnKeRaiseIrqlToDpcLevel>(routine_address) }
    } else {
        return Err(HypervisorError::KeRaiseIrqlToDpcLevelNull);
    };

    // Invoke the retrieved function
    Ok(unsafe { pKeRaiseIrqlToDpcLevel() })
}

/// Lowers the current IRQL to the specified value.
///
/// # Arguments
/// * `old_irql` - The IRQL to which the current IRQL should be lowered.
pub fn lower_irql_to_old_level(old_irql: KIRQL) {
    // Directly manipulating the IRQL is an unsafe operation
    unsafe { KeLowerIrql(old_irql) };
}

/// Represents the CR3 (Directory Table Base) of the system process.
///
/// This is typically used to store the page table root physical address
/// of the system process for use in virtual-to-physical address translation.
pub static mut NTOSKRNL_CR3: u64 = 0;

/// Updates the `NTOSKRNL_CR3` static with the CR3 of the system process.
///
/// Retrieves the Directory Table Base (DirBase) of the system process,
/// typically corresponding to the NT kernel (`ntoskrnl`).
///
/// # Credits
///
/// Credits to @Drew from https://github.com/drew-gpf for the help.
pub fn update_ntoskrnl_cr3() {
    // Default initialization of APC state.
    let mut apc_state = _KAPC_STATE::default();

    // Attach to the system process's stack safely.
    // `KeStackAttachProcess` is unsafe as it manipulates thread execution context.
    unsafe { KeStackAttachProcess(PsInitialSystemProcess as PRKPROCESS, &mut apc_state) };

    // Update the NTOSKRNL_CR3 static with the current CR3 value.
    // Accessing CR3 is an unsafe operation as it involves reading a control register.
    unsafe {
        NTOSKRNL_CR3 = x86::controlregs::cr3();
    }

    log::info!("NTOSKRNL_CR3: {:#x}", unsafe { NTOSKRNL_CR3 });

    // Detach from the system process's stack safely.
    // `KeUnstackDetachProcess` is unsafe as it restores the previous thread execution context.
    unsafe { KeUnstackDetachProcess(&mut apc_state) };
}

#[link(name = "ntoskrnl")]
extern "C" {
    pub static mut PsInitialSystemProcess: PEPROCESS;
}
