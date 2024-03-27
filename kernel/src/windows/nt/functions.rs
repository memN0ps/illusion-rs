use {crate::windows::nt::types::PHYSICAL_ADDRESS, core::ffi::c_void, spin::Mutex};

extern crate spin;

/// https://github.com/microsoft/windows-drivers-rs/blob/main/crates/wdk-sys/generated_bindings/ntddk.rs#L7902C56-L7902C72
pub type fnMmGetPhysicalAddress =
    extern "system" fn(BaseAddress: *const c_void) -> PHYSICAL_ADDRESS;

/// https://github.com/microsoft/windows-drivers-rs/blob/main/crates/wdk-sys/generated_bindings/ntddk.rs#L7930
pub type fnMmGetVirtualForPhysical =
    extern "system" fn(PhysicalAddress: PHYSICAL_ADDRESS) -> *mut c_void;

pub static MM_GET_PHYSICAL_ADDRESS: Mutex<Option<fnMmGetPhysicalAddress>> = Mutex::new(None);
pub static MM_GET_VIRTUAL_FOR_PHYSICAL: Mutex<Option<fnMmGetVirtualForPhysical>> = Mutex::new(None);

pub fn set_mm_get_physical_address(func: fnMmGetPhysicalAddress) {
    *MM_GET_PHYSICAL_ADDRESS.lock() = Some(func);
}

pub fn set_mm_get_virtual_for_physical(func: fnMmGetVirtualForPhysical) {
    *MM_GET_VIRTUAL_FOR_PHYSICAL.lock() = Some(func);
}

pub fn MmGetPhysicalAddress(BaseAddress: *const c_void) -> PHYSICAL_ADDRESS {
    if let Some(func) = *MM_GET_PHYSICAL_ADDRESS.lock() {
        func(BaseAddress)
    } else {
        panic!("MmGetPhysicalAddress not set");
    }
}

pub fn MmGetVirtualForPhysical(PhysicalAddress: PHYSICAL_ADDRESS) -> *mut c_void {
    if let Some(func) = *MM_GET_VIRTUAL_FOR_PHYSICAL.lock() {
        func(PhysicalAddress)
    } else {
        panic!("MmGetVirtualForPhysical not set");
    }
}
