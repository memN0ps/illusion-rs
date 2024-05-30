use {crate::intel::capture::GuestRegisters, log::info};

#[allow(dead_code)]
pub fn log_mm_is_address_valid_params(regs: &GuestRegisters) {
    info!(
        "MmIsAddressValid called with parameters:\n\
         VirtualAddress: {:#018x}", // Typically passed in RCX for x64 calling convention
        regs.rcx // VirtualAddress to check
    );
}

#[allow(dead_code)]
pub fn log_nt_query_system_information_params(regs: &GuestRegisters) {
    info!(
        "NtQuerySystemInformation called with parameters: SystemInformationClass: {}, \
        SystemInformation: {:#018x}, SystemInformationLength: {}, ReturnLength: {:#018x}",
        system_information_class_name(regs.rcx as u32),
        regs.rdx,
        regs.r8,
        regs.r9,
    );
}

#[allow(dead_code)]
pub fn system_information_class_name(class: u32) -> &'static str {
    match class {
        0x00 => "SystemBasicInformation",
        0x01 => "SystemProcessorInformation",
        0x02 => "SystemPerformanceInformation",
        0x03 => "SystemTimeOfDayInformation",
        0x04 => "SystemPathInformation",
        0x05 => "SystemProcessInformation",
        0x06 => "SystemCallCountInformation",
        0x07 => "SystemDeviceInformation",
        0x08 => "SystemProcessorPerformanceInformation",
        0x09 => "SystemFlagsInformation",
        0x0A => "SystemCallTimeInformation",
        0x0B => "SystemModuleInformation",
        0x0C => "SystemLocksInformation",
        0x0D => "SystemStackTraceInformation",
        0x0E => "SystemPagedPoolInformation",
        0x0F => "SystemNonPagedPoolInformation",
        0x10 => "SystemHandleInformation",
        0x11 => "SystemObjectInformation",
        0x12 => "SystemPageFileInformation",
        0x13 => "SystemVdmInstemulInformation",
        0x14 => "SystemVdmBopInformation",
        0x15 => "SystemFileCacheInformation",
        0x16 => "SystemPoolTagInformation",
        0x17 => "SystemInterruptInformation",
        0x18 => "SystemDpcBehaviorInformation",
        0x19 => "SystemMemoryInformation",
        0x1A => "SystemLoadGdiDriverInformation",
        0x1B => "SystemUnloadGdiDriverInformation",
        0x1C => "SystemTimeAdjustmentInformation",
        0x1D => "SystemSummaryMemoryInformation",
        0x1E => "SystemNextEventIdInformation",
        0x1F => "SystemEventIdsInformation",
        0x20 => "SystemCrashDumpInformation",
        0x21 => "SystemExceptionInformation",
        0x22 => "SystemCrashDumpStateInformation",
        0x23 => "SystemKernelDebuggerInformation",
        0x24 => "SystemContextSwitchInformation",
        0x25 => "SystemRegistryQuotaInformation",
        0x26 => "SystemExtendServiceTableInformation",
        0x27 => "SystemPrioritySeperation",
        0x28 => "SystemPlugPlayBusInformation",
        0x29 => "SystemDockInformation",
        0x2A => "SystemPowerInformation",
        0x2B => "SystemProcessorSpeedInformation",
        0x2C => "SystemCurrentTimeZoneInformation",
        0x2D => "SystemLookasideInformation",
        // This pattern continues for all known System Information Classes
        0x2E => "SystemTimeSlipNotification",
        0x2F => "SystemSessionCreate",
        0x30 => "SystemSessionDetach",
        0x31 => "SystemSessionInformation",
        // Add additional mappings here up to 0xD5...
        0xD5 => "SystemSecureSpeculationControlInformation",
        _ => "Unknown Information Class",
    }
}

#[allow(dead_code)]
pub fn log_nt_create_file_params(regs: &GuestRegisters) {
    info!(
        "NtCreateFile called with parameters:\n\
         FileHandle: {:#018x}, DesiredAccess: {:#018x}, ObjectAttributes: {:#018x},\n\
         IoStatusBlock: {:#018x}, AllocationSize: {:#018x}, FileAttributes: {:#x},\n\
         ShareAccess: {:#x}, CreateDisposition: {:#x}, CreateOptions: {:#x},\n\
         EaBuffer: {:#018x}, EaLength: {:#x}",
        regs.rcx,        // FileHandle (typically an out parameter, pointer passed in RCX)
        regs.rdx,        // DesiredAccess (passed in RDX)
        regs.r8,         // ObjectAttributes (pointer in R8)
        regs.r9,         // IoStatusBlock (pointer in R9)
        regs.rsp + 0x28, // AllocationSize (pointer, next stack parameter)
        regs.rsp + 0x30, // FileAttributes
        regs.rsp + 0x38, // ShareAccess
        regs.rsp + 0x40, // CreateDisposition
        regs.rsp + 0x48, // CreateOptions
        regs.rsp + 0x50, // EaBuffer (pointer)
        regs.rsp + 0x58  // EaLength
    );
}

#[allow(dead_code)]
pub fn log_nt_open_process_params(regs: &GuestRegisters) {
    info!(
        "NtOpenProcess called with parameters:\n\
         ProcessHandle (out): {:#018x},\n\
         DesiredAccess: {:#018x},\n\
         ObjectAttributes: {:#018x},\n\
         ClientId (PID): {:#018x}", // Assuming ClientId is a pointer to a CLIENT_ID structure that contains PID
        regs.rcx, // ProcessHandle, typically a pointer to a HANDLE, passed back out to the caller
        regs.rdx, // DesiredAccess, specifies access rights
        regs.r8,  // ObjectAttributes, pointer to an OBJECT_ATTRIBUTES structure
        regs.r9   // ClientId, pointer to a CLIENT_ID structure (which typically includes a PID)
    );
}
