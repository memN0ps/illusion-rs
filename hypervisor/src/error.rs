use {alloc::ffi::NulError, thiserror_no_std::Error};

#[derive(Error, Debug)]
pub enum HypervisorError {
    #[error("Intel CPU not found")]
    CPUUnsupported,

    #[error("VMX is not supported")]
    VMXUnsupported,

    #[error("EPT is not supported")]
    EPTUnsupported,

    #[error("MTRRs are not supported")]
    MTRRUnsupported,

    #[error("VMX locked off in BIOS")]
    VMXBIOSLock,

    #[error("Failed allocate memory via PhysicalAllocator")]
    MemoryAllocationFailed(#[from] core::alloc::AllocError),

    #[error("Failed to convert from virtual address to physical address")]
    VirtualToPhysicalAddressFailed,

    #[error("Failed to execute VMXON")]
    VMXONFailed,

    #[error("Failed to execute VMXOFF")]
    VMXOFFFailed,

    #[error("Failed to execute VMCLEAR")]
    VMCLEARFailed,

    #[error("Failed to execute VMPTRLD")]
    VMPTRLDFailed,

    #[error("Failed to execute VMREAD")]
    VMREADFailed,

    #[error("Failed to execute VMWRITE")]
    VMWRITEFailed,

    #[error("Failed to execute VMLAUNCH")]
    VMLAUNCHFailed,

    #[error("Failed to execute VMRESUME")]
    VMRESUMEFailed,

    #[error("Failed to switch processor")]
    ProcessorSwitchFailed,

    #[error("Failed to access VCPU table")]
    VcpuIsNone,

    #[error("Unknown VM exit basic reason")]
    UnknownVMExitReason,

    #[error("Unknown VM instruction error")]
    UnknownVMInstructionError,

    #[error("VM Fail Invalid")]
    VmFailInvalid,

    #[error("Unhandled VmExit")]
    UnhandledVmExit,

    #[error("KeRaiseIrqlToDpcLevel function pointer is null")]
    KeRaiseIrqlToDpcLevelNull,

    #[error("Invalid EPT PML4 base address")]
    InvalidEptPml4BaseAddress,

    #[error("Failed to resolve memory type for given physical address range")]
    MemoryTypeResolutionError,

    #[error("Invalid CR3 base address")]
    InvalidCr3BaseAddress,

    #[error("Failed to parse bytes of original function")]
    InvalidBytes,

    #[error("Couldn't find enough space for the jump shellcode")]
    NotEnoughBytes,

    #[error("Failed to find original instructions")]
    NoInstructions,

    #[error("Found rip-relative instruction which is not supported")]
    RelativeInstruction,

    #[error("Found unsupported instruction")]
    UnsupportedInstruction,

    #[error("VMX is not initialized")]
    VmxNotInitialized,

    #[error("Hook error")]
    HookError,

    #[error("Primary EPT not provided")]
    PrimaryEPTNotProvided,

    #[error("Invalid PML4 entry")]
    InvalidPml4Entry,

    #[error("Invalid PDPT entry")]
    InvalidPdptEntry,

    #[error("Invalid PD entry")]
    InvalidPdEntry,

    #[error("Invalid PT entry")]
    InvalidPtEntry,

    #[error("Invalid Permission Character")]
    InvalidPermissionCharacter,

    #[error("Unaligned address error")]
    UnalignedAddressError,

    #[error("Already split error")]
    AlreadySplitError,

    #[error("Out of memory")]
    OutOfMemory,

    #[error("Page already split")]
    PageAlreadySplit,

    #[error("Hook manager not provided")]
    HookManagerNotProvided,

    #[error("NtQuerySystemInformation failed")]
    NtQuerySystemInformationFailed,

    #[error("ExAllocatePoolFailed failed")]
    ExAllocatePoolFailed,

    #[error("Pattern not found")]
    PatternNotFound,

    #[error("SSDT not found")]
    SsdtNotFound,

    #[error("Failed create a C String")]
    FailedToCreateCString(#[from] NulError),

    #[error("Failed to get kernel base")]
    GetKernelBaseFailed,

    #[error("Failed to get kernel size")]
    FailedToGetKernelSize,

    #[error("Failed to get export hash")]
    FailedToGetExport,

    #[error("Failed to parse hexadecimal string")]
    HexParseError,

    #[error("VM instruction failed due to carry flag being set")]
    VMFailToLaunch,

    #[error("VM instruction failed due to zero flag being set")]
    VmInstructionError,

    #[error("Large page remap error")]
    LargePageRemapError,

    #[error("Failed to get image base address")]
    FailedToGetImageBaseAddress,

    #[error("Unknown VMCALL command")]
    UnknownVmcallCommand,

    #[error("Unknown guest agent command")]
    UnknownGuestAgentCommand,

    #[error("Out of hooks")]
    OutOfHooks,

    #[error("Failed to get current hook index")]
    FailedToGetCurrentHookIndex,

    #[error("Too many hooks")]
    TooManyHooks,

    #[error("Failed to get current hook")]
    HookNotFound,

    #[error("Failed to get current inline hook")]
    InlineHookNotFound,

    #[error("Old RFLAGS not set")]
    OldRflagsNotSet,

    #[error("MTF counter not set")]
    MtfCounterNotSet,

    #[error("Invalid pre-allocated page table index")]
    InvalidPreAllocPtIndex,

    #[error("Failed to allocate shadow pages for memory manager")]
    ShadowPageAllocationError,

    #[error("Failed to allocate page tables for memory manager")]
    PageTablesAllocationError,

    #[error("Shadow pages unavailable")]
    ShadowPagesUnavailable,

    #[error("Page tables unavailable")]
    PageTablesUnavailable,

    #[error("Shadow page not found")]
    ShadowPageNotFound,

    #[error("Page table not found")]
    PageTableNotFound,

    #[error("Page table already mapped")]
    PageTableAlreadyMapped,

    #[error("Shadow page already mapped")]
    ShadowPageAlreadyMapped,

    #[error("Kernel hook missing")]
    KernelHookMissing,

    #[error("Active mapping error")]
    ActiveMappingError,

    #[error("Large page table mapping error")]
    LargePtMappingError,

    #[error("Failed to get hook info")]
    HookInfoNotFound,

    #[error("EPT misconfiguration error")]
    EptMisconfiguration,
}
