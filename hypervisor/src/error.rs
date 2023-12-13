use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum HypervisorError {
    #[error("Intel CPU not found")]
    CPUUnsupported,

    #[error("VMX is not supported")]
    VMXUnsupported,

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
}
