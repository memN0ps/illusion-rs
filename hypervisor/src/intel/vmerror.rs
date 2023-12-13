//! This module provides utilities and structures related to VMX exit reasons
//! and VM instruction errors. These enumerations are utilized to understand and
//! handle the various reasons for VM exits and specific VM instruction errors.

/// Represents the basic VM exit reasons.
///
/// These are the reasons for which a VM might exit based on the VMCS exit reason field.
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmxBasicExitReason {
    ExceptionOrNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartupIpi = 4,
    IoSystemManagementInterrupt = 5,
    OtherSmi = 6,
    InterruptWindow = 7,
    NmiWindow = 8,
    TaskSwitch = 9,
    Cpuid = 10,
    Getsec = 11,
    Hlt = 12,
    Invd = 13,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Rsm = 17,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmxoff = 26,
    Vmxon = 27,
    ControlRegisterAccesses = 28,
    MovDr = 29,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMsrLoading = 34,
    Mwait = 36,
    MonitorTrapFlag = 37,
    Monitor = 39,
    Pause = 40,
    VmEntryFailureMachineCheckEvent = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    VirtualizedEoi = 45,
    AccessToGdtrOrIdtr = 46,
    AccessToLdtrOrTr = 47,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    VmxPreemptionTimerExpired = 52,
    Invvpid = 53,
    WbinvdOrWbnoinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    PageModificationLogFull = 62,
    Xsaves = 63,
    Xrstors = 64,
    Pconfig = 65,
    SppRelatedEvent = 66,
    Umwait = 67,
    Tpause = 68,
    Loadiwkey = 69,
    Enclv = 70,
    EnqcmdPasidTranslationFailure = 72,
    EnqcmdsPasidTranslationFailure = 73,
    BusLock = 74,
    InstructionTimeout = 75,
}

impl VmxBasicExitReason {
    /// Converts a 32-bit VM exit reason from the VMCS to the corresponding `VmxBasicExitReason` variant.
    ///
    /// Every VM exit writes a 32-bit exit reason to the VMCS. The lower 16 bits of this field form the basic exit reason.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9.1 VM Exit Reason
    pub fn from_u32(value: u32) -> Option<Self> {
        let basic_exit_reason = (value & 0xFFFF) as u16;
        match basic_exit_reason {
            0 => Some(Self::ExceptionOrNmi),
            1 => Some(Self::ExternalInterrupt),
            2 => Some(Self::TripleFault),
            3 => Some(Self::InitSignal),
            4 => Some(Self::StartupIpi),
            5 => Some(Self::IoSystemManagementInterrupt),
            6 => Some(Self::OtherSmi),
            7 => Some(Self::InterruptWindow),
            8 => Some(Self::NmiWindow),
            9 => Some(Self::TaskSwitch),
            10 => Some(Self::Cpuid),
            11 => Some(Self::Getsec),
            12 => Some(Self::Hlt),
            13 => Some(Self::Invd),
            14 => Some(Self::Invlpg),
            15 => Some(Self::Rdpmc),
            16 => Some(Self::Rdtsc),
            17 => Some(Self::Rsm),
            18 => Some(Self::Vmcall),
            19 => Some(Self::Vmclear),
            20 => Some(Self::Vmlaunch),
            21 => Some(Self::Vmptrld),
            22 => Some(Self::Vmptrst),
            23 => Some(Self::Vmread),
            24 => Some(Self::Vmresume),
            25 => Some(Self::Vmwrite),
            26 => Some(Self::Vmxoff),
            27 => Some(Self::Vmxon),
            28 => Some(Self::ControlRegisterAccesses),
            29 => Some(Self::MovDr),
            30 => Some(Self::IoInstruction),
            31 => Some(Self::Rdmsr),
            32 => Some(Self::Wrmsr),
            33 => Some(Self::VmEntryFailureInvalidGuestState),
            34 => Some(Self::VmEntryFailureMsrLoading),
            36 => Some(Self::Mwait),
            37 => Some(Self::MonitorTrapFlag),
            39 => Some(Self::Monitor),
            40 => Some(Self::Pause),
            41 => Some(Self::VmEntryFailureMachineCheckEvent),
            43 => Some(Self::TprBelowThreshold),
            44 => Some(Self::ApicAccess),
            45 => Some(Self::VirtualizedEoi),
            46 => Some(Self::AccessToGdtrOrIdtr),
            47 => Some(Self::AccessToLdtrOrTr),
            48 => Some(Self::EptViolation),
            49 => Some(Self::EptMisconfiguration),
            50 => Some(Self::Invept),
            51 => Some(Self::Rdtscp),
            52 => Some(Self::VmxPreemptionTimerExpired),
            53 => Some(Self::Invvpid),
            54 => Some(Self::WbinvdOrWbnoinvd),
            55 => Some(Self::Xsetbv),
            56 => Some(Self::ApicWrite),
            57 => Some(Self::Rdrand),
            58 => Some(Self::Invpcid),
            59 => Some(Self::Vmfunc),
            60 => Some(Self::Encls),
            61 => Some(Self::Rdseed),
            62 => Some(Self::PageModificationLogFull),
            63 => Some(Self::Xsaves),
            64 => Some(Self::Xrstors),
            65 => Some(Self::Pconfig),
            66 => Some(Self::SppRelatedEvent),
            67 => Some(Self::Umwait),
            68 => Some(Self::Tpause),
            69 => Some(Self::Loadiwkey),
            70 => Some(Self::Enclv),
            72 => Some(Self::EnqcmdPasidTranslationFailure),
            73 => Some(Self::EnqcmdsPasidTranslationFailure),
            74 => Some(Self::BusLock),
            75 => Some(Self::InstructionTimeout),
            _ => None,
        }
    }
}

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons
impl core::fmt::Display for VmxBasicExitReason {
    /// Provides a descriptive string for a `VmxBasicExitReason` variant.
    ///
    /// This implementation aids in debugging by providing a human-readable description of each exit reason.
    #[rustfmt::skip]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let description = match *self {
            VmxBasicExitReason::ExceptionOrNmi => "Exception or non-maskable interrupt (NMI)",
            VmxBasicExitReason::ExternalInterrupt => "External interrupt",
            VmxBasicExitReason::TripleFault => "Triple fault",
            VmxBasicExitReason::InitSignal => "INIT signal",
            VmxBasicExitReason::StartupIpi => "Start-up IPI (SIPI)",
            VmxBasicExitReason::IoSystemManagementInterrupt => "I/O system-management interrupt (SMI)",
            VmxBasicExitReason::OtherSmi => "Other SMI",
            VmxBasicExitReason::InterruptWindow => "Interrupt window",
            VmxBasicExitReason::NmiWindow => "NMI window",
            VmxBasicExitReason::TaskSwitch => "Task switch",
            VmxBasicExitReason::Cpuid => "Guest software attempted to execute CPUID",
            VmxBasicExitReason::Getsec => "Guest software attempted to execute GETSEC",
            VmxBasicExitReason::Hlt => "Guest software attempted to execute HLT",
            VmxBasicExitReason::Invd => "Guest software attempted to execute INVD",
            VmxBasicExitReason::Invlpg => "Guest software attempted to execute INVLPG",
            VmxBasicExitReason::Rdpmc => "Guest software attempted to execute RDPMC",
            VmxBasicExitReason::Rdtsc => "Guest software attempted to execute RDTSC",
            VmxBasicExitReason::Rsm => "Guest software attempted to execute RSM in SMM",
            VmxBasicExitReason::Vmcall => "VMCALL was executed",
            VmxBasicExitReason::Vmclear => "Guest software attempted to execute VMCLEAR",
            VmxBasicExitReason::Vmlaunch => "Guest software attempted to execute VMLAUNCH",
            VmxBasicExitReason::Vmptrld => "Guest software attempted to execute VMPTRLD",
            VmxBasicExitReason::Vmptrst => "Guest software attempted to execute VMPTRST",
            VmxBasicExitReason::Vmread => "Guest software attempted to execute VMREAD",
            VmxBasicExitReason::Vmresume => "Guest software attempted to execute VMRESUME",
            VmxBasicExitReason::Vmwrite => "Guest software attempted to execute VMWRITE",
            VmxBasicExitReason::Vmxoff => "Guest software attempted to execute VMXOFF",
            VmxBasicExitReason::Vmxon => "Guest software attempted to execute VMXON",
            VmxBasicExitReason::ControlRegisterAccesses => "Control-register accesses",
            VmxBasicExitReason::MovDr => "Guest software attempted a MOV to or from a debug register",
            VmxBasicExitReason::IoInstruction => "Guest software attempted to execute an I/O instruction",
            VmxBasicExitReason::Rdmsr => "Guest software attempted to execute RDMSR",
            VmxBasicExitReason::Wrmsr => "Guest software attempted to execute WRMSR",
            VmxBasicExitReason::VmEntryFailureInvalidGuestState => "VM-entry failure due to invalid guest state",
            VmxBasicExitReason::VmEntryFailureMsrLoading => "VM-entry failure due to MSR loading",
            VmxBasicExitReason::Mwait => "Guest software attempted to execute MWAIT",
            VmxBasicExitReason::MonitorTrapFlag => "Monitor trap flag",
            VmxBasicExitReason::Monitor => "Guest software attempted to execute MONITOR",
            VmxBasicExitReason::Pause => "Either guest software attempted to execute PAUSE or the PAUSE-loop exiting VM-execution control was 1",
            VmxBasicExitReason::VmEntryFailureMachineCheckEvent => "VM-entry failure due to machine-check event",
            VmxBasicExitReason::TprBelowThreshold => "TPR below threshold",
            VmxBasicExitReason::ApicAccess => "APIC access",
            VmxBasicExitReason::VirtualizedEoi => "Virtualized EOI",
            VmxBasicExitReason::AccessToGdtrOrIdtr => "Access to GDTR or IDTR",
            VmxBasicExitReason::AccessToLdtrOrTr => "Access to LDTR or TR",
            VmxBasicExitReason::EptViolation => "EPT violation",
            VmxBasicExitReason::EptMisconfiguration => "EPT misconfiguration",
            VmxBasicExitReason::Invept => "Guest software attempted to execute INVEPT",
            VmxBasicExitReason::Rdtscp => "Guest software attempted to execute RDTSCP",
            VmxBasicExitReason::VmxPreemptionTimerExpired => "VMX-preemption timer expired",
            VmxBasicExitReason::Invvpid => "Guest software attempted to execute INVVPID",
            VmxBasicExitReason::WbinvdOrWbnoinvd => "Guest software attempted to execute WBINVD or WBNOINVD",
            VmxBasicExitReason::Xsetbv => "Guest software attempted to execute XSETBV",
            VmxBasicExitReason::ApicWrite => "APIC write",
            VmxBasicExitReason::Rdrand => "Guest software attempted to execute RDRAND",
            VmxBasicExitReason::Invpcid => "Guest software attempted to execute INVPCID",
            VmxBasicExitReason::Vmfunc => "Guest software invoked a VM function with the VMFUNC instruction",
            VmxBasicExitReason::Encls => "Guest software attempted to execute ENCLS",
            VmxBasicExitReason::Rdseed => "Guest software attempted to execute RDSEED",
            VmxBasicExitReason::PageModificationLogFull => "Page-modification log full",
            VmxBasicExitReason::Xsaves => "Guest software attempted to execute XSAVES",
            VmxBasicExitReason::Xrstors => "Guest software attempted to execute XRSTORS",
            VmxBasicExitReason::Pconfig => "Guest software attempted to execute PCONFIG",
            VmxBasicExitReason::SppRelatedEvent => "SPP-related event",
            VmxBasicExitReason::Umwait => "Guest software attempted to execute UMWAIT",
            VmxBasicExitReason::Tpause => "Guest software attempted to execute TPAUSE",
            VmxBasicExitReason::Loadiwkey => "Guest software attempted to execute LOADIWKEY",
            VmxBasicExitReason::Enclv => "Guest software attempted to execute ENCLV",
            VmxBasicExitReason::EnqcmdPasidTranslationFailure => "ENQCMD PASID translation failure",
            VmxBasicExitReason::EnqcmdsPasidTranslationFailure => "ENQCMDS PASID translation failure",
            VmxBasicExitReason::BusLock => "Bus lock",
            VmxBasicExitReason::InstructionTimeout => "Instruction timeout",
        };

        // Write both the discriminant (as a number) and the description to the formatter.
        write!(f, "{}: {}", *self as u16, description)
    }
}

/// Represents the VM instruction error numbers.
///
/// These error numbers correspond to specific errors that can occur when executing VMX instructions.
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 31.4 VM INSTRUCTION ERROR NUMBERS
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 31-1. VM-Instruction Error Numbers
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmInstructionError {
    VmcallInRoot = 1,
    VmclearInvalidAddress = 2,
    VmclearWithVmxonPointer = 3,
    VmlaunchNonClearVmcs = 4,
    VmresumeNonLaunchedVmcs = 5,
    VmresumeAfterVmxoff = 6,
    VmEntryInvalidControlFields = 7,
    VmEntryInvalidHostState = 8,
    VmptrldInvalidAddress = 9,
    VmptrldWithVmxonPointer = 10,
    VmptrldIncorrectVmcsRevision = 11,
    VmreadVmwriteUnsupportedVmcsComponent = 12,
    VmwriteReadonlyVmcsComponent = 13,
    VmxonInRoot = 15,
    VmEntryInvalidExecutiveVmcsPointer = 16,
    VmEntryNonLaunchedExecutiveVmcs = 17,
    VmEntryExecutiveVmcsPointerNotVmxonPointer = 18,
    VmcallNonClearVmcs = 19,
    VmcallInvalidVmExitControlFields = 20,
    VmcallIncorrectMsegRevision = 22,
    VmxoffUnderDualMonitorTreatment = 23,
    VmcallInvalidSmmMonitorFeatures = 24,
    VmEntryInvalidVmExecutionControlFieldsExecutiveVmcs = 25,
    VmEntryEventsBlockedByMovSs = 26,
    InvalidOperandToInveptInvvpid = 28,
}

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 31.4 VM INSTRUCTION ERROR NUMBERS
/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 31-1. VM-Instruction Error Numbers
impl VmInstructionError {
    /// Converts a u32 value to the corresponding `VmInstructionError` variant.
    ///
    /// This method helps in interpreting the error numbers provided by VMX instructions.
    pub fn from_u32(value: u32) -> Option<Self> {
        use VmInstructionError::*;
        match value {
            1 => Some(VmcallInRoot),
            2 => Some(VmclearInvalidAddress),
            3 => Some(VmclearWithVmxonPointer),
            4 => Some(VmlaunchNonClearVmcs),
            5 => Some(VmresumeNonLaunchedVmcs),
            6 => Some(VmresumeAfterVmxoff),
            7 => Some(VmEntryInvalidControlFields),
            8 => Some(VmEntryInvalidHostState),
            9 => Some(VmptrldInvalidAddress),
            10 => Some(VmptrldWithVmxonPointer),
            11 => Some(VmptrldIncorrectVmcsRevision),
            12 => Some(VmreadVmwriteUnsupportedVmcsComponent),
            13 => Some(VmwriteReadonlyVmcsComponent),
            15 => Some(VmxonInRoot),
            16 => Some(VmEntryInvalidExecutiveVmcsPointer),
            17 => Some(VmEntryNonLaunchedExecutiveVmcs),
            18 => Some(VmEntryExecutiveVmcsPointerNotVmxonPointer),
            19 => Some(VmcallNonClearVmcs),
            20 => Some(VmcallInvalidVmExitControlFields),
            22 => Some(VmcallIncorrectMsegRevision),
            23 => Some(VmxoffUnderDualMonitorTreatment),
            24 => Some(VmcallInvalidSmmMonitorFeatures),
            25 => Some(VmEntryInvalidVmExecutionControlFieldsExecutiveVmcs),
            26 => Some(VmEntryEventsBlockedByMovSs),
            28 => Some(InvalidOperandToInveptInvvpid),
            _ => None,
        }
    }
}

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 31.4 VM INSTRUCTION ERROR NUMBERS
/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 31-1. VM-Instruction Error Numbers
impl core::fmt::Display for VmInstructionError {
    /// Provides a descriptive string for a `VmInstructionError` variant.
    ///
    /// This implementation aids in debugging by providing a human-readable description of each instruction error.
    #[rustfmt::skip]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use VmInstructionError::*;
        let description = match *self {
            VmcallInRoot => "1: VMCALL executed in VMX root operation",
            VmclearInvalidAddress => "2: VMCLEAR with invalid physical address",
            VmclearWithVmxonPointer => "3: VMCLEAR with VMXON pointer",
            VmlaunchNonClearVmcs => "4: VMLAUNCH with non-clear VMCS",
            VmresumeNonLaunchedVmcs => "5: VMRESUME with non-launched VMCS",
            VmresumeAfterVmxoff => "6: VMRESUME after VMXOFF",
            VmEntryInvalidControlFields => "7: VM entry with invalid control field(s)",
            VmEntryInvalidHostState => "8: VM entry with invalid host-state field(s)",
            VmptrldInvalidAddress => "9: VMPTRLD with invalid physical address",
            VmptrldWithVmxonPointer => "10: VMPTRLD with VMXON pointer",
            VmptrldIncorrectVmcsRevision => "11: VMPTRLD with incorrect VMCS revision identifier",
            VmreadVmwriteUnsupportedVmcsComponent => "12: VMREAD/VMWRITE from/to unsupported VMCS component",
            VmwriteReadonlyVmcsComponent => "13: VMWRITE to read-only VMCS component",
            VmxonInRoot => "15: VMXON executed in VMX root operation",
            VmEntryInvalidExecutiveVmcsPointer => "16: VM entry with invalid executive-VMCS pointer",
            VmEntryNonLaunchedExecutiveVmcs => "17: VM entry with non-launched executive VMCS",
            VmEntryExecutiveVmcsPointerNotVmxonPointer => "18: VM entry with executive-VMCS pointer not VMXON pointer",
            VmcallNonClearVmcs => "19: VMCALL with non-clear VMCS",
            VmcallInvalidVmExitControlFields => "20: VMCALL with invalid VM-exit control fields",
            VmcallIncorrectMsegRevision => "22: VMCALL with incorrect MSEG revision identifier",
            VmxoffUnderDualMonitorTreatment => "23: VMXOFF under dual-monitor treatment of SMIs and SMM",
            VmcallInvalidSmmMonitorFeatures => "24: VMCALL with invalid SMM-monitor features",
            VmEntryInvalidVmExecutionControlFieldsExecutiveVmcs => "25: VM entry with invalid VM-execution control fields in executive VMCS",
            VmEntryEventsBlockedByMovSs => "26: VM entry with events blocked by MOV SS.",
            InvalidOperandToInveptInvvpid => "28: Invalid operand to INVEPT/INVVPID.",
        };
        write!(f, "{}", description)
    }
}
