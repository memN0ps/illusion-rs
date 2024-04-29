//! This module provides utilities and structures related to VMX exit reasons,
//! VM instruction errors, and VM Exit Qualification errors. These enumerations are utilized to understand and
//! handle the various reasons for VM exits, specific VM instruction errors, and specific VM Exit Qualification errors.

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

/// Represents the exit qualification for EPT Violations.
///
/// This struct interprets the exit qualification for EPT Violations as described in
/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 28-7. Exit Qualification for EPT Violations (Contd.)
#[derive(Clone, Copy)]
pub struct EptViolationExitQualification {
    pub data_read: bool,
    pub data_write: bool,
    pub instruction_fetch: bool,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub user_mode_executable: bool,
    pub guest_linear_address_valid: bool,
    pub guest_physical_access: bool,
    pub supervisor_user_mode: bool,
    pub linear_address_read_write: bool,
    pub linear_address_executable: bool,
    pub nmi_unblocking_due_to_iret: bool,
    pub shadow_stack_access: bool,
    pub supervisor_shadow_stack_control: bool,
    pub caused_by_guest_paging_verification: bool,
    pub asynchronous_access: bool,
    // Reserved for future use.
}

impl EptViolationExitQualification {
    /// Constructs an `EptViolationExitQualification` from the raw 64-bit exit qualification value.
    pub fn from_exit_qualification(value: u64) -> Self {
        EptViolationExitQualification {
            data_read: value & (1 << 0) != 0,
            data_write: value & (1 << 1) != 0,
            instruction_fetch: value & (1 << 2) != 0,
            readable: value & (1 << 3) != 0,
            writable: value & (1 << 4) != 0,
            executable: value & (1 << 5) != 0,
            user_mode_executable: value & (1 << 6) != 0,
            guest_linear_address_valid: value & (1 << 7) != 0,
            guest_physical_access: value & (1 << 8) != 0,
            supervisor_user_mode: value & (1 << 9) != 0,
            linear_address_read_write: value & (1 << 10) != 0,
            linear_address_executable: value & (1 << 11) != 0,
            nmi_unblocking_due_to_iret: value & (1 << 12) != 0,
            shadow_stack_access: value & (1 << 13) != 0,
            supervisor_shadow_stack_control: value & (1 << 14) != 0,
            caused_by_guest_paging_verification: value & (1 << 15) != 0,
            asynchronous_access: value & (1 << 16) != 0,
        }
    }
}

impl core::fmt::Debug for EptViolationExitQualification {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EptViolationExitQualification")
            .field("Data Read", &self.data_read)
            .field("Data Write", &self.data_write)
            .field("Instruction Fetch", &self.instruction_fetch)
            .field(
                "Page Permissions",
                &format_args!("R:{} W:{} X:{}", self.readable, self.writable, self.executable),
            )
            .field("User Mode Executable", &self.user_mode_executable)
            .field("Guest Linear Address Valid", &self.guest_linear_address_valid)
            .field("Guest Physical Access", &self.guest_physical_access)
            .field("Supervisor/User Mode", &self.supervisor_user_mode)
            .field("Linear Address Read/Write", &self.linear_address_read_write)
            .field("Linear Address Executable", &self.linear_address_executable)
            .field("NMI Unblocking due to IRET", &self.nmi_unblocking_due_to_iret)
            .field("Shadow Stack Access", &self.shadow_stack_access)
            .field("Supervisor Shadow Stack Control", &self.supervisor_shadow_stack_control)
            .field("Caused by Guest Paging Verification", &self.caused_by_guest_paging_verification)
            .field("Asynchronous Access", &self.asynchronous_access)
            .finish()
    }
}

/// Represents the various types of exceptions and interrupts.
///
/// References:
/// * Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 6-1. Protected-Mode Exceptions and Interrupts
/// * Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 21-1. Real-Address Mode Exceptions and Interrupts
/// * https://wiki.osdev.org/Exceptions#:~:text=Exceptions
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExceptionInterrupt {
    /// Divide Error caused by DIV and IDIV instructions.
    DivisionError = 0,

    /// Debug exception for any code or data reference.
    Debug = 1,

    /// Non-maskable external interrupt.
    NonMaskableInterrupt = 2,

    /// Breakpoint triggered by the INT3 instruction.
    Breakpoint = 3,

    /// Overflow occurred from the INTO instruction.
    Overflow = 4,

    /// BOUND Range Exceeded caused by BOUND instruction.
    BoundRangeExceeded = 5,

    /// Invalid Opcode (Undefined Opcode) from UD instruction or reserved opcode.
    InvalidOpcode = 6,

    /// Device Not Available (No Math Coprocessor), triggered by floating-point or WAIT/FWAIT instruction.
    DeviceNotAvailable = 7,

    /// Double Fault, can occur from any instruction that can generate an exception, an NMI, or an INTR.
    DoubleFault = 8,

    /// CoProcessor Segment Overrun, reserved for floating-point instructions.
    CoprocessorSegmentOverrun = 9,

    /// Invalid TSS, caused by task switch or TSS access.
    InvalidTSS = 10,

    /// Segment Not Present, triggered by loading segment registers or accessing system segments.
    SegmentNotPresent = 11,

    /// Stack Segment Fault, caused by stack operations and SS register loads.
    StackSegmentFault = 12,

    /// General Protection Fault, can be caused by any memory reference and other protection checks.
    GeneralProtectionFault = 13,

    /// Page Fault, triggered by any memory reference.
    PageFault = 14,

    // Reserved = 15,
    /// Floating-Point Error (Math Fault), caused by floating-point or WAIT/FWAIT instruction.
    FloatingPointError = 16,

    /// Alignment Check, triggered by any data reference in memory.
    AlignmentCheck = 17,

    /// Machine Check, error codes and source are model dependent.
    MachineCheck = 18,

    /// SIMD Floating-Point Exception, caused by SIMD Floating-Point Instruction.
    SimdFloatingPointException = 19,

    /// Virtualization Exception, caused by EPT violations.
    VirtualizationException = 20,

    /// Control Protection Exception, can be generated by various instructions like RET, IRET when CET indirect branch tracking is enabled.
    ControlProtectionException = 21,

    // Reserved 22-31,
    /// Maskable Interrupts, external interrupt from INTR pin or INT n instruction.
    MaskableInterrupts = 32,
}

impl ExceptionInterrupt {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::DivisionError),
            1 => Some(Self::Debug),
            2 => Some(Self::NonMaskableInterrupt),
            3 => Some(Self::Breakpoint),
            4 => Some(Self::Overflow),
            5 => Some(Self::BoundRangeExceeded),
            6 => Some(Self::InvalidOpcode),
            7 => Some(Self::DeviceNotAvailable),
            8 => Some(Self::DoubleFault),
            9 => Some(Self::CoprocessorSegmentOverrun),
            10 => Some(Self::InvalidTSS),
            11 => Some(Self::SegmentNotPresent),
            12 => Some(Self::StackSegmentFault),
            13 => Some(Self::GeneralProtectionFault),
            14 => Some(Self::PageFault),
            16 => Some(Self::FloatingPointError),
            17 => Some(Self::AlignmentCheck),
            18 => Some(Self::MachineCheck),
            19 => Some(Self::SimdFloatingPointException),
            20 => Some(Self::VirtualizationException),
            21 => Some(Self::ControlProtectionException),
            32 => Some(Self::MaskableInterrupts),
            _ => None,
        }
    }
}

/// This enum maps to the interruption type field in the VM-Exit Interruption-Information Field.
/// * Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 6-1. Protected-Mode Exceptions and Interrupts
/// * Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 21-1. Real-Address Mode Exceptions and Interrupts
/// * https://wiki.osdev.org/Exceptions#:~:text=Exceptions
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InterruptionType {
    /// External interrupt.
    ExternalInterrupt = 0,
    /// Reserved value.
    Reserved = 1,
    /// Non-maskable interrupt (NMI).
    NonMaskableInterrupt = 2,
    /// Hardware exception, such as #PF.
    HardwareException = 3,
    /// Software interrupt using the INT n instruction.
    SoftwareInterrupt = 4,
    /// Privileged software exception using the INT1 instruction.
    PrivilegedSoftwareException = 5,
    /// Software exception using the INT3 or INTO instructions.
    SoftwareException = 6,
    /// Represents other types of events not covered by the above categories.
    OtherEvent = 7,
}

impl InterruptionType {
    /// Converts a u8 value representing interruption type bits into a corresponding `InterruptionType` enum variant.
    ///
    /// This function is typically used to interpret the interruption type field extracted from the VM-Exit Interruption-Information Field.
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::ExternalInterrupt),
            2 => Some(Self::NonMaskableInterrupt),
            3 => Some(Self::HardwareException),
            5 => Some(Self::PrivilegedSoftwareException),
            6 => Some(Self::SoftwareException),
            _ => None, // Return None if the bits do not correspond to a known interruption type.
        }
    }
}

/// Represents the VM-exit interruption information.
/// This struct is used to parse and store information from the VM-Exit Interruption-Information Field.
#[derive(Debug, Clone, Copy)]
pub struct VmExitInterruptionInformation {
    /// The vector number of the interrupt or exception.
    pub vector: u8,
    /// The type of interruption that caused the VM exit.
    pub interruption_type: InterruptionType,
    /// Indicates whether an error code is associated with the interruption.
    pub error_code_valid: bool,
    /// Indicates if NMI unblocking is due to an IRET instruction.
    pub nmi_unblocking_due_to_iret: bool,
    /// Indicates if the interruption information is valid.
    pub valid: bool,
}

impl VmExitInterruptionInformation {
    /// Constructs a `VmExitInterruptionInformation` from a 32-bit value.
    /// This method interprets the raw value from the VM-Exit Interruption-Information Field and extracts relevant information.
    pub fn from_u32(value: u32) -> Option<Self> {
        let vector = (value & 0xff) as u8; // Extract the vector (bits 7:0).
        let interruption_type_bits = ((value >> 8) & 0x7) as u8; // Extract the interruption type (bits 10:8).
        let interruption_type = InterruptionType::from_bits(interruption_type_bits)?;

        Some(VmExitInterruptionInformation {
            vector,
            interruption_type,
            error_code_valid: (value & (1 << 11)) != 0,           // Check if error code is valid (bit 11).
            nmi_unblocking_due_to_iret: (value & (1 << 12)) != 0, // Check for NMI unblocking due to IRET (bit 12).
            valid: (value & (1 << 31)) != 0,                      // Check if the interruption information is valid (bit 31).
        })
    }
}
