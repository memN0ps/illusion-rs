pub mod commands;
pub mod cpuid;
pub mod ept_misconfiguration;
pub mod ept_violation;
pub mod exception;
pub mod halt;
pub mod init;
pub mod invd;
pub mod invept;
pub mod invvpid;
pub mod msr;
pub mod mtf;
pub mod rdtsc;
pub mod sipi;
pub mod vmcall;
pub mod xsetbv;

/// Represents the type of VM exit.
#[derive(PartialOrd, PartialEq)]
pub enum ExitType {
    ExitHypervisor,
    IncrementRIP,
    Continue,
}
