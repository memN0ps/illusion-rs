pub mod cpuid;
pub mod ept;
pub mod exception;
pub mod invd;
pub mod invept;
pub mod invvpid;
pub mod msr;
pub mod rdtsc;
pub mod xsetbv;

/// Represents the type of VM exit.
#[derive(PartialOrd, PartialEq)]
pub enum ExitType {
    ExitHypervisor,
    IncrementRIP,
    Continue,
}
