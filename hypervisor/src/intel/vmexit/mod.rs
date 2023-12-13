//! A module providing utilities and structures for handling VM exits.
//!
//! This module focuses on the reasons for VM exits, VM instruction errors, and the associated handlers for each exit type.
//! The handlers interpret and respond to different VM exit reasons, ensuring the safe and correct execution of the virtual machine.

use {
    super::{support::vmwrite, vmerror::VmxBasicExitReason},
    crate::{
        error::HypervisorError,
        intel::{
            support::vmread,
            vmexit::{
                cpuid::handle_cpuid,
                ept::{handle_ept_misconfiguration, handle_ept_violation},
                invd::handle_invd,
                msr::{handle_msr_access, MsrAccessType},
                rdtsc::handle_rdtsc,
                xsetbv::handle_xsetbv,
            },
        },
        utils::capture::GuestRegisters,
    },
    x86::vmx::vmcs::{guest, ro},
};

pub mod cpuid;
pub mod ept;
pub mod invd;
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

/// Represents a VM exit, which can be caused by various reasons.
///
/// A VM exit transfers control from the guest to the host (hypervisor).
/// The `VmExit` structure provides methods to handle various VM exit reasons and ensures the correct and safe continuation of the guest's execution.
pub struct VmExit;

impl VmExit {
    pub fn new() -> Self {
        Self
    }

    /// Handles the VM-exit.
    ///
    /// This function interprets the VM exit reason and invokes the appropriate handler based on the exit type.
    ///
    /// # Arguments
    ///
    /// * `registers` - A mutable reference to the guest's current register state.
    ///
    /// # Returns
    ///
    /// A result containing the VM exit reason if the handling was successful or an error if the VM exit reason is unknown or unsupported.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS
    /// - APPENDIX C VMX BASIC EXIT REASONS
    /// - Table C-1. Basic Exit Reasons
    pub fn handle_vmexit(
        &self,
        guest_registers: &mut GuestRegisters,
    ) -> Result<(), HypervisorError> {
        // Upon VM-exit, transfer the guest register values from VMCS to `self.registers` to ensure it reflects the latest and complete state.
        guest_registers.rip = vmread(guest::RIP);
        guest_registers.rsp = vmread(guest::RSP);
        guest_registers.rflags = vmread(guest::RFLAGS);

        log::info!("Guest RIP: {:#x}", guest_registers.rip);
        log::info!("Guest RSP: {:#x}", guest_registers.rsp);
        log::info!("Guest RFLAGS: {:#x}", guest_registers.rflags);

        let exit_reason = vmread(ro::EXIT_REASON) as u32;

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            log::info!("Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };
        log::info!("Basic Exit Reason: {}", basic_exit_reason);

        log::info!(
            "Guest registers before handling vmexit: {:#x?}",
            guest_registers
        );

        // Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.2 Instructions That Cause VM Exits Unconditionally:
        // - The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC, INVD, and XSETBV.
        // - This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //
        // 26.1.3 Instructions That Cause VM Exits Conditionally: Certain instructions cause VM exits in VMX non-root operation depending on the setting of the VM-execution controls.
        let exit_type = match basic_exit_reason {
            VmxBasicExitReason::Cpuid => handle_cpuid(guest_registers),
            VmxBasicExitReason::Rdmsr => handle_msr_access(guest_registers, MsrAccessType::Read),
            VmxBasicExitReason::Wrmsr => handle_msr_access(guest_registers, MsrAccessType::Write),
            VmxBasicExitReason::Invd => handle_invd(guest_registers),
            VmxBasicExitReason::Rdtsc => handle_rdtsc(guest_registers),
            VmxBasicExitReason::EptViolation => handle_ept_violation(guest_registers),
            VmxBasicExitReason::EptMisconfiguration => handle_ept_misconfiguration(),
            VmxBasicExitReason::Xsetbv => handle_xsetbv(guest_registers),
            _ => return Err(HypervisorError::UnhandledVmExit),
        };

        if exit_type == ExitType::IncrementRIP {
            self.advance_guest_rip(guest_registers);
        }

        log::info!(
            "Guest registers after handling vmexit: {:#x?}",
            guest_registers
        );

        log::info!("VMEXIT handled successfully.");

        return Ok(());
    }

    /// Advances the guest's instruction pointer (RIP) after a VM exit.
    ///
    /// When a VM exit occurs, the guest's execution is interrupted, and control is transferred
    /// to the hypervisor. To ensure that the guest does not re-execute the instruction that
    /// caused the VM exit, the hypervisor needs to advance the guest's RIP to the next instruction.
    #[rustfmt::skip]
    fn advance_guest_rip(&self, guest_registers: &mut GuestRegisters) {
        log::info!("Advancing guest RIP...");
        let len = vmread(ro::VMEXIT_INSTRUCTION_LEN);
        guest_registers.rip += len;
        vmwrite(guest::RIP, guest_registers.rip);
        log::info!("Guest RIP advanced to: {:#x}", vmread(guest::RIP));
    }
}
