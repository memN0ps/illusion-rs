//! This module provides utility functions for processor-related operations.

use wdk_sys::NTSTATUS;
use {
    core::mem::MaybeUninit,
    wdk_sys::{
        ntddk::{
            KeGetCurrentProcessorNumberEx, KeGetProcessorNumberFromIndex,
            KeQueryActiveProcessorCountEx, KeRevertToUserGroupAffinityThread,
            KeSetSystemGroupAffinityThread,
        },
        ALL_PROCESSOR_GROUPS, GROUP_AFFINITY, NT_SUCCESS, PROCESSOR_NUMBER,
    },
};

#[link(name = "ntoskrnl")]
extern "system" {
    ///undocumented
    fn ZwYieldExecution() -> NTSTATUS;
}

/// Atomic bitset used to track which processors have been virtualized.
static VIRTUALIZED_BITSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Determines if the current processor is already virtualized.
///
/// # Returns
///
/// `true` if the processor is virtualized, otherwise `false`.
pub fn is_virtualized() -> bool {
    let bit = 1 << current_processor_index();

    VIRTUALIZED_BITSET.load(core::sync::atomic::Ordering::Relaxed) & bit != 0
}

/// Marks the current processor as virtualized.
pub fn set_virtualized() {
    let bit = 1 << current_processor_index();

    VIRTUALIZED_BITSET.fetch_or(bit, core::sync::atomic::Ordering::Relaxed);
}

/// Returns the number of active logical processors in a specified group in a multiprocessor system or in the entire system.
pub fn processor_count() -> u32 {
    unsafe { KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS as _) }
}

/// Gets the processor number of the logical processor that the caller is running on.
pub fn current_processor_index() -> u32 {
    unsafe { KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) }
}

/// Converts a systemwide processor index to a group number and a group-relative processor number.
///
/// # Arguments
///
/// * `index` - The index of the processor to retrieve the processor number for.
///
/// # Returns
///
/// An `Option` containing the `PROCESSOR_NUMBER` if successful, or `None` if not.
fn processor_number_from_index(index: u32) -> Option<PROCESSOR_NUMBER> {
    let mut processor_number: MaybeUninit<PROCESSOR_NUMBER> = MaybeUninit::uninit();
    let status = unsafe { KeGetProcessorNumberFromIndex(index, processor_number.as_mut_ptr()) };

    if NT_SUCCESS(status) {
        Some(unsafe { processor_number.assume_init() })
    } else {
        None
    }
}

/// Struct responsible for switching execution to a specific processor until it's dropped.
pub struct ProcessorExecutor {
    old_affinity: MaybeUninit<GROUP_AFFINITY>,
}

impl ProcessorExecutor {
    /// Switches the execution context to a specific processor.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the processor to switch to.
    ///
    /// # Returns
    ///
    /// An `Option` containing the `ProcessorExecutor` if the switch was successful, or `None` if not.
    pub fn switch_to_processor(i: u32) -> Option<Self> {
        if i > processor_count() {
            log::info!("Invalid processor index: {}", i);
            return None;
        }

        let processor_number = processor_number_from_index(i)?;

        let mut old_affinity: MaybeUninit<GROUP_AFFINITY> = MaybeUninit::uninit();
        let mut affinity: GROUP_AFFINITY = unsafe { core::mem::zeroed() };

        affinity.Group = processor_number.Group;
        affinity.Mask = 1 << processor_number.Number;
        affinity.Reserved[0] = 0;
        affinity.Reserved[1] = 0;
        affinity.Reserved[2] = 0;

        log::info!("Switching execution to processor {}", i);
        unsafe { KeSetSystemGroupAffinityThread(&mut affinity, old_affinity.as_mut_ptr()) };

        log::info!("Yielding execution");
        if !NT_SUCCESS(unsafe { ZwYieldExecution() }) {
            return None;
        }

        Some(Self { old_affinity })
    }
}

impl Drop for ProcessorExecutor {
    /// Restores the group affinity of the calling thread to its original value when the `ProcessorExecutor` is dropped.
    fn drop(&mut self) {
        log::info!("Switching execution back to previous processor");
        unsafe {
            KeRevertToUserGroupAffinityThread(self.old_affinity.as_mut_ptr());
        }
    }
}
