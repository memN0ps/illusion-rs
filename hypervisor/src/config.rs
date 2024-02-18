//! The module containing various constants that may be modified by developers.

#![allow(dead_code)]

use crate::logger::{UartComPort, UartLogger};

/// The logging level.
pub const LOGGING_LEVEL: log::LevelFilter = log::LevelFilter::Trace;

/// Once in how many iterations stats should be sent to the serial output.
/// Ignored when [`LOGGING_LEVEL`] is `Trace`.
pub const SERIAL_OUTPUT_INTERVAL: u64 = 500;

/// Once in how many iterations stats should be displayed on the console.
/// Ignored when `stdout_stats_report` is disabled.
pub const CONSOLE_OUTPUT_INTERVAL: u64 = 1000;

/// How long a single fuzzing iteration can spend within the guest-mode, in TSC.
/// If the more than this is spent, a timer fires and aborts the VM.
pub const GUEST_EXEC_TIMEOUT_IN_TSC: u64 = 200_000_000;

/// The number of fuzzing iterations to be done for single input. The lower, the
/// more frequently new files are selected, and it is slightly costly. Ignored
/// when `random_byte_modification` is disabled.
pub const MAX_ITERATION_COUNT_PER_FILE: u64 = 10_000;

/// The COM port to be used for UART logging.
pub static UART_LOGGER: UartLogger = UartLogger::new(UartComPort::Com2);
