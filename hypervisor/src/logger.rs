//! Provides a serial port logger implementation.
//!
//! This module implements logging over a serial port, enabling the output of log messages
//! to a serial console. This is particularly useful for debugging hypervisor and kernel-level
//! development where traditional logging mechanisms might not be available.
//!
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/serial_logger.rs
//!

use {
    crate::intel::support::{inb, outb},
    core::{fmt, fmt::Write},
    spin::Mutex,
};

/// The global serial port logger instance.
static SERIAL_LOGGER: SerialLogger = SerialLogger::new();

/// The default COM port for the serial logger (COM1).
static mut COM_PORT: u16 = 0x3f8;

/// Enum representing available serial ports.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialPort {
    /// COM1 serial port (0x3F8).
    COM1 = 0x3F8,
    /// COM2 serial port (0x2F8).
    COM2 = 0x2F8,
}

/// Initializes the serial port logger.
///
/// Sets up the logging framework to output through the serial port specified in the `Serial` struct.
/// This function configures the global logger to the `SerialLogger` and sets the logging level.
///
/// # Arguments
///
/// - `level`: The maximum log level filter. Messages with a level higher than this will not be logged.
pub fn init(port: SerialPort, level: log::LevelFilter) {
    unsafe { COM_PORT = port as u16 };
    log::set_logger(&SERIAL_LOGGER)
        .map(|()| log::set_max_level(level))
        .unwrap();
}

/// A logger that outputs messages to a serial port.
///
/// Encapsulates the functionality for logging messages over a serial port. It holds a mutex-protected
/// `Serial` instance to ensure that log messages are written atomically without being interleaved with
/// other output.
///
/// The logger can be used with the Rust `log` crate's macros (e.g., `info!`, `debug!`) to direct log output
/// to the serial port.
struct SerialLogger {
    /// Mutex to protect access to the Serial instance.
    port: Mutex<Serial>,
}

impl SerialLogger {
    /// Creates a new instance of `SerialLogger`.
    ///
    /// Initializes `SerialLogger` with a `Serial` instance protected by a `Mutex`.
    /// This ensures that access to the serial port is synchronized across different
    /// execution contexts, preventing data races and ensuring thread safety.
    ///
    /// # Returns
    ///
    /// Returns a `SerialLogger` instance with a mutex-protected `Serial` port ready for logging.
    const fn new() -> Self {
        Self {
            port: Mutex::new(Serial {}),
        }
    }

    /// Acquires a lock on the serial port for exclusive access.
    ///
    /// This method locks the mutex protecting the `Serial` instance, ensuring that
    /// the current context has exclusive access to the serial port for writing log messages.
    /// The lock is released when the returned `MutexGuard` is dropped at the end of its scope.
    ///
    /// # Returns
    ///
    /// Returns a `MutexGuard` for the `Serial` instance, providing exclusive access to the serial port.
    fn lock(&self) -> spin::MutexGuard<'_, Serial> {
        self.port.lock()
    }
}

impl log::Log for SerialLogger {
    /// Determines if a log message should be logged.
    ///
    /// # Arguments
    ///
    /// - `metadata`: Metadata for the log message being checked.
    ///
    /// # Returns
    ///
    /// Returns `true` if the message's level is less than or equal to `Level::Trace`, indicating
    /// it should be logged.
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    /// Logs a record.
    ///
    /// Writes the log message to the serial port if its level is enabled.
    ///
    /// # Arguments
    ///
    /// - `record`: The log record to be output.
    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            // Explicitly get the APIC ID (core number) before locking the serial port
            let vcpu_id = apic_id();

            // Ensure we lock the mutex before writing to the serial port
            let mut serial = self.lock();

            // Format and print the log message with APIC ID, log level, and log message
            let _ = writeln!(
                serial,
                "vcpu-{} {}: {}",
                vcpu_id,
                record.level(),
                record.args()
            );
        }
    }

    /// Flushes buffered log messages.
    ///
    /// Currently, this is a no-op as messages are written directly to the serial port without buffering.
    fn flush(&self) {}
}

/// Represents the serial port used for logging.
///
/// Provides low-level access to a serial port for writing log messages. This struct implements
/// the `Write` trait, allowing it to be used with Rust's formatting macros and functions.
struct Serial;

/// Writes a string slice to the serial port.
///
/// Outputs a string to the serial port byte by byte. It waits for the transmitter holding
/// register to be empty before sending each byte, ensuring that the entire message is
/// transmitted sequentially.
///
/// # Arguments
///
/// - `string`: The string slice to write to the serial port.
///
/// # Returns
///
/// Returns `Ok(())` if the string is successfully written, or an `Err` on failure.
impl Write for Serial {
    // Writes bytes `string` to the serial port.
    fn write_str(&mut self, string: &str) -> Result<(), fmt::Error> {
        const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0;
        const UART_OFFSET_LINE_STATUS: u16 = 5;

        for byte in string.bytes() {
            while (inb(unsafe { COM_PORT } + UART_OFFSET_LINE_STATUS) & 0x20) == 0 {}
            outb(
                unsafe { COM_PORT } + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER,
                byte,
            );
        }
        Ok(())
    }
}

/// Gets an APIC ID.
///
/// # Returns
///
/// Returns the APIC ID of the current processor.
fn apic_id() -> u32 {
    // See: (AMD) CPUID Fn0000_0001_EBX LocalApicId, LogicalProcessorCount, CLFlush
    // See: (Intel) Table 3-8. Information Returned by CPUID Instruction
    x86::cpuid::cpuid!(0x1).ebx >> 24
}
