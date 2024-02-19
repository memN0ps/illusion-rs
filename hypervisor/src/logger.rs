//! The module containing the serial port logger implementation.

use {
    crate::intel::support::{inb, outb},
    core::{fmt, fmt::Write},
    spin::Mutex,
};

/// Initializes the logger instance.
pub fn init(level: log::LevelFilter) {
    log::set_logger(&SERIAL_LOGGER)
        .map(|()| log::set_max_level(level))
        .unwrap();
}

struct SerialLogger {
    port: Mutex<Serial>,
}
impl SerialLogger {
    const fn new() -> Self {
        Self {
            port: Mutex::new(Serial {}),
        }
    }

    fn lock(&self) -> spin::MutexGuard<'_, Serial> {
        self.port.lock()
    }
}
impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let _ = writeln!(self.lock(), "{}: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

struct Serial;

impl Write for Serial {
    // Writes bytes `string` to the serial port.
    fn write_str(&mut self, string: &str) -> Result<(), fmt::Error> {
        //const UART_COM1: u16 = 0x3f8;
        const UART_COM2: u16 = 0x2f8;
        const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0;
        const UART_OFFSET_LINE_STATUS: u16 = 5;

        for byte in string.bytes() {
            while (inb(UART_COM2 + UART_OFFSET_LINE_STATUS) & 0x20) == 0 {}
            outb(UART_COM2 + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER, byte);
        }
        Ok(())
    }
}

static SERIAL_LOGGER: SerialLogger = SerialLogger::new();
