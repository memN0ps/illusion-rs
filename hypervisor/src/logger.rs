//! The module containing the UART (serial port) logger implementation.
// Inspired by:
// https://github.com/iankronquist/rustyvisor/blob/83b53ac104d85073858ba83326a28a6e08d1af12/pcuart/src/lib.rs
// Credits: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/logger.rs

use {
    crate::intel::support::{inb, outb},
    core::{fmt, fmt::Write},
    spin::Mutex,
};

/// Initializes the logger instance.
pub fn init_uart_logger(level: log::LevelFilter) -> Result<(), log::SetLoggerError> {
    log::set_logger(&UART_LOGGER).map(|()| log::set_max_level(level))
}

struct UartLogger {
    port: Mutex<Uart>,
}
impl UartLogger {
    const fn new(port: UartComPort) -> Self {
        Self {
            port: Mutex::new(Uart::new(port)),
        }
    }

    fn lock(&self) -> spin::MutexGuard<'_, Uart> {
        self.port.lock()
    }
}
impl log::Log for UartLogger {
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

#[derive(Default)]
struct Uart {
    io_port_base: u16,
}
impl Uart {
    const fn new(port: UartComPort) -> Self {
        Self {
            io_port_base: port as u16,
        }
    }
}
impl Write for Uart {
    // Writes bytes `string` to the serial port.
    fn write_str(&mut self, string: &str) -> Result<(), fmt::Error> {
        const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0;
        const UART_OFFSET_LINE_STATUS: u16 = 5;

        for byte in string.bytes() {
            while (inb(self.io_port_base + UART_OFFSET_LINE_STATUS) & 0x20) == 0 {}
            outb(
                self.io_port_base + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER,
                byte,
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[repr(u16)]
enum UartComPort {
    Com1 = 0x3f8,
}

static UART_LOGGER: UartLogger = UartLogger::new(UartComPort::Com1);
