use crate::intel::capture::GuestRegisters;
use crate::intel::vmexit::ExitType;

pub fn handle_sipi_signal(_guest_registers: &mut GuestRegisters) -> ExitType {
    panic!("SIPI called, panicking!");

    //ExitType::IncrementRIP
}
