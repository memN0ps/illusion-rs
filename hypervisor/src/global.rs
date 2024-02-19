use crate::intel::capture::GuestRegisters;

pub struct GlobalState {
    pub guest_registers: GuestRegisters,
}

impl GlobalState {
    pub fn new(guest_registers: GuestRegisters) -> Self {
        Self { guest_registers }
    }
}
