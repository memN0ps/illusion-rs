use alloc::boxed::Box;
use crate::intel::capture::GuestRegisters;
use crate::intel::ept::paging::Ept;
use crate::intel::paging::PageTables;
use crate::intel::vmcs::Vmcs;

pub struct Vm {
    //vmcs: Box<Vmcs>,

    pub host_paging_structures: Box<PageTables>,

    pub ept: Box<Ept>,

    /// The guest's general-purpose registers state.
    pub guest_registers: GuestRegisters,
}

impl Vm {
    pub fn new() -> Self {
        let mut vmcs = Box::<Vmcs>::default();

        let mut host_paging = Box::<PageTables>::new_zeroed();

        host_paging.build_identity();
    }
}