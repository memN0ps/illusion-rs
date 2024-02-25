use {
    crate::intel::{
        capture::GuestRegisters,
        support::{vmread, vmwrite},
        vmexit::ExitType,
    },
    x86::vmx::vmcs,
};

pub fn handle_sipi_signal(_guest_registers: &mut GuestRegisters) -> ExitType {
    //
    // Then, emulate effects of SIPI by making further changes.
    //
    // "For a start-up IPI (SIPI), the exit qualification contains the SIPI
    //  vector information in bits 7:0. Bits 63:8 of the exit qualification are
    //  cleared to 0."
    // See: 27.2.1 Basic VM-Exit Information
    //
    let vector = vmread(vmcs::ro::EXIT_QUALIFICATION);

    //
    // "At the end of the boot-strap procedure, the BSP sets ... broadcasts a
    //  SIPI message to all the APs in the system. Here, the SIPI message contains
    //  a vector to the BIOS AP initialization code (at 000VV000H, where VV is the
    //  vector contained in the SIPI message)."
    //
    // See: 8.4.3 MP Initialization Protocol Algorithm for MP Systems
    //
    vmwrite(vmcs::guest::CS_SELECTOR, vector << 8);
    vmwrite(vmcs::guest::CS_BASE, vector << 12);
    vmwrite(vmcs::guest::RIP, 0u64);

    //
    // Done. Note that the 2nd SIPI will be ignored if that occurs after this.
    //
    // "If a logical processor is not in the wait-for-SIPI activity state when a
    //  SIPI arrives, no VM exit occurs and the SIPI is discarded"
    // See: 25.2 OTHER CAUSES OF VM EXITS
    //
    let vmx_active = 0x0u64;
    vmwrite(vmcs::guest::ACTIVITY_STATE, vmx_active);

    ExitType::Continue
}
