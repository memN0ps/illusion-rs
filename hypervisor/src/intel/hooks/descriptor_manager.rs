use {crate::intel::descriptor::Descriptors, lazy_static::lazy_static, spin::Mutex};

/// Manages descriptor tables for both guest and host states in a virtualized environment.
///
/// The `DescriptorManager` struct holds descriptor tables for the guest and host,
/// ensuring that each has the necessary configurations for VMX operations. This includes
/// the Global Descriptor Table (GDT) and the Interrupt Descriptor Table (IDT) for both
/// the guest and host.

pub struct DescriptorManager {
    /// Descriptor tables for the guest state.
    pub guest_descriptor: Descriptors,

    /// Descriptor tables for the host state.
    pub host_descriptor: Descriptors,
}

lazy_static! {
    /// A globally shared instance of `DescriptorManager`, protected by a mutex.
    ///
    /// The `SHARED_DESCRIPTOR_MANAGER` ensures that there is a single instance of
    /// `DescriptorManager` accessible throughout the application. It is protected by
    /// a `spin::Mutex` to ensure safe concurrent access. The descriptor tables are
    /// initialized for both guest and host states.
    pub static ref SHARED_DESCRIPTOR_MANAGER: Mutex<DescriptorManager> = Mutex::new(DescriptorManager {
        guest_descriptor: Descriptors::initialize_for_guest(),
        host_descriptor: Descriptors::initialize_for_host(),
    });
}
