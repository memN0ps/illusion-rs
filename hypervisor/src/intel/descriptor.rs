//! Manages GDT and TSS for VMX virtualization contexts.
//!
//! Facilitates the creation and manipulation of the Global Descriptor Table (GDT) and
//! Task State Segment (TSS) necessary for VMX operations. Supports both host and guest
//! environments, ensuring compatibility and proper setup for virtualization.
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/descriptors.rs

use {
    crate::intel::support::sgdt,
    alloc::{boxed::Box, vec::Vec},
    x86::{
        dtables::DescriptorTablePointer,
        segmentation::{
            cs, BuildDescriptor, CodeSegmentType, Descriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentDescriptorBuilder, SegmentSelector,
        },
    },
};

/// Manages GDT and TSS for VMX operations.
///
/// Supports creating a new GDT that includes TSS, addressing compatibility issues in UEFI environments
/// and ensuring proper VM and hypervisor states. This struct is essential for setting up the environment
/// for both host and guest VMX operations.
pub struct Descriptors {
    /// Vector holding the GDT entries.
    gdt: Vec<u64>,

    /// Descriptor table pointer to the GDT.
    pub gdtr: DescriptorTablePointer<u64>,

    /// Code segment selector.
    pub cs: SegmentSelector,

    /// Task register selector.
    pub tr: SegmentSelector,

    /// Task State Segment.
    pub tss: TaskStateSegment,
}

impl Default for Descriptors {
    fn default() -> Self {
        Self {
            gdt: Vec::new(),
            gdtr: DescriptorTablePointer::<u64>::default(),
            cs: SegmentSelector::from_raw(0),
            tr: SegmentSelector::from_raw(0),
            tss: TaskStateSegment::default(),
        }
    }
}
impl Descriptors {
    /// Creates a new GDT based on the current one, including TSS.
    ///
    /// Copies the current GDT and appends a TSS descriptor to it. Useful for guest
    /// VM setup to ensure compatibility with VMX requirements.
    ///
    /// # Returns
    /// A `Descriptors` instance with an updated GDT including TSS.
    pub fn new_from_current() -> Self {
        log::debug!("Creating a new GDT with TSS for guest");

        // Get the current GDT.
        let current_gdtr = sgdt();
        let current_gdt = unsafe { core::slice::from_raw_parts(current_gdtr.base.cast::<u64>(), usize::from(current_gdtr.limit + 1) / 8) };

        // Copy the current GDT.
        let mut descriptors = Self {
            gdt: current_gdt.to_vec(),
            ..Default::default()
        };

        // Append the TSS descriptor. Push extra 0 as it is 16 bytes.
        // See: 3.5.2 Segment Descriptor Tables in IA-32e Mode
        let tr_index = descriptors.gdt.len() as u16;
        descriptors.gdt.push(Self::task_segment_descriptor(&descriptors.tss).as_u64());
        descriptors.gdt.push(0);

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.cs = cs();
        descriptors.tr = SegmentSelector::new(tr_index, x86::Ring::Ring0);

        log::debug!("New GDT with TSS created for guest successfully!");

        descriptors
    }

    /// Creates a new GDT with TSS from scratch for the host.
    ///
    /// Initializes a GDT with essential descriptors, including a TSS descriptor,
    /// tailored for host operation in a VMX environment.
    ///
    /// # Returns
    /// A `Descriptors` instance with a newly created GDT for the host.
    pub fn new_for_host() -> Self {
        log::debug!("Creating a new GDT with TSS for host");

        let mut descriptors = Self::default();

        descriptors.gdt.push(0);
        descriptors.gdt.push(Self::code_segment_descriptor().as_u64());
        descriptors.gdt.push(Self::task_segment_descriptor(&descriptors.tss).as_u64());
        descriptors.gdt.push(0);

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.cs = SegmentSelector::new(1, x86::Ring::Ring0);
        descriptors.tr = SegmentSelector::new(2, x86::Ring::Ring0);

        log::debug!("New GDT with TSS created for host successfully!");

        descriptors
    }

    /// Builds a descriptor for the Task State Segment (TSS).
    ///
    /// Configures a TSS descriptor based on the provided TSS's base and limit,
    /// setting it as present and with a privilege level of ring 0.
    ///
    /// # Arguments
    ///
    /// - `tss`: A reference to the `TaskStateSegment` for which to create the descriptor.
    ///
    /// # Returns
    ///
    /// A `Descriptor` instance representing the TSS in the GDT.
    fn task_segment_descriptor(tss: &TaskStateSegment) -> Descriptor {
        <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(tss.base, tss.limit, true)
            .present()
            .dpl(x86::Ring::Ring0)
            .finish()
    }

    /// Constructs a code segment descriptor for use in the GDT.
    ///
    /// Creates a descriptor representing a code segment with standard access rights,
    /// suitable for execution in a protected or long mode environment.
    ///
    /// # Returns
    ///
    /// A `Descriptor` instance configured as a code segment.
    fn code_segment_descriptor() -> Descriptor {
        DescriptorBuilder::code_descriptor(0, u32::MAX, CodeSegmentType::ExecuteAccessed)
            .present()
            .dpl(x86::Ring::Ring0)
            .limit_granularity_4kb()
            .l()
            .finish()
    }

    /// Converts a descriptor table pointer to a slice of GDT entries.
    ///
    /// # Arguments
    ///
    /// - `pointer`: A reference to the `DescriptorTablePointer` for the GDT.
    ///
    /// # Returns
    ///
    /// A slice of the GDT entries represented as `u64` values.
    pub fn from_pointer(pointer: &DescriptorTablePointer<u64>) -> &[u64] {
        unsafe { core::slice::from_raw_parts(pointer.base.cast::<u64>(), (pointer.limit + 1) as usize / core::mem::size_of::<u64>()) }
    }
}

/// Represents the Task State Segment (TSS).
///
/// Encapsulates the TSS, which is critical for task-switching and storing state information
/// in protected mode operations. Includes fields for the base address, limit, and access rights.:
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct TaskStateSegment {
    /// The base address of the TSS.
    pub base: u64,

    /// The size of the TSS minus one.
    pub limit: u64,

    /// Access rights for the TSS.
    pub ar: u32,

    /// The actual TSS data.
    #[allow(dead_code)]
    #[derivative(Debug = "ignore")]
    segment: Box<TaskStateSegmentRaw>,
}

/// Initializes a default TSS.
///
/// Allocates and sets up a default TSS with predefined access rights and size,
/// ready for use in VMX operations.
///
/// # Returns
/// A default `TaskStateSegment` instance.
impl Default for TaskStateSegment {
    fn default() -> Self {
        let segment = Box::new(TaskStateSegmentRaw([0; 104]));
        Self {
            base: segment.as_ref() as *const _ as u64,
            limit: core::mem::size_of_val(segment.as_ref()) as u64 - 1,
            ar: 0x8b00,
            segment,
        }
    }
}

/// Low-level representation of the 64-bit Task State Segment (TSS).
///
/// Encapsulates the raw structure of the TSS as defined in the x86_64 architecture.
/// This structure is used internally to manage the TSS's memory layout directly.
/// See: Figure 8-11. 64-Bit TSS Format
#[allow(dead_code)]
struct TaskStateSegmentRaw([u8; 104]);
