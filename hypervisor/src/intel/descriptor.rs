use {
    crate::intel::support::sgdt,
    alloc::{boxed::Box, vec::Vec},
    x86::{
        dtables::DescriptorTablePointer,
        segmentation::{
            cs, BuildDescriptor, CodeSegmentType, Descriptor, DescriptorBuilder,
            GateDescriptorBuilder, SegmentDescriptorBuilder, SegmentSelector,
        },
    },
};

// UEFI does not set TSS in the GDT. This is incompatible to be both as VM and
// hypervisor states. This struct supports creating a new GDT that does contain
// the TSS.
//
// See: 27.2.3 Checks on Host Segment and Descriptor-Table Registers
// See: 27.3.1.2 Checks on Guest Segment Registers
pub struct Descriptors {
    gdt: Vec<u64>,
    pub gdtr: DescriptorTablePointer<u64>,
    pub cs: SegmentSelector,
    pub tr: SegmentSelector,
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
    /// Creates a new GDT with TSS based on the current GDT.
    pub fn new_from_current() -> Self {
        log::debug!("Creating a new GDT with TSS for guest");

        // Get the current GDT.
        let current_gdtr = sgdt();
        let current_gdt = unsafe {
            core::slice::from_raw_parts(
                current_gdtr.base.cast::<u64>(),
                usize::from(current_gdtr.limit + 1) / 8,
            )
        };

        // Copy the current GDT.
        let mut descriptors = Self {
            gdt: current_gdt.to_vec(),
            ..Default::default()
        };

        // Append the TSS descriptor. Push extra 0 as it is 16 bytes.
        // See: 3.5.2 Segment Descriptor Tables in IA-32e Mode
        let tr_index = descriptors.gdt.len() as u16;
        descriptors
            .gdt
            .push(Self::task_segment_descriptor(&descriptors.tss).as_u64());
        descriptors.gdt.push(0);

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.cs = cs();
        descriptors.tr = SegmentSelector::new(tr_index, x86::Ring::Ring0);

        log::debug!("New GDT with TSS created for guest successfully!");

        descriptors
    }

    /// Creates a new GDT with TSS from scratch for the host.
    pub fn new_for_host() -> Self {
        log::debug!("Creating a new GDT with TSS for host");

        let mut descriptors = Self::default();

        descriptors.gdt.push(0);
        descriptors
            .gdt
            .push(Self::code_segment_descriptor().as_u64());
        descriptors
            .gdt
            .push(Self::task_segment_descriptor(&descriptors.tss).as_u64());
        descriptors.gdt.push(0);

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.cs = SegmentSelector::new(1, x86::Ring::Ring0);
        descriptors.tr = SegmentSelector::new(2, x86::Ring::Ring0);

        log::debug!("New GDT with TSS created for host successfully!");

        descriptors
    }

    /// Builds a segment descriptor from the task state segment.
    fn task_segment_descriptor(tss: &TaskStateSegment) -> Descriptor {
        <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(tss.base, tss.limit, true)
            .present()
            .dpl(x86::Ring::Ring0)
            .finish()
    }

    fn code_segment_descriptor() -> Descriptor {
        DescriptorBuilder::code_descriptor(0, u32::MAX, CodeSegmentType::ExecuteAccessed)
            .present()
            .dpl(x86::Ring::Ring0)
            .limit_granularity_4kb()
            .l()
            .finish()
    }

    /// Gets the table as a slice from the pointer.
    pub fn from_pointer(pointer: &DescriptorTablePointer<u64>) -> &[u64] {
        unsafe {
            core::slice::from_raw_parts(
                pointer.base.cast::<u64>(),
                (pointer.limit + 1) as usize / core::mem::size_of::<u64>(),
            )
        }
    }
}

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct TaskStateSegment {
    pub base: u64,
    pub limit: u64,
    pub ar: u32,
    #[allow(dead_code)]
    #[derivative(Debug = "ignore")]
    segment: Box<TaskStateSegmentRaw>,
}
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

/// See: Figure 8-11. 64-Bit TSS Format
#[allow(dead_code)]
struct TaskStateSegmentRaw([u8; 104]);
