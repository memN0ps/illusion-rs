use crate::intel::paging::PageTables;

/// Reads a value of a specified type from guest memory at the provided virtual address, ensuring safety by internal validation.
///
/// # Arguments
///
/// * `guest_cr3` - The base address of the guest's page table hierarchy.
/// * `guest_va` - The guest virtual address from which to read.
///
/// # Returns
///
/// * Returns an `Option<T>` which is `Some(value)` if the read is successful and safe, or `None` if the address cannot be translated or if safety conditions are not met.
///
/// # Type Parameters
///
/// * `T` - The type of the value to read. This can be any type that implements the `Copy` trait and has a size that can be read atomically.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
pub fn read_guest_memory<T: Copy>(guest_cr3: usize, guest_va: usize) -> Option<T> {
    // Safety justification:
    // The translation function ensures that the physical address is valid and maps to a real physical memory location.
    // The dereference is only performed if the translation succeeds, and it's constrained to types that are Copy, implying they can be safely duplicated and do not manage resources that require manual cleanup.
    // Still, the caller must ensure that reading from this specific address does not violate any safety contracts.
    let pa = PageTables::translate_guest_virtual_to_physical(guest_cr3, guest_va)?;
    unsafe { Some(*(pa as *const T)) }
}

/// Finds the base virtual address of an image by scanning memory for the 'MZ' signature, starting
/// from a specified address and scanning backwards. This function is typically used to locate
/// the base address of system modules like ntoskrnl.exe in a Windows guest.
///
/// # Arguments
/// * `start_address` - The guest virtual address from where the backward scanning begins.
///
/// # Returns
/// * `Option<u64>` - Some with the base virtual address of the image if the 'MZ' signature is found,
///   indicating the start of a PE header; otherwise None.
///
/// # Safety
/// This function performs raw memory accesses based on a guest virtual address. The caller must ensure
/// that the provided address and the memory being accessed are valid and safely accessible.
///
/// # Credits
/// Credits to Jessie (jessiep_) for the initial concept.
pub fn get_image_base_address(start_address: u64, guest_cr3: u64) -> Option<u64> {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // 'MZ' signature at the start of DOS headers.

    // Align the start address down to the nearest page boundary.
    let mut guest_va = start_address & !0xFFF;

    loop {
        // Attempt to read the potential DOS signature at the current address.
        match read_guest_memory::<u16>(guest_cr3 as _, guest_va as _)? {
            IMAGE_DOS_SIGNATURE => return Some(guest_va), // Found the 'MZ' signature.
            _ => {
                if guest_va == 0 {
                    break; // Prevent underflow and ensure the loop eventually terminates.
                }
                guest_va -= 0x1000; // Move to the previous page.
            }
        }
    }

    None // The 'MZ' signature was not found in the scanned range.
}
