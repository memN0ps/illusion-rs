#![no_main]
#![no_std]

use log::*;
use uefi::prelude::*;

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    com_logger::builder().filter(LevelFilter::Debug).setup();

    uefi_services::init(&mut system_table).unwrap();
    
    info!("Hello, world!");
    
    system_table.boot_services().stall(10_000_000);

    Status::SUCCESS
}