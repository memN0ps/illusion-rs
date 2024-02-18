//! This crate provides an interface to a hypervisor.

#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![feature(once_cell_try)]
#![feature(decl_macro)]

extern crate alloc;
extern crate static_assertions;

pub mod config;
pub mod error;
pub mod intel;
pub mod logger;
pub mod vmm;
