//! This crate provides an interface to a hypervisor.

#![no_std]
#![feature(allocator_api)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(once_cell_try)]
#![feature(decl_macro)]
#![feature(new_zeroed_alloc)]

extern crate alloc;
extern crate static_assertions;

pub mod allocator;
pub mod error;
pub mod global_const;
pub mod intel;
pub mod logger;
pub mod vmm;
pub mod windows;
