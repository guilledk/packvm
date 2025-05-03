#![allow(incomplete_features)]
#![feature(specialization)]
extern crate core;

pub mod utils;
pub mod compiler;
pub mod isa;
pub use isa::{
    Value,
    Instruction,
};

mod isa_impl;
pub mod runtime;

pub use runtime::{
    PackVM,
};
