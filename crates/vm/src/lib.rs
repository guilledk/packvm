#![allow(incomplete_features)]
#![feature(specialization)]
extern crate core;

pub mod compiler;
pub use compiler::{
    RunTarget,
    assembly::Executable
};
pub mod isa;
pub mod utils;
pub use isa::{DataInstruction, Instruction, Value};

mod isa_impl;
pub mod runtime;

pub use runtime::PackVM;

#[cfg(feature = "python")]
mod pyo3;
