#![allow(incomplete_features)]
#![feature(specialization)]
extern crate core;

pub mod compiler;
pub mod isa;
pub mod utils;
pub use isa::{Instruction, Value};

mod isa_impl;
pub mod runtime;

pub use runtime::PackVM;

#[cfg(feature = "python")]
mod pyo3;
