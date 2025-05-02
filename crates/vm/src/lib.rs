#![feature(specialization)]
pub mod utils;
pub mod compiler;
pub mod isa;
pub use isa::{
    Value,
    Instruction,
    Exception,
    IOValue,
};

mod isa_impl;
pub mod runtime;

pub use runtime::{
    PackVM,
    UnpackVM
};
