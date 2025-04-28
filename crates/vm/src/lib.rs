#![feature(specialization)]
pub mod utils;
pub mod compiler;
pub mod isa;
pub use isa::{
    Value,
    Instruction,
    Exception,
    IOStackValue,
    IntoIOStack
};

mod isa_impl;
pub mod runtime;

pub use runtime::{
    PackVM,
    UnpackVM
};
