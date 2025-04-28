use crate::payload_size;
use crate::{
    utils::PackerError,
    compiler::Program,
    isa::Value,
    isa_impl::{pack, unpack}
};

pub struct PackVM<'a> {
    pub(crate) ip:  usize,
    pub(crate) bp: usize,
    pub(crate) iop:  usize,
    pub(crate) csp: usize,

    pub(crate) cndstack:   Vec<isize>,

    pub(crate) iostack:      &'a [Value],
    pub(crate) program: &'a Program,
}

impl<'a> PackVM<'a> {
    pub fn init(
        program: &'a Program,
        iostack: &'a [Value]
    ) -> PackVM<'a> {
        PackVM {
            ip: 0,
            bp: 0,
            iop: 0,
            csp: 0,
            cndstack: vec![0],

            iostack,
            program
        }
    }
}

impl<'a> PackVM<'a> {
    pub fn run(
        program: &Program,
        stack: &[Value]
    ) -> Result<Vec<u8>, PackerError> {
        let mut vm = PackVM::init(program, stack);
        let size = program.base_size + payload_size!(stack);
        let mut buffer: Vec<u8> = vec![0; size];

        pack::exec(&mut vm, &mut buffer)?;

        Ok(buffer)
    }
}

pub struct UnpackVM<'a> {
    pub(crate) ip:  usize,
    pub(crate) bp: usize,
    pub(crate) csp: usize,

    pub(crate) cndstack:   Vec<isize>,

    pub(crate) iostack: Vec<Value>,
    pub(crate) program: &'a Program
}

impl<'a> UnpackVM<'a> {
    pub fn init(program: &'a Program) -> Self {
        Self {
            ip: 0,
            bp: 0,
            csp: 0,

            cndstack: vec![0],

            iostack: Vec::new(),
            program
        }
    }
}

impl<'a> UnpackVM<'a> {
    pub fn run(
        program: &Program,
        buffer: &[u8]
    ) -> Result<Vec<Value>, PackerError> {
        let mut vm = UnpackVM::init(program);

        unpack::exec(&mut vm, buffer)?;

        Ok(vm.iostack)
    }
}
