use crate::{debug_log, payload_size, Instruction};
use crate::{
    utils::PackerError,
    compiler::Program,
    isa::Value,
    isa_impl::{pack, unpack}
};

#[derive(Debug)]
pub enum NamespacePart {
    Root,

    ArrayNode,
    ArrayIndex,

    StructNode(u8),
    StructField,
}

impl Into<String> for &NamespacePart {
    fn into(self) -> String {
        match self {
            NamespacePart::Root => "$".to_string(),
            NamespacePart::ArrayNode => "array".to_string(),
            NamespacePart::ArrayIndex => "idx".to_string(),
            NamespacePart::StructNode(ctype) => match ctype {
                1u8 => "enum".to_string(),
                2u8 => "struct".to_string(),
                _ => unreachable!()
            },
            NamespacePart::StructField => "field".to_string(),
        }
    }
}


pub struct PackVM<'a> {
    pub(crate) ip:  usize,
    pub(crate) bp: usize,
    pub(crate) iop:  usize,
    pub(crate) csp: usize,

    pub(crate) cndstack:   Vec<isize>,
    pub(crate) retstack:   Vec<usize>,

    pub(crate) iostack:      &'a [Value],
    pub(crate) ionsp: Vec<NamespacePart>,
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
            retstack: vec![0],

            ionsp: vec![NamespacePart::Root],

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

        debug_log!("Running pack program: ");
        #[cfg_attr(not(feature = "debug"), allow(unused_variables))]
        for op in program.code.iter().enumerate() {
            debug_log!("{:?}", op);
        }
        debug_log!("With stack: \n{:#?}", stack);

        pack::exec(&mut vm, &mut buffer)?;

        Ok(buffer)
    }
}

pub struct UnpackVM<'a> {
    pub(crate) ip:  usize,
    pub(crate) bp: usize,

    pub(crate) cndstack:   Vec<isize>,
    pub(crate) retstack:   Vec<usize>,

    pub(crate) io: Value,
    pub(crate) ionsp: Vec<NamespacePart>,
    pub(crate) code: &'a [Instruction]
}

impl<'a> UnpackVM<'a> {
    pub fn init(code: &'a [Instruction]) -> Self {
        Self {
            ip: 0,
            bp: 0,

            cndstack: vec![0],
            retstack: vec![0],

            io: Value::None,
            ionsp: vec![NamespacePart::Root],

            code
        }
    }
}

impl<'a> UnpackVM<'a> {
    pub fn run(
        program: u64,
        code: &[Instruction],
        buffer: &[u8]
    ) -> Result<Value, PackerError> {
        let mut vm = UnpackVM::init(code);
        vm.ip = program as usize;

        debug_log!("Running unpack program: ");
        #[cfg_attr(not(feature = "debug"), allow(unused_variables))]
        for op in code.iter().enumerate() {
            debug_log!("{:?}", op);
        }

        unpack::exec(&mut vm, buffer)?;

        debug_log!("Output: \n{:#?}", vm.io);

        Ok(vm.io)
    }
}
