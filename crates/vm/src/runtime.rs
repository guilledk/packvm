use crate::debug_log;
use crate::{
    utils::PackerError,
    isa::Value,
    isa_impl::{pack, unpack}
};
use crate::compiler::assembly::Executable;

#[derive(Debug)]
pub enum NamespacePart {
    Root,

    ArrayNode,
    ArrayIndex,

    StructNode(u8, String),
    StructField(String),
}

impl Into<String> for &NamespacePart {
    fn into(self) -> String {
        match self {
            NamespacePart::Root => "$".to_string(),
            NamespacePart::ArrayNode => "array".to_string(),
            NamespacePart::ArrayIndex => "idx".to_string(),
            NamespacePart::StructNode(ctype, name) => match ctype {
                1u8 => format!("enum({})", name),
                2u8 => format!("struct({})", name),
                _ => unreachable!()
            },
            NamespacePart::StructField(name) => name.clone(),
        }
    }
}


pub struct PackVM<'a> {
    pub(crate) ip: usize,
    pub(crate) bp: usize,  // only for unpack

    pub(crate) cndstack: Vec<u32>,
    pub(crate) retstack: Vec<usize>,

    pub(crate) io: Value,
    pub(crate) ionsp: Vec<NamespacePart>,
    pub(crate) executable: &'a Executable
}

impl<'a> PackVM<'a> {
    pub fn from_executable(executable: &'a Executable) -> Self {
        debug_log!("Initialized VM with executable: \n{:?}", executable);
        PackVM {
            ip: 0,
            bp: 0,

            cndstack: vec![0],
            retstack: vec![0],

            io: Value::None,
            ionsp: vec![NamespacePart::Root],

            executable
        }
    }

    pub fn run_pack(
        &mut self,
        program: usize,
        io: &Value
    ) -> Result<Vec<u8>, PackerError> {
        let mut buffer: Vec<u8> = vec![];
        self.ip = program;

        debug_log!("Running pack program: {}", program);

        pack::exec(self, io, &mut buffer)?;

        Ok(buffer)
    }

    pub fn run_unpack(
        &mut self,
        program: usize,
        buffer: &[u8]
    ) -> Result<&Value, PackerError> {
        self.ip = program;

        debug_log!("Running unpack program: {}", program);

        unpack::exec(self, buffer)?;

        Ok(&self.io)
    }

    #[inline(always)]
    pub fn nsp_last(&self) -> &NamespacePart {
        let last = self.ionsp.len() - 1;
        &self.ionsp[last]
    }

    #[inline(always)]
    pub fn cnd(&self) -> u32 {
        let last = self.cndstack.len() - 1;
        self.cndstack[last]
    }

    #[inline(always)]
    pub fn cnd_mut(&mut self) -> &mut u32 {
        let last = self.cndstack.len() - 1;
        &mut self.cndstack[last]
    }
}