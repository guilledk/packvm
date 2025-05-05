use crate::debug_log;
use crate::{
    utils::PackerError,
    isa::Value,
    isa_impl::{pack, unpack}
};
use crate::compiler::assembly::Executable;

#[derive(Debug, Clone)]
pub enum NamespacePart {
    Root,

    ArrayNode,
    ArrayIndex,

    StructNode(u8),
    StructField(String),
}

impl Into<String> for &NamespacePart {
    fn into(self) -> String {
        match self {
            NamespacePart::Root => "$".to_string(),
            NamespacePart::ArrayNode => "array".to_string(),
            NamespacePart::ArrayIndex => "idx".to_string(),
            NamespacePart::StructNode(ctype) => match ctype {
                1u8 => "enum",
                2u8 => "struct",
                _ => unreachable!()
            }.to_string(),
            NamespacePart::StructField(name) => name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackVM {
    pub(crate) ip: usize,
    pub(crate) bp: usize,  // only for unpack

    pub(crate) cndstack: Vec<u32>,
    pub(crate) retstack: Vec<usize>,

    pub(crate) io: Value,
    pub(crate) ionsp: Vec<NamespacePart>,
    pub(crate) executable: Executable
}

impl PackVM {
    pub fn from_executable(executable: Executable) -> Self {
        debug_log!("Initialized VM with executable: \n{}", executable.pretty_string());
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

    pub fn reset(&mut self) {
        self.bp = 0;
        self.cndstack = vec![0];
        self.retstack = vec![0];

        self.io = Value::None;
        self.ionsp = vec![NamespacePart::Root];
    }

    pub fn run_pack(
        &mut self,
        program: usize,
        io: &Value
    ) -> Result<Vec<u8>, PackerError> {
        self.reset();
        let mut buffer: Vec<u8> = vec![];
        self.ip = program;

        debug_log!("Running pack program: {}", program);
        debug_log!("Input: {:?}", io);

        pack::exec(self, io, &mut buffer)?;

        Ok(buffer)
    }

    pub fn run_unpack(
        &mut self,
        program: usize,
        buffer: &[u8]
    ) -> Result<&Value, PackerError> {
        self.ip = program;
        self.reset();

        debug_log!("Running unpack program: {}", program);

        unpack::exec(self, buffer)?;

        debug_log!("Output: {:?}", &self.io);

        Ok(&self.io)
    }

    #[inline(always)]
    pub fn cnd_at_level(&self, level: usize) -> u32 {
        let level = self.ionsp.len() - level;
        let mut csp = 1usize;
        for part in &self.ionsp[..level] {
            match part {
                NamespacePart::StructNode(ctype) => {
                    if *ctype == 1 {
                        csp += 1;
                    }
                },
                NamespacePart::ArrayNode => csp += 1,
                _ => (),
            }
        }

        self.cndstack[csp]
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

    pub fn nsp_string(&self) -> String {
        self.ionsp.iter()
            .map(|p| p.into())
            .map(|p| if p == "idx" {self.cnd().to_string()} else {p})
            .collect::<Vec<String>>()
            .join(".")
    }
}