use std::fmt::{Debug, Formatter};
use crate::debug_log;
use crate::{
    utils::PackerError,
    isa::Value,
    isa_impl::{unpack}
};
use crate::compiler::assembly::Executable;
use crate::compiler::RESERVED_IDS;
use crate::isa_impl::pack;
use crate::utils::numbers::U48;

/// Always points at the *slot* the current opcode writes into.
#[derive(Debug, Clone)]
pub struct ValueCursor {
    stack: Vec<std::ptr::NonNull<Value>>,
}

impl ValueCursor {
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// # Safety
    /// The caller guarantees every pushed pointer lives as long as the cursor
    /// (that’s true while we mutate only through `vm.io`).
    #[inline(always)]
    pub unsafe fn push(&mut self, ptr: *mut Value) {
        self.stack.push(std::ptr::NonNull::new_unchecked(ptr));
    }

    #[inline(always)]
    pub fn pop(&mut self) {
        self.stack.pop();
    }

    #[inline(always)]
    pub fn current(&self) -> &Value {
        unsafe { self.stack.last().unwrap().as_ref() }
    }

    #[inline(always)]
    pub fn current_mut(&mut self) -> &mut Value {
        unsafe { self.stack.last_mut().unwrap().as_mut() }
    }
}

#[derive(Clone)]
pub struct PackVM {
    pub(crate) ip: U48,
    pub(crate) bp: usize,  // only for unpack
    pub(crate) fp: U48,  // next field id
    pub(crate) et: u32,  // next enum variant index
    pub(crate) ef: bool,  // on unpack, used to not repeat enum -> struct double push

    pub(crate) cndstack: Vec<u32>,
    pub(crate) retstack: Vec<U48>,

    pub(crate) cursor: ValueCursor,
    pub(crate) executable: Executable
}

impl PackVM {
    pub fn from_executable(executable: Executable) -> Self {
        debug_log!("Initialized VM with executable: \n{}", executable.pretty_string());
        PackVM {
            ip: U48(0),
            fp: U48(0),
            bp: 0,
            et: 0,
            ef: false,

            cndstack: vec![0],
            retstack: vec![U48(0)],

            cursor: ValueCursor { stack: Vec::new() },
            executable,
        }
    }

    pub fn reset(&mut self) {
        self.bp = 0;
        self.fp = U48(0);
        self.ef = false;

        self.cndstack = vec![0];
        self.retstack = vec![U48(0)];

        self.cursor.stack.clear();
    }

    pub fn run_pack(
        &mut self,
        program: U48,
        io: &Value
    ) -> Result<Vec<u8>, PackerError> {
        self.reset();
        let mut buffer: Vec<u8> = vec![];
        let mut val = io.clone();
        unsafe { self.cursor.push(&mut val as *mut _); }

        self.ip = program - U48::from(RESERVED_IDS);

        debug_log!("Running pack program: {}", program);

        pack::exec(self, &mut buffer)?;

        Ok(buffer)
    }

    pub fn run_unpack(
        &mut self,
        program: U48,
        buffer: &[u8]
    ) -> Result<Value, PackerError> {
        self.reset();
        let mut val = Value::None;
        unsafe { self.cursor.push(&mut val as *mut _); }

        self.ip = program - U48::from(RESERVED_IDS);

        debug_log!("Running unpack program: {}", program);

        unpack::exec(self, buffer)?;

        Ok(val)
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

impl Debug for PackVM {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ip({:4}) bp({:5}) cnd({:4}) csp({:2}) iop({:2})  | {}",
            self.ip, self.bp, self.cnd(), self.cndstack.len(), self.cursor.len(),
            self.executable.pretty_op_string(self.ip)
        ))
    }
}

#[macro_export]
macro_rules! run_pack {
    ($vm:ident, $pid:expr, $val:expr) => {
        match $vm.run_pack($pid, $val) {
            Ok(encoded) => encoded,
            Err(err) => panic!("Run pack failed!:\n{}", err.reason),
        }
    };
}

#[macro_export]
macro_rules! run_unpack {
    ($vm:ident, $pid:expr, $buf:expr) => {
        match $vm.run_unpack($pid, $buf) {
            Ok(decoded) => decoded,
            Err(err) => panic!("Run unpack failed!:\n{}", err.reason),
        }
    };
}
