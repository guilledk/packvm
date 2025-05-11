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

/// ValueCursor allows PackVM to keep track where in a nested Value is the next operation going to
/// touch, be for fetching a value to pack or unpacking the next bytes
/// # Safety
/// The caller guarantees every pushed pointer lives as long as the cursor
#[derive(Debug, Clone)]
pub struct ValueCursor {
    stack: Vec<std::ptr::NonNull<Value>>,
}

impl ValueCursor {
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

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

pub const PACKVM_RAM: usize = 1024 * 16;  // 16kb

#[derive(Clone)]
pub struct PackVM {
    pub(crate) bp: usize,  // buffer pointer: only needed for unpack
    pub(crate) ip: U48,  // instruction pointer
    pub(crate) fp: U48,  // field pointer: next field id
    pub(crate) et: u32,  // enum type: next enum variant index
    pub(crate) ef: bool,  // emum flag: on unpack, used to not repeat enum -> struct double push

    pub(crate) rp: usize,  // ram pointer
    pub(crate) ram: [u8; PACKVM_RAM],

    pub(crate) retstack: Vec<U48>,  // return stack: used by JmpRet & Exit instruction

    pub(crate) cursor: ValueCursor,
    pub(crate) executable: Executable
}

impl PackVM {
    pub fn from_executable(executable: Executable) -> Self {
        debug_log!("Initialized VM with executable: \n{}", executable.pretty_string());
        PackVM {
            bp: 0,
            ip: U48(0),
            fp: U48(0),
            et: 0,
            ef: false,

            rp: 8,
            ram: [0; PACKVM_RAM],

            retstack: vec![U48(0)],

            cursor: ValueCursor { stack: Vec::new() },
            executable,
        }
    }

    pub fn reset(&mut self) {
        self.bp = 0;
        self.fp = U48(0);
        self.ef = false;

        self.rp = 8;
        self.ram = [0; PACKVM_RAM];
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
        u32::from_le_bytes(
            self.ram[self.rp..self.rp + 4]
                .try_into()
                .expect("Could not get cnd from ram")
        )
    }

    #[inline(always)]
    pub fn set_cnd(&mut self, cnd: u32) -> () {
        let cnd = cnd.to_le_bytes();
        self.ram[self.rp] = cnd[0];
        self.ram[self.rp + 1] = cnd[1];
        self.ram[self.rp + 2] = cnd[2];
        self.ram[self.rp + 3] = cnd[3];
    }

    #[inline(always)]
    pub fn sub_cnd(&mut self, delta: u32) -> u32 {
        let cnd = self.cnd() - delta;
        self.set_cnd(cnd);
        cnd
    }

    #[inline(always)]
    pub fn push_cnd(&mut self, cnd: u32) -> () {
        self.rp += 4;
        self.set_cnd(cnd);
    }

    #[inline(always)]
    pub fn pop_cnd(&mut self) -> () {
        self.rp -= 4;
    }
}

impl Debug for PackVM {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ip({:4}) bp({:5}) cnd({:4}) rp({:2}) iop({:2})  | {}",
            self.ip, self.bp, self.cnd(), self.rp, self.cursor.len(),
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
