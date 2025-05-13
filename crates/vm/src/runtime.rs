use crate::compiler::assembly::Executable;
use crate::compiler::{RunTarget, TypeModifier, RESERVED_IDS, TRAP_COUNT};
use crate::isa_impl::pack;
use crate::utils::numbers::U48;
use crate::debug_log;
use crate::{isa::Value, isa_impl::unpack, utils::PackerError};
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ptr::NonNull;

/// ValueCursor allows PackVM to keep track where in a nested Value is the next operation going to
/// touch, be for fetching a value to pack or unpacking the next bytes
/// # Safety
/// The caller guarantees every pushed pointer lives as long as the cursor
pub struct ValueCursor<const MAX: usize> {
    stack: [MaybeUninit<NonNull<Value>>; MAX],
    len: usize,
}

impl<const MAX: usize> ValueCursor<MAX> {
    #[inline(always)]
    pub const fn new() -> Self {
        // `[MaybeUninit<_>; N]` is always valid uninitialised memory.
        Self {
            stack: unsafe {
                MaybeUninit::<[MaybeUninit<NonNull<Value>>; MAX]>::uninit().assume_init()
            },
            len: 0,
        }
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// # Safety
    /// Caller guarantees `ptr` lives while it is on the cursor stack.
    #[inline(always)]
    pub unsafe fn push(&mut self, ptr: *mut Value) {
        debug_assert!(self.len < MAX, "ValueCursor overflow");
        self.stack[self.len].write(NonNull::new_unchecked(ptr));
        self.len += 1;
    }

    #[inline(always)]
    pub fn pop(&mut self) {
        debug_assert!(self.len > 0, "ValueCursor underflow");
        self.len -= 1;
    }

    #[inline(always)]
    pub fn current(&self) -> &Value {
        debug_assert!(self.len > 0, "ValueCursor is empty");
        unsafe { self.stack[self.len - 1].assume_init_ref().as_ref() }
    }

    #[inline(always)]
    pub fn current_mut(&mut self) -> &mut Value {
        debug_assert!(self.len > 0, "ValueCursor is empty");
        unsafe { self.stack[self.len - 1].assume_init_mut().as_mut() }
    }
}

impl<const MAX: usize> Default for ValueCursor<MAX> {
    fn default() -> Self {
        Self::new()
    }
}

pub const PACKVM_RAM: usize = 1024 * 16; // 16kb
pub const PACKVM_MAX_DEPTH: usize = 2048;

pub struct PackVM {
    pub(crate) bp: usize, // buffer pointer: only needed for unpack
    pub(crate) ip: U48,   // instruction pointer
    pub(crate) fp: U48,   // field pointer: next field id
    pub(crate) ef: bool,  // emum flag: on unpack, used to not repeat enum -> struct double push

    pub(crate) rp: usize, // ram pointer
    pub(crate) ram: [u8; PACKVM_RAM],

    pub(crate) retp: usize,                       // return stack pointer
    pub(crate) retstack: [U48; PACKVM_MAX_DEPTH], // return stack: used by JmpRet & Exit instruction

    pub(crate) cursor: ValueCursor<PACKVM_MAX_DEPTH>,
    pub(crate) executable: Executable,
}

impl Clone for PackVM {
    fn clone(&self) -> Self {
        Self::from_executable(self.executable.clone())
    }
}

impl PackVM {
    pub fn from_executable(executable: Executable) -> Self {
        debug_log!(
            "Initialized VM with executable: \n{}",
            executable.pretty_string()
        );
        PackVM {
            bp: 0,
            ip: U48(0),
            fp: U48(0),
            ef: false,

            rp: 8,
            ram: [0; PACKVM_RAM],

            retp: 1,
            retstack: [U48(0); PACKVM_MAX_DEPTH],

            cursor: ValueCursor::new(),
            executable,
        }
    }

    pub fn executable(&self) -> &Executable {
        &self.executable
    }

    pub fn reset(&mut self) {
        self.bp = 0;
        self.fp = U48(0);
        self.ef = false;

        self.rp = 8;
        self.retp = 1;

        self.cursor.clear();
    }

    fn set_target(&mut self, target: &RunTarget) {
        if let Some(modifier) = target.modifier {
            let pid = target.pid - U48::from(RESERVED_IDS - TRAP_COUNT);
            self.set_pid(pid);
            match modifier {
                TypeModifier::Array => {
                    self.ip = U48(0);
                }
                TypeModifier::Optional => {
                    self.ip = U48(1);
                }
                TypeModifier::Extension => {
                    self.ip = U48(2);
                }
            }
        } else {
            self.ip = target.pid - U48::from(RESERVED_IDS - TRAP_COUNT);
        }
    }

    pub fn run_pack(&mut self, target: &RunTarget, io: &Value) -> Result<Vec<u8>, PackerError> {
        self.reset();
        let mut buffer: Vec<u8> = vec![];
        let mut val = io.clone();
        unsafe {
            self.cursor.push(&mut val as *mut _);
        }

        self.set_target(target);

        debug_log!("Running pack program: {:?}", target);

        pack::exec(self, &mut buffer)?;

        Ok(buffer)
    }

    pub fn run_unpack(&mut self, target: &RunTarget, buffer: &[u8]) -> Result<Value, PackerError> {
        self.reset();
        let mut val = Value::None;
        unsafe {
            self.cursor.push(&mut val as *mut _);
        }

        self.set_target(target);

        debug_log!("Running unpack program: {:?}", target);

        unpack::exec(self, buffer)?;

        Ok(val)
    }
    #[inline(always)]
    pub fn pid(&self) -> U48 {
    u64::from_le_bytes(
        self.ram[..8]
            .try_into()
            .expect("Could not get pid from ram"),
        ).into()
    }
    #[inline(always)]
    pub fn set_pid(&mut self, pid: U48) {
        let pid = pid.0.to_le_bytes();
        self.ram[0] = pid[0];
        self.ram[1] = pid[1];
        self.ram[2] = pid[2];
        self.ram[3] = pid[3];
        self.ram[4] = pid[4];
        self.ram[5] = pid[5];
        self.ram[6] = pid[6];
        self.ram[7] = pid[7];
    }

    #[inline(always)]
    pub fn cnd(&self) -> u32 {
        u32::from_le_bytes(
            self.ram[self.rp..self.rp + 4]
                .try_into()
                .expect("Could not get cnd from ram"),
        )
    }

    #[inline(always)]
    pub fn set_cnd(&mut self, cnd: u32) {
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
    pub fn push_cnd(&mut self, cnd: u32) {
        self.rp += 4;
        self.set_cnd(cnd);
    }

    #[inline(always)]
    pub fn pop_cnd(&mut self) {
        self.rp -= 4;
    }
    #[inline(always)]
    pub fn push_ret(&mut self) {
        self.retp += 1;
        self.retstack[self.retp] = self.ip;
    }
}

impl Debug for PackVM {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ip({:4}) bp({:5}) cnd({:4}) rp({:2}) retp({:2}) iop({:2})  | {}",
            self.ip,
            self.bp,
            self.cnd(),
            self.rp,
            self.retp,
            self.cursor.len(),
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
