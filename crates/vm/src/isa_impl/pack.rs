use tailcall::tailcall;
use crate::packer_error;
use crate::{
    utils::{
        PackerError,
        varint::{
            VarUInt32, VarInt32
        },
    },
    isa_impl::common::OpResult,
    Value,
    Instruction,
    Exception,
    PackVM
};

macro_rules! type_mismatch {
    ($expected:expr, $self:ident) => {
        Err(packer_error!("Expected {}, got {}", $expected, &$self.iostack[$self.iop]))
    };
}

#[cfg(feature = "debug_vm")]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) sp({:4}) csp({:4}) cnd({:4}) | {:80} | s: {:?}",
            $vm.ip,
            $vm.iop,
            $vm.csp,
            $vm.cndstack.last().unwrap_or(&-1),
            &format!("{}{}", $instr, format_args!($($args)*)),
            $vm.iostack.get($vm.iop),
        );
    }};
}

#[cfg(not(feature = "debug_vm"))]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{}};
}

macro_rules! vmstep {
    ($vm:ident) => {
        $vm.ip += 1;
        $vm.iop += 1;
    };
}

macro_rules! vmpack {
    ($vm:ident, $buf:ident, $val:expr) => {
        $buf[$vm.bp..$vm.bp + $val.len()].copy_from_slice($val);
        $vm.bp += $val.len();
    };
}

macro_rules! impl_pack_op {
    ($( ($fname:ident, $variant:ident, $dbg:literal) ),* $(,)?) => {$(
        #[inline(always)]
        pub fn $fname(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
            match vm.iostack[vm.iop] {
                Value::$variant(v) => {
                    vmpack!(
                        vm,
                        buffer,
                        v.to_le_bytes().as_ref()
                    );
                    vmstep!(vm);
                }
                _ => return type_mismatch!(stringify!($variant), vm),
            }
            debug_log!(vm, $dbg, "()");
            Ok(())
        }
    )*};
}

impl_pack_op!(
    (uint8,    Uint8,   "uint8"),
    (uint16,   Uint16,  "uint16"),
    (uint32,   Uint32,  "uint32"),
    (uint64,   Uint64,  "uint64"),
    (uint128,  Uint128, "uint128"),

    (int8,     Int8,    "int8"),
    (int16,    Int16,   "int16"),
    (int32,    Int32,   "int32"),
    (int64,    Int64,   "int64"),
    (int128,   Int128,  "int128"),

    (float32,  Float32, "float32"),
    (float64,  Float64, "float64"),
);

const TRUE_BYTES: [u8; 1] = [1u8];
const FALSE_BYTES: [u8; 1] = [0u8];

#[inline(always)]
pub fn boolean(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match vm.iostack[vm.iop] {
        Value::Bool(v) => {
            let flag = match v {
                true => &TRUE_BYTES,
                false => &FALSE_BYTES,
            };
            vmpack!(vm, buffer, flag);
            vmstep!(vm);
        }
        _ => return type_mismatch!("VarUInt32", vm)
    }
    debug_log!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varuint32(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match vm.iostack[vm.iop] {
        Value::VarUInt32(v) => {
            let (raw, size) = VarUInt32(v).encode();
            vmpack!(vm, buffer, &raw[..size]);
            vmstep!(vm);
        }
        _ => return type_mismatch!("VarUInt32", vm)
    }
    debug_log!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varint32(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match vm.iostack[vm.iop] {
        Value::VarInt32(v) => {
            let (raw, size) = VarInt32(v).encode();
            vmpack!(vm, buffer, &raw[..size]);
            vmstep!(vm);
        }
        _ => return type_mismatch!("VarUInt32", vm)
    }
    debug_log!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match &vm.iostack[vm.iop] {
        Value::Float128(v) => {
            vmpack!(vm, buffer, v);
            vmstep!(vm);
        }
        _ => return type_mismatch!("Float128", vm)
    }
    debug_log!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match &vm.iostack[vm.iop] {
        Value::Bytes(v) => {
            let (size_raw, size_len) = VarUInt32(v.len() as u32).encode();
            let mut array = Vec::with_capacity(size_len + v.len());
            array.extend_from_slice(&size_raw[..size_len]);
            array.extend_from_slice(v);
            vmpack!(vm, buffer, array.as_slice());
            vmstep!(vm);
        }
        _ => return type_mismatch!("Bytes", vm)
    }
    debug_log!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut PackVM, buffer: &mut Vec<u8>, len: u8) -> OpResult {
    match &vm.iostack[vm.iop] {
        Value::Bytes(v) => {
            if len > 0 && v.len() != len as usize {
                return Err(packer_error!("Raw bytes fixed size mistmatch: {} != {}", v.len(), len))
            }
            vmpack!(vm, buffer, v);
            vmstep!(vm);
        }
        _ => return type_mismatch!("Bytes", vm)
    }
    debug_log!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut PackVM, buffer: &mut Vec<u8>, stride: u8) -> OpResult {
    match &vm.iostack[vm.iop] {
        Value::None => {
            buffer[vm.bp] = 0u8;
            vm.iop += 1;                     // pop the None
            vm.ip += stride as usize + 1;   // jump over wrapped code
            debug_log!(vm, "optional none", "({})", stride);
        }
        _ => {
            buffer[vm.bp] = 1u8;
            vm.ip += 1;                     // execute wrapped code next
            debug_log!(vm, "optional some", "({})", stride);
        }
    }
    vm.bp += 1;
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut PackVM, stride: u8) -> OpResult {
    match vm.iostack.get(vm.iop) {
        Some(Value::None) => {
            vm.iop += 1;                         // pop the sentinel
            vm.ip += stride as usize + 1;       // jump over wrapped code
            debug_log!(vm, "extension none", "({})", stride);
        }

        Some(_) => {
            vm.ip += 1;
            debug_log!(vm, "extension", "({})", stride);
        }

        None => {
            vm.ip += stride as usize + 1;       // skip wrapped code
            debug_log!(vm, "extension stack empty", "({})", stride);
        }
    }
    Ok(())
}

#[inline(always)]
pub fn pushcnd(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match vm.iostack[vm.iop] {
        Value::Condition(cnd) => {
            vm.cndstack.push(cnd);
            vm.csp += 1;
            let (size_raw, size_len) = VarUInt32(cnd as u32).encode();
            vmpack!(vm, buffer, &size_raw[..size_len]);
            vmstep!(vm);
        }
        _ => return type_mismatch!("Condition", vm)
    }
    debug_log!(vm, "pushcnd", " io -> ({})", vm.cndstack[vm.cndstack.len() - 1]);
    Ok(())
}

#[inline(always)]
pub fn popcnd(vm: &mut PackVM) -> OpResult {
    vm.cndstack.pop();
    vm.csp -= 1;
    vm.ip += 1;
    debug_log!(vm, "popcnd", "()");
    Ok(())
}

pub fn jmp(vm: &mut PackVM, ptr: usize) -> OpResult {
    vm.ip = ptr;
    debug_log!(vm, "jmp", "({})", ptr);
    Ok(())
}

#[inline(always)]
pub fn jmpcnd(vm: &mut PackVM, target: usize, value: isize, delta: isize) -> OpResult {
    vm.cndstack[vm.csp] += delta;
    if vm.cndstack[vm.csp] == value {
        vm.ip = target;       // branch taken
        debug_log!(
            vm,
            "jmpcnd",
            "(t: {}, v: {}, d: {}) triggered", target, value, delta
        );
    } else {
        vm.ip += 1;           // fall-through
        debug_log!(
            vm,
            "jmpcnd",
            "(t: {}, v: {}, d: {})", target, value, delta
        );
    }
    Ok(())
}

#[inline(always)]
pub fn jmpnotcnd(vm: &mut PackVM, target: usize, value: isize, delta: isize) -> OpResult {
    vm.cndstack[vm.csp] += delta;
    if vm.cndstack[vm.csp] != value {
        vm.ip = target;       // branch taken
        debug_log!(
            vm,
            "jmpnotcnd",
            "(t: {}, v: {}, d: {}) triggered", target, value, delta
        );
    } else {
        vm.ip += 1;           // fall-through
        debug_log!(
            vm,
            "jmpnotcnd",
            "(t: {}, v: {}, d: {})", target, value, delta
        );
    }
    Ok(())
}

#[inline(always)]
#[cfg_attr(not(feature = "debug_vm"), allow(unused_variables))]
pub fn raise(vm: &PackVM, e: &Exception) -> OpResult {
    debug_log!(
        vm,
        "raise",
        "({:?})", e
    );
    Err(packer_error!("raise exception: {:?}", e))
}

#[inline(always)]
#[cfg_attr(not(feature = "debug_vm"), allow(unused_variables))]
pub fn exit(vm: &mut PackVM, status: u8) -> Result<u8, PackerError> {
    debug_log!(
        vm,
        "exit",
        "({})", status
    );
    Ok(status)
}

#[tailcall]
pub fn exec(vm: &mut PackVM, buffer: &mut Vec<u8>) -> Result<u8, PackerError> {
    match &vm.program.code[vm.ip] {
        Instruction::Bool => { boolean(vm, buffer)?; exec(vm, buffer) }

        Instruction::UInt(1) => { uint8(vm, buffer)?; exec(vm, buffer) }
        Instruction::UInt(2) => { uint16(vm, buffer)?; exec(vm, buffer) }
        Instruction::UInt(4) => { uint32(vm, buffer)?; exec(vm, buffer) }
        Instruction::UInt(8) => { uint64(vm, buffer)?; exec(vm, buffer) }
        Instruction::UInt(16) => { uint128(vm, buffer)?; exec(vm, buffer) }

        Instruction::Int(1) => { int8(vm, buffer)?; exec(vm, buffer) }
        Instruction::Int(2) => { int16(vm, buffer)?; exec(vm, buffer) }
        Instruction::Int(4) => { int32(vm, buffer)?; exec(vm, buffer) }
        Instruction::Int(8) => { int64(vm, buffer)?; exec(vm, buffer) }
        Instruction::Int(16) => { int128(vm, buffer)?; exec(vm, buffer) }

        Instruction::VarUInt => { varuint32(vm, buffer)?; exec(vm, buffer) }
        Instruction::VarInt => { varint32(vm, buffer)?; exec(vm, buffer) },

        Instruction::Float(4) => { float32(vm, buffer)?; exec(vm, buffer) }
        Instruction::Float(8) => { float64(vm, buffer)?; exec(vm, buffer) }
        Instruction::Float(16) => { float128(vm, buffer)?; exec(vm, buffer) }

        Instruction::Bytes => { bytes(vm, buffer)?; exec(vm, buffer) }
        Instruction::BytesRaw(l) => { bytes_raw(vm, buffer, *l)?; exec(vm, buffer) }

        Instruction::Optional(s) => { optional(vm, buffer, *s)?; exec(vm, buffer) }
        Instruction::Extension(s) => { extension(vm, *s)?; exec(vm, buffer) }

        Instruction::PushCND => { pushcnd(vm, buffer)?; exec(vm, buffer) }
        Instruction::PopCND => { popcnd(vm)?; exec(vm, buffer) }
        Instruction::Jmp(ptr) => { jmp(vm, *ptr)?; exec(vm, buffer) }
        Instruction::JmpCND(t, v, d) => { jmpcnd(vm, *t, *v, *d)?; exec(vm, buffer) }
        Instruction::JmpNotCND(t, v, d) => { jmpnotcnd(vm, *t, *v, *d)?; exec(vm, buffer) }
        Instruction::Raise(e) => { raise(vm, e)?; exec(vm, buffer) }
        Instruction::Exit(s) => { exit(vm, *s) }
        _ => unreachable!()
    }
}