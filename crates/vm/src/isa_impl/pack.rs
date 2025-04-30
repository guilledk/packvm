use tailcall::tailcall;
use crate::{exit, jmp, jmpcnd, jmpnotcnd, packer_error, popcnd, jmpret, raise};
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
    PackVM
};

macro_rules! type_mismatch {
    ($expected:expr, $self:ident) => {
        Err(packer_error!("Expected {}, got {}", $expected, &$self.iostack[$self.iop]))
    };
}

#[cfg(feature = "debug")]
macro_rules! vmlog {
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

#[cfg(not(feature = "debug"))]
macro_rules! vmlog {
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
            vmlog!(vm, $dbg, "()");
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
    vmlog!(vm, "varuint32", "()");
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
    vmlog!(vm, "varuint32", "()");
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
    vmlog!(vm, "varuint32", "()");
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
    vmlog!(vm, "float128", "()");
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
    vmlog!(vm, "bytes", "()");
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
    vmlog!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut PackVM, buffer: &mut Vec<u8>) -> OpResult {
    match &vm.iostack[vm.iop] {
        Value::None => {
            buffer[vm.bp] = 0u8;
            vm.iop += 1;                     // pop the None
            vm.ip += 2;   // jump over wrapped code
            vmlog!(vm, "optional none", "()");
        }
        _ => {
            buffer[vm.bp] = 1u8;
            vm.ip += 1;                     // execute wrapped code next
            vmlog!(vm, "optional some", "()");
        }
    }
    vm.bp += 1;
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut PackVM) -> OpResult {
    match vm.iostack.get(vm.iop) {
        Some(Value::None) => {
            vm.iop += 1;                         // pop the sentinel
            vm.ip += 2;       // jump over wrapped code
            vmlog!(vm, "extension none", "()");
        }

        Some(_) => {
            vm.ip += 1;
            vmlog!(vm, "extension", "()");
        }

        None => {
            vm.ip += 2;       // skip wrapped code
            vmlog!(vm, "extension stack empty", "()");
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
    vmlog!(vm, "pushcnd", " io -> ({})", vm.cndstack[vm.cndstack.len() - 1]);
    Ok(())
}

#[tailcall]
#[cfg_attr(not(feature = "debug"), allow(unused_variables))]
pub fn exec(vm: &mut PackVM, buffer: &mut Vec<u8>) -> Result<(), PackerError> {
    match &vm.program.code[vm.ip] {
        Instruction::Bool => { boolean(vm, buffer)?; exec(vm, buffer) }

        Instruction::UInt {size} => {
            match size {
                1 => { uint8(vm, buffer)?; exec(vm, buffer) },
                2 => { uint16(vm, buffer)?; exec(vm, buffer) },
                4 => { uint32(vm, buffer)?; exec(vm, buffer) },
                8 => { uint64(vm, buffer)?; exec(vm, buffer) },
                16 => { uint128(vm, buffer)?; exec(vm, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Int {size} => {
            match size {
                1 => { int8(vm, buffer)?; exec(vm, buffer) },
                2 => { int16(vm, buffer)?; exec(vm, buffer) },
                4 => { int32(vm, buffer)?; exec(vm, buffer) },
                8 => { int64(vm, buffer)?; exec(vm, buffer) },
                16 => { int128(vm, buffer)?; exec(vm, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::VarUInt => { varuint32(vm, buffer)?; exec(vm, buffer) }
        Instruction::VarInt => { varint32(vm, buffer)?; exec(vm, buffer) },

        Instruction::Float {size} => {
            match size {
                4 => { float32(vm, buffer)?; exec(vm, buffer) },
                8 => { float64(vm, buffer)?; exec(vm, buffer) },
                16 => { float128(vm, buffer)?; exec(vm, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Bytes => { bytes(vm, buffer)?; exec(vm, buffer) }
        Instruction::BytesRaw{ size } => { bytes_raw(vm, buffer, *size)?; exec(vm, buffer) }

        Instruction::Optional => { optional(vm, buffer)?; exec(vm, buffer) }
        Instruction::Extension => { extension(vm)?; exec(vm, buffer) }

        Instruction::PushCND => { pushcnd(vm, buffer)?; exec(vm, buffer) }
        Instruction::PopCND => { popcnd!(vm)?; exec(vm, buffer) }
        Instruction::Jmp{ info: _, ptr} => { jmp!(vm, *ptr)?; exec(vm, buffer) }
        Instruction::JmpRet{info, ptr} => { jmpret!(vm, *info, *ptr); exec(vm, buffer) }
        Instruction::JmpCND{ ptrdelta: target, value, delta} => { jmpcnd!(vm, *target, *value, *delta)?; exec(vm, buffer) }
        Instruction::JmpNotCND{ ptrdelta: target, value, delta} => { jmpnotcnd!(vm, *target, *value, *delta)?; exec(vm, buffer) }
        Instruction::Raise{ex} => { raise!(vm, ex)?; exec(vm, buffer) }
        Instruction::Exit => {
            if exit!(vm)? {
                Ok(())
            } else {
                exec(vm, buffer)
            }
        }
        Instruction::Section(name) => { Err(packer_error!("Reached section instruction: {}", name))}
        Instruction::ProgramJmp{..} => { Err(packer_error!("Reached program jmp instruction")) },
    }
}