use tailcall::tailcall;
use crate::{exit, jmp, packer_error, popcnd, jmpret, section, field, jmpacnd, jmpscnd};
use crate::{
    utils::{
        PackerError,
        varint::{
            VarUInt32, VarInt32
        },
    },
    runtime::NamespacePart,
    isa_impl::common::OpResult,
    Value,
    Instruction,
    PackVM
};

macro_rules! type_mismatch {
    ($expected:expr, $got:ident) => {
        Err(packer_error!("Expected {}, got {}", $expected, $got))
    };
}

#[cfg(feature = "debug")]
macro_rules! vmlog {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) cnd({:4}) | {:80} | ionsp: {}",
            $vm.ip,
            $vm.cndstack.last().unwrap(),
            &format!("{}{}", $instr, format_args!($($args)*)),
            $vm.ionsp.iter().map(|p| p.into()).collect::<Vec<String>>().join("."),
        );
    }};
}

#[cfg(not(feature = "debug"))]
macro_rules! vmlog {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{}};
}


// allow unreachable due to how the tailcall macro expands
#[allow(unreachable_code)]
#[tailcall]
fn vmio<'a>(vm: &PackVM, io: &'a Value, nsp: &[NamespacePart]) -> Result<Option<&'a Value>, PackerError> {
    // out-of recursion: nothing left to consume, return the current slot
    if nsp.is_empty() {
        return Ok(Some(io));
    }

    match &nsp[0] {
        // root case
        NamespacePart::Root => vmio(vm, io, &nsp[1..]),

        // array indexing
        NamespacePart::ArrayIndex => {
            if let Value::Array(arr) = io {
                let cnd_idx = vm.cndstack.len() - nsp.len();
                if let Some(cnd) = vm.cndstack.get(cnd_idx) {
                    let index = arr.len() - *cnd as usize;
                    vmio(vm, &arr[index], &nsp[1..])
                } else {
                    Ok(None)
                }
            } else {
                Err(packer_error!("expected Value::Array at {:?}, io: {:#?}", nsp, io))
            }
        }

        // struct field access
        NamespacePart::StructField(name) => {
            if let Value::Struct(_, fields) = io {
                if let Some(val) = fields.get(name) {
                    vmio(vm, val, &nsp[1..])
                } else {
                    Ok(None)
                }
            } else {
                Err(packer_error!("expected Value::Struct at {:?}, io: {:#?}", nsp, io))
            }
        }

        _ => {
            vmio(vm, io, &nsp[1..])
        }
    }
}

macro_rules! vmgetio {
    ($vm:ident, $io:ident) => {
        vmio($vm, $io, $vm.ionsp.as_slice())?
    };
}

macro_rules! vmgetio_expect {
    ($vm:ident, $io:ident, $expect:ident) => {
        vmgetio!($vm, $io).ok_or(
            packer_error!("expected vmgetio to return Some({})", stringify!($expect))
        )?
    };
}

macro_rules! vmstep {
    ($vm:ident) => {
        $vm.ip += 1;
    };
}

macro_rules! vmpack {
    ($vm:ident, $buf:ident, $val:expr) => {
        $buf.extend_from_slice($val);
    };
}

macro_rules! impl_pack_op {
    ($( ($fname:ident, $variant:ident, $dbg:literal) ),* $(,)?) => {$(
        #[inline(always)]
        pub fn $fname(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
            let val = vmgetio_expect!(vm, io, $variant);
            match val {
                Value::$variant(v) => {
                    vmpack!(
                        vm,
                        buffer,
                        v.to_le_bytes().as_ref()
                    );
                    vmstep!(vm);
                }
                _ => { return type_mismatch!(stringify!($variant), val) },
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
pub fn boolean(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let val = vmgetio_expect!(vm, io, Bool);
    match val {
        Value::Bool(v) => {
            let flag = match v {
                true => &TRUE_BYTES,
                false => &FALSE_BYTES,
            };
            vmpack!(vm, buffer, flag);
            vmstep!(vm);
        }
        _ => return type_mismatch!("VarUInt32", val)
    }
    vmlog!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varuint32(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let val = vmgetio_expect!(vm, io, VarUInt32);
    match val {
        Value::VarUInt32(v) => {
            let (raw, size) = VarUInt32(*v).encode();
            vmpack!(vm, buffer, &raw[..size]);
            vmstep!(vm);
        }
        _ => return type_mismatch!("VarUInt32", val)
    }
    vmlog!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varint32(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let val = vmgetio_expect!(vm, io, VarInt32);
    match val {
        Value::VarInt32(v) => {
            let (raw, size) = VarInt32(*v).encode();
            vmpack!(vm, buffer, &raw[..size]);
            vmstep!(vm);
        }
        _ => return type_mismatch!("VarUInt32", val)
    }
    vmlog!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let val = vmgetio_expect!(vm, io, Float128);
    match val {
        Value::Float128(v) => {
            vmpack!(vm, buffer, v);
            vmstep!(vm);
        }
        _ => return type_mismatch!("Float128", val)
    }
    vmlog!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let val = vmgetio_expect!(vm, io, Bytes);
    match val {
        Value::Bytes(v) => {
            let (size_raw, size_len) = VarUInt32(v.len() as u32).encode();
            let mut array = Vec::with_capacity(size_len + v.len());
            array.extend_from_slice(&size_raw[..size_len]);
            array.extend_from_slice(&v);
            vmpack!(vm, buffer, array.as_slice());
            vmstep!(vm);
        }
        _ => return type_mismatch!("Bytes", val)
    }
    vmlog!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>, len: u8) -> OpResult {
    let val = vmgetio_expect!(vm, io, BytesRaw);
    match val {
        Value::Bytes(v) => {
            if len > 0 && v.len() != len as usize {
                return Err(packer_error!("Raw bytes fixed size mistmatch: {} != {}", v.len(), len))
            }
            vmpack!(vm, buffer, v);
            vmstep!(vm);
        }
        _ => return type_mismatch!("Bytes", val)
    }
    vmlog!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let b = match vmgetio_expect!(vm, io, Optional) {
        Value::None => {
            vm.ip += 2;   // jump over wrapped code
            vmlog!(vm, "optional none", "()");
            0u8
        }
        _ => {
            vm.ip += 1;                     // execute wrapped code next
            vmlog!(vm, "optional some", "()");
            1u8
        }
    };
    buffer.push(b);
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut PackVM, io: &Value) -> OpResult {
    match vmgetio!(vm, io) {
        Some(Value::None) => {
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
pub fn pushcnd(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>, ctype: u8) -> OpResult {
    let val = vmgetio_expect!(vm, io, AnyPushCND);
    let cnd: u32 = match val {
        Value::Array(values) => {
            vm.ionsp.push(NamespacePart::ArrayNode);
            vm.ionsp.push(NamespacePart::ArrayIndex);
            values.len() as u32
        }
        Value::Struct(name, fields) => {
            let type_field = fields.get("type")
                .ok_or(packer_error!("Cant find type field in enum struct {}: {:?}", name, fields))?;

            match type_field {
                Value::Uint32(cnd) => {
                    *cnd
                }
                _ => return type_mismatch!("Enum variant id Value::UInt32", val)
            }
        }
        _ => {
            return match ctype {
                0u8 => {
                    type_mismatch!("Array", val)
                }
                1u8 => {
                    type_mismatch!("Struct", val)
                }
                _ => unreachable!()
            }
        }
    };

    vm.cndstack.push(cnd);
    let (size_raw, size_len) = VarUInt32(cnd).encode();
    vmpack!(vm, buffer, &size_raw[..size_len]);
    vmstep!(vm);
    vmlog!(vm, "pushcnd", "({}) io -> {}", ctype, vm.cndstack.last().unwrap());
    Ok(())
}

#[tailcall]
pub fn exec(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> Result<(), PackerError> {
    match vm.executable.code[vm.ip] {
        Instruction::Bool => { boolean(vm, io, buffer)?; exec(vm, io, buffer) }

        Instruction::UInt {size} => {
            match size {
                1 => { uint8(vm, io, buffer)?; exec(vm, io, buffer) },
                2 => { uint16(vm, io, buffer)?; exec(vm, io, buffer) },
                4 => { uint32(vm, io, buffer)?; exec(vm, io, buffer) },
                8 => { uint64(vm, io, buffer)?; exec(vm, io, buffer) },
                16 => { uint128(vm, io, buffer)?; exec(vm, io, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Int {size} => {
            match size {
                1 => { int8(vm, io, buffer)?; exec(vm, io, buffer) },
                2 => { int16(vm, io, buffer)?; exec(vm, io, buffer) },
                4 => { int32(vm, io, buffer)?; exec(vm, io, buffer) },
                8 => { int64(vm, io, buffer)?; exec(vm, io, buffer) },
                16 => { int128(vm, io, buffer)?; exec(vm, io, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::VarUInt => { varuint32(vm, io, buffer)?; exec(vm, io, buffer) }
        Instruction::VarInt => { varint32(vm, io, buffer)?; exec(vm, io, buffer) },

        Instruction::Float {size} => {
            match size {
                4 => { float32(vm, io, buffer)?; exec(vm, io, buffer) },
                8 => { float64(vm, io, buffer)?; exec(vm, io, buffer) },
                16 => { float128(vm, io, buffer)?; exec(vm, io, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Bytes => { bytes(vm, io, buffer)?; exec(vm, io, buffer) }
        Instruction::BytesRaw{ size } => { bytes_raw(vm, io, buffer, size)?; exec(vm, io, buffer) }

        Instruction::Optional => { optional(vm, io, buffer)?; exec(vm, io, buffer) }
        Instruction::Extension => { extension(vm, io)?; exec(vm, io, buffer) }

        Instruction::PushCND(ctype) => { pushcnd(vm, io, buffer, ctype)?; exec(vm, io, buffer) }
        Instruction::PopCND => { popcnd!(vm)?; exec(vm, io, buffer) }
        Instruction::Jmp{ ptr} => { jmp!(vm, ptr)?; exec(vm, io, buffer) }
        Instruction::JmpRet{ptr} => { jmpret!(vm, ptr); exec(vm, io, buffer) }
        Instruction::JmpArrayCND(ptr) => { jmpacnd!(vm, ptr)?; exec(vm, io, buffer) }
        Instruction::JmpStructCND(variant, ptr) => { jmpscnd!(vm, variant, ptr)?; exec(vm, io, buffer) }
        Instruction::Exit => {
            if exit!(vm)? {
                Ok(())
            } else {
                exec(vm, io, buffer)
            }
        }
        Instruction::Section(ctype, name) => { section!(vm, ctype, name); exec(vm, io, buffer) },
        Instruction::Field(name) => { field!(vm, name); exec(vm, io, buffer) },
    }
}