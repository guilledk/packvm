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
        Err(packer_error!("Expected {}, got {:?}", $expected, $got))
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
            if let Value::Struct(fields) = io {
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

#[inline(always)]
pub fn integer(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>, size: u8, signed: bool) -> OpResult {
    let val = vmgetio_expect!(vm, io, Int);
    match val {
        Value::Int(num) => {
            if signed {
                match size {
                    1 => {
                        let num = num.as_i64().unwrap() as i8;
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    2 => {
                        let num = num.as_i64().unwrap() as i16;
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    4 => {
                        let num = num.as_i64().unwrap() as i32;
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    8 => {
                        let num = num.as_i64().unwrap();
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    _ => unreachable!(),
                }
            } else {
                match size {
                    1 => {
                        let num = num.as_u64().unwrap() as u8;
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    2 => {
                        let num = num.as_u64().unwrap() as u16;
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    4 => {
                        let num = num.as_u64().unwrap() as u32;
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    8 => {
                        let num = num.as_u64().unwrap();
                        vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                    }
                    _ => unreachable!(),
                }
            }
        }
        _ => return type_mismatch!("Int", val)
    }
    vmstep!(vm);
    vmlog!(vm, "int", "({}, {})", size, signed);
    Ok(())
}

#[inline(always)]
pub fn long(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>, signed: bool) -> OpResult {
    let val = vmgetio_expect!(vm, io, Long);
    match val {
        Value::Long(num) => {
            if signed {
                let num = num.as_i128().unwrap();
                vmpack!(vm, buffer, num.to_le_bytes().as_ref());
            } else {
                let num = num.as_u128().unwrap();
                vmpack!(vm, buffer, num.to_le_bytes().as_ref());
            }
        }
        _ => return type_mismatch!("Long", val)
    }
    vmstep!(vm);
    vmlog!(vm, "long", "({})", signed);
    Ok(())
}

#[inline(always)]
pub fn float(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>, size: u8) -> OpResult {
    let val = vmgetio_expect!(vm, io, Float);
    match val {
        Value::Float(num) => {
            match size {
                4 => {
                    let num: f32 = num.as_f32().unwrap();
                    vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                }
                8 => {
                    let num: f64 = num.as_f64();
                    vmpack!(vm, buffer, num.to_le_bytes().as_ref());
                }
                _ => unreachable!(),
            }
        }
        _ => return type_mismatch!("Int", val)
    }
    vmstep!(vm);
    vmlog!(vm, "float", "({})", size);
    Ok(())
}

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
pub fn string(vm: &mut PackVM, io: &Value, buffer: &mut Vec<u8>) -> OpResult {
    let val = vmgetio_expect!(vm, io, String);
    match val {
        Value::String(s) => {
            let (size_raw, size_len) = VarUInt32(s.len() as u32).encode();
            let mut array = Vec::with_capacity(size_len + s.len());
            array.extend_from_slice(&size_raw[..size_len]);
            array.extend_from_slice(s.as_bytes());
            vmpack!(vm, buffer, array.as_slice());
            vmstep!(vm);
        }
        _ => return type_mismatch!("String", val)
    }
    vmlog!(vm, "string", "()");
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
        Value::Struct(fields) => {
            let type_field = fields.get("type")
                .ok_or(packer_error!("Cant find type field in enum struct: {:?}", fields))?;

            match type_field {
                Value::Int(cnd) => {
                    cnd.as_u64().unwrap() as u32
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
            if size == 16 {
                long(vm, io, buffer, false)?
            } else {
                integer(vm, io, buffer, size, false)?
            };
            exec(vm, io, buffer)
        }
        Instruction::Int {size} => {
            if size == 16 {
                long(vm, io, buffer, true)?
            } else {
                integer(vm, io, buffer, size, true)?
            };
            exec(vm, io, buffer)
        }

        Instruction::VarUInt => { varuint32(vm, io, buffer)?; exec(vm, io, buffer) }
        Instruction::VarInt => { varint32(vm, io, buffer)?; exec(vm, io, buffer) },

        Instruction::Float {size} => {
            match size {
                4 | 8 => { float(vm, io, buffer, size)?; exec(vm, io, buffer) },
                16 => { float128(vm, io, buffer)?; exec(vm, io, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Bytes => { bytes(vm, io, buffer)?; exec(vm, io, buffer) }
        Instruction::BytesRaw{ size } => { bytes_raw(vm, io, buffer, size)?; exec(vm, io, buffer) }
        Instruction::String => { string(vm, io, buffer)?; exec(vm, io, buffer) }

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
        #[cfg_attr(not(feature = "debug"), allow(unused_variables))]
        Instruction::Section(ctype, id) => { section!(vm, ctype, id); exec(vm, io, buffer) },
        Instruction::Field(name) => { field!(vm, name); exec(vm, io, buffer) },
    }
}