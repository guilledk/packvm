use std::collections::HashMap;
use tailcall::tailcall;
use crate::{exit, jmp, packer_error, popcnd, jmpret, section, field, jmpacnd, jmpscnd};
use crate::{
    utils::{
        PackerError,
        varint::{VarUInt32, VarInt32}
    },
    runtime::NamespacePart,
    isa_impl::common::OpResult,
    Value,
    Instruction,
    PackVM
};
use crate::utils::numbers::{Float, Integer, Long};

#[cfg(feature = "debug")]
macro_rules! vmlog {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) cnd({:4}) bp({:4}) | {:80} | ionsp: {}",
            $vm.ip,
            $vm.cndstack.last().unwrap(),
            $vm.bp,
            &format!("{}{}", $instr, format_args!($($args)*)),
            $vm.ionsp.iter().map(|p| p.into()).collect::<Vec<String>>().join("."),
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
    };
}

/// Walk `io` following `nsp`, materialising intermediate containers
/// (`Value::Array` / `Value::Struct`) when they don’t exist yet, and
/// return a *mutable* reference to the final slot.
// allow unreachable due to how the tailcall macro expands
#[allow(unreachable_code)]
#[tailcall]
fn vmiomut<'a>(io: &'a mut Value, nsp: &[NamespacePart]) -> &'a mut Value {
    // out-of recursion: nothing left to consume, return the current slot
    if nsp.is_empty() {
        return io;
    }

    match &nsp[0] {
        // root case
        NamespacePart::Root => vmiomut(io, &nsp[1..]),

        // array indexing
        NamespacePart::ArrayIndex => {
            if let Value::Array(ref mut arr) = io {
                let idx = arr.len();
                arr.push(Value::None);
                vmiomut(&mut arr[idx], &nsp[1..])
            } else {
                panic!("expected Value::Array at {:?}, io: {:#?}", nsp, io);
            }
        }

        // struct field access
        NamespacePart::StructField(name) => {
            if let Value::Struct(ref mut fields) = io {
                let val = fields.entry(name.clone()).or_insert(Value::None);
                vmiomut(val, &nsp[1..])
            } else {
                panic!("expected Value::Struct at {:?} io: {:?}", nsp, io);
            }
        }

        NamespacePart::ArrayNode => {
            if let Value::None = io {
                *io = Value::Array(Vec::new());
            }
            vmiomut(io, &nsp[1..])
        }

        NamespacePart::StructNode(_ctype) => {
            if let Value::None = io {
                *io = Value::Struct(HashMap::new());
            }
            vmiomut(io, &nsp[1..])
        }
    }
}

macro_rules! vmgetio {
    ($vm:expr) => {
        vmiomut(&mut $vm.io, $vm.ionsp.as_slice())
    };
}

macro_rules! vmsetio {
    ($vm:expr, $val:expr) => {{
        let slot = vmiomut(&mut $vm.io, &$vm.ionsp);
        *slot = $val;
    }};
}

macro_rules! vmunpack {
    ($vm:ident, $buf:ident, $len:expr) => {{
        let start = $vm.bp;
        $vm.bp += $len;
        &$buf[start..start + $len]
    }}
}

#[inline(always)]
pub fn boolean(vm: &mut PackVM, buffer: &[u8]) -> Result<(), PackerError> {
    let b = match buffer[vm.bp] {
        0u8 => false,
        1u8 => true,
        _ => return Err(
            packer_error!(
                "Expected encoded boolean but got {} at buffer index {}",
                buffer[vm.bp],
                vm.bp
            )
        )
    };
    vmsetio!(vm, Value::Bool(b));
    vm.bp += 1;
    vmstep!(vm);
    vmlog!(vm, "bool", "()");
    Ok(())
}

#[inline(always)]
pub fn integer(vm: &mut PackVM, buffer: &[u8], size: u8, signed: bool) -> Result<(), PackerError> {
    let buf = vmunpack!(vm, buffer, size as usize);
    let val = if signed {
        match size {
            1 => {
                let num = i8::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            2 => {
                let num = i16::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            4 => {
                let num = i32::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            8 => {
                let num = i64::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            _ => unreachable!()
        }
    } else {
        match size {
            1 => {
                let num = u8::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            2 => {
                let num = u16::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            4 => {
                let num = u32::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            8 => {
                let num = u64::from_le_bytes(buf.try_into().unwrap());
                Value::Int(Integer::from(num))
            }
            _ => unreachable!()
        }
    };
    vmsetio!(vm, val);
    vmstep!(vm);
    vmlog!(vm, "integer", "({}, {})", size, signed);
    Ok(())
}

#[inline(always)]
pub fn long(vm: &mut PackVM, buffer: &[u8], signed: bool) -> Result<(), PackerError> {
    let buf = vmunpack!(vm, buffer, 16);
    let val = if signed {
        let num = i128::from_le_bytes(buf.try_into().unwrap());
        Value::Long(Long::from(num))
    } else {
        let num = u128::from_le_bytes(buf.try_into().unwrap());
        Value::Long(Long::from(num))
    };
    vmsetio!(vm, val);
    vmstep!(vm);
    vmlog!(vm, "long", "({})", signed);
    Ok(())
}

#[inline(always)]
pub fn float(vm: &mut PackVM, buffer: &[u8], size: u8) -> Result<(), PackerError> {
    let buf = vmunpack!(vm, buffer, size as usize);
    let val = if size == 4 {
        let num = f32::from_le_bytes(buf.try_into().unwrap());
        Value::Float(Float::from(num))
    } else {
        let num = f64::from_le_bytes(buf.try_into().unwrap());
        Value::Float(Float::from(num))
    };
    vmsetio!(vm, val);
    vmstep!(vm);
    vmlog!(vm, "float", "({})", size);
    Ok(())
}

#[inline(always)]
pub fn varuint32(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (varint, val_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("{}", e))?;
    vmsetio!(vm, Value::VarUInt32(varint.0));
    vm.bp += val_size;
    vmstep!(vm);
    vmlog!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varint32(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (val, val_size) = VarInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("{}", e))?;
    vmsetio!(vm, Value::VarInt32(val.0));
    vm.bp += val_size;
    vmstep!(vm);
    vmlog!(vm, "varint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let float_raw: [u8; 16] = vmunpack!(vm, buffer, 16)
        .try_into()
        .map_err(|e| packer_error!("{}", e))?;

    vmsetio!(vm, Value::Float128(float_raw));
    vmstep!(vm);
    vmlog!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (len, len_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes len: {}", e))?;

    vm.bp += len_size;
    let raw = vmunpack!(vm, buffer, len.0 as usize);
    vmsetio!(vm, Value::Bytes(raw.to_vec()));
    vmstep!(vm);
    vmlog!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn string(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (len, len_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes len: {}", e))?;

    vm.bp += len_size;
    let raw = vmunpack!(vm, buffer, len.0 as usize);
    vmsetio!(vm, Value::String(
        String::from_utf8(raw.to_vec())
            .map_err(|e| packer_error!("{}", e.to_string()))?
    ));
    vmstep!(vm);
    vmlog!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut PackVM, len: u8, buffer: &[u8]) -> OpResult {
    let raw = vmunpack!(vm, buffer, len as usize);
    vmsetio!(vm, Value::Bytes(raw.to_vec()));
    vmstep!(vm);
    vmlog!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    if buffer[vm.bp] == 1 {
        vm.ip += 1;
        vmlog!(vm, "optional some", "()");
    } else {
        vmsetio!(vm, Value::None);
        vm.ip += 2;
        vmlog!(vm, "optional none", "()");
    }
    vm.bp += 1;
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    if vm.bp == buffer.len() {
        vmsetio!(vm, Value::None);
        vm.ip += 2;
        vmlog!(vm, "extension stack empty", "()");
    } else {
        vm.ip += 1;
        vmlog!(vm, "extension", "()");
    }
    Ok(())
}

#[inline(always)]
pub fn pushcnd(vm: &mut PackVM, buffer: &[u8], ctype: u8) -> OpResult {
    let (cnd, cnd_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes cnd: {}", e))?;
    vm.bp += cnd_size;

    match ctype {
        0u8 => {
            if cnd.0 > 0 {
                vm.cndstack.push(cnd.0);
                vm.ionsp.push(NamespacePart::ArrayNode);
                vm.ionsp.push(NamespacePart::ArrayIndex);
                vmstep!(vm);
            } else {
                let next_popcnd = vm.executable.code[vm.ip..].iter()
                    .position(|op| match op {
                        Instruction::PopCND => true,
                        _ => false,
                    })
                    .ok_or(packer_error!("Can't find next CND pop"))?;

                vm.ip += next_popcnd + 1;
                vmsetio!(vm, Value::Array(Vec::new()));
            }
        }
        1u8 => {
            vm.cndstack.push(cnd.0);
            let val = vmgetio!(vm);
            match val {
                Value::Struct(values) => {
                    values.insert("type".to_string(), Value::Int(Integer::from(cnd.0)));
                }
                _ => return Err(packer_error!("expected struct to be target value but got: {}", val)),
            }
            vmstep!(vm);
        }
        _ => return Err(packer_error!("invalid ctype {}", ctype)),
    }

    vmlog!(vm, "pushcnd", "({}) io -> {}", ctype, vm.cndstack.last().unwrap());
    Ok(())
}

#[tailcall]
pub fn exec(vm: &mut PackVM, buffer: &[u8]) -> Result<(), PackerError> {
    match vm.executable.code[vm.ip] {
        Instruction::Bool => { boolean(vm, buffer).map_err(|e| packer_error!("{}\nVM state: {:?}", e.to_string(), vm.ionsp))?; exec(vm, buffer) }

        Instruction::UInt {size} => {
            if size == 16 {
                long(vm, buffer, false)?
            } else {
                integer(vm, buffer, size, false)?
            };
            exec(vm, buffer)
        }
        Instruction::Int {size} => {
            if size == 16 {
                long(vm, buffer, true)?
            } else {
                integer(vm, buffer, size, true)?
            };
            exec(vm, buffer)
        }

        Instruction::VarUInt => { varuint32(vm, buffer)?; exec(vm, buffer) }
        Instruction::VarInt => { varint32(vm, buffer)?; exec(vm, buffer) },

        Instruction::Float {size} => {
            match size {
                4 | 8 => { float(vm, buffer, size)?; exec(vm, buffer) },
                16 => { float128(vm, buffer)?; exec(vm, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Bytes => { bytes(vm, buffer)?; exec(vm, buffer) }
        Instruction::BytesRaw{ size } => { bytes_raw(vm, size, buffer)?; exec(vm, buffer) }
        Instruction::String => { string(vm, buffer)?; exec(vm, buffer) }

        Instruction::Optional => { optional(vm, buffer)?; exec(vm, buffer) }
        Instruction::Extension => { extension(vm, buffer)?; exec(vm, buffer) }

        Instruction::PushCND(ctype) => { pushcnd(vm, buffer, ctype)?; exec(vm, buffer) }
        Instruction::PopCND => { popcnd!(vm)?; exec(vm, buffer) }
        Instruction::Jmp{ ptr} => { jmp!(vm, ptr)?; exec(vm, buffer) }
        Instruction::JmpRet{ptr} => { jmpret!(vm, ptr); exec(vm, buffer) }
        Instruction::JmpArrayCND(ptr) => { jmpacnd!(vm, ptr)?; exec(vm, buffer) }
        Instruction::JmpStructCND(variant, ptr) => { jmpscnd!(vm, variant, ptr)?; exec(vm, buffer) }
        Instruction::Exit => {
            if exit!(vm)? {
                Ok(())
            } else {
                exec(vm, buffer)
            }
        }
        #[cfg_attr(not(feature = "debug"), allow(unused_variables))]
        Instruction::Section(ctype, id) => { section!(vm, ctype, id); exec(vm, buffer) },
        Instruction::Field(name) => { field!(vm, name); exec(vm, buffer) },
    }
}
