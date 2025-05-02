use std::collections::HashMap;
use tailcall::tailcall;
use crate::{exit, jmp, jmpcnd, jmpnotcnd, packer_error, popcnd, jmpret, section, field};
use crate::{
    utils::{
        PackerError,
        varint::{VarUInt32, VarInt32}
    },
    runtime::NamespacePart,
    isa_impl::common::OpResult,
    Value,
    Instruction,
    UnpackVM
};

#[cfg(feature = "debug")]
macro_rules! vmlog {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) cnd({:4}) bp({:4}) | {:80} | ionsp: {}",
            $vm.ip,
            $vm.cndstack.last().unwrap_or(&-1),
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
            if let Value::Struct(_, ref mut fields) = io {
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

        NamespacePart::StructNode(_ctype, name) => {
            if let Value::None = io {
                *io = Value::Struct(name.clone(), HashMap::new());
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

macro_rules! impl_unpack_op {
    ($( ($fname:ident, $ty:ident, $variant:ident, $dbg:literal) ),* $(,)?) => {$(
        #[inline(always)]
        pub fn $fname(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
            let buf = vmunpack!(vm, buffer, size_of::<$ty>());
            let num = $ty::from_le_bytes(
                buf.try_into()
                    .map_err(|e| packer_error!("while unpacking {}: {}", stringify!($ty), e))?,
            );
            vmsetio!(vm, Value::$variant(num));
            vmstep!(vm);
            vmlog!(vm, $dbg, "()");
            Ok(())
        }
    )*};
}

impl_unpack_op!(
    (uint8,   u8,       Uint8,   "uint8"),
    (uint16,  u16,      Uint16,  "uint16"),
    (uint32,  u32,      Uint32,  "uint32"),
    (uint64,  u64,      Uint64,  "uint64"),
    (uint128, u128,     Uint128, "uint128"),

    (int8,    i8,       Int8,    "int8"),
    (int16,   i16,      Int16,   "int16"),
    (int32,   i32,      Int32,   "int32"),
    (int64,   i64,      Int64,   "int64"),
    (int128,  i128,     Int128,  "int128"),

    (float32, f32,      Float32, "float32"),
    (float64, f64,      Float64, "float64"),
);

#[inline(always)]
pub fn boolean(vm: &mut UnpackVM, buffer: &[u8]) -> Result<(), PackerError> {
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
pub fn varuint32(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let (varint, val_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("{}", e))?;
    vmsetio!(vm, Value::VarUInt32(varint.0));
    vm.bp += val_size;
    vmstep!(vm);
    vmlog!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varint32(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let (val, val_size) = VarInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("{}", e))?;
    vmsetio!(vm, Value::VarInt32(val.0));
    vm.bp += val_size;
    vmstep!(vm);
    vmlog!(vm, "varint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let float_raw: [u8; 16] = vmunpack!(vm, buffer, 16)
        .try_into()
        .map_err(|e| packer_error!("{}", e))?;

    vmsetio!(vm, Value::Float128(float_raw));
    vm.bp += 16;
    vmstep!(vm);
    vmlog!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
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
pub fn bytes_raw(vm: &mut UnpackVM, len: u8, buffer: &[u8]) -> OpResult {
    let raw = vmunpack!(vm, buffer, len as usize);
    vmsetio!(vm, Value::Bytes(raw.to_vec()));
    vmstep!(vm);
    vmlog!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
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
pub fn extension(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
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
pub fn pushcnd(vm: &mut UnpackVM, buffer: &[u8], ctype: &u8) -> OpResult {
    let (cnd, cnd_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes cnd: {}", e))?;
    vm.bp += cnd_size;
    let cnd = cnd.0 as isize;
    vm.cndstack.push(cnd);

    match ctype {
        0u8 => {
            vm.ionsp.push(NamespacePart::ArrayNode);
            vm.ionsp.push(NamespacePart::ArrayIndex);
        }
        1u8 => {
            let val = vmgetio!(vm);
            match val {
                Value::Struct(_name, values) => {
                    values.insert("type".to_string(), Value::Uint32(cnd as u32));
                }
                _ => return Err(packer_error!("expected struct to be target value but got: {}", val)),
            }
        }
        _ => return Err(packer_error!("invalid ctype {}", ctype)),
    }

    vmstep!(vm);
    vmlog!(vm, "pushcnd", "({}) io -> {}", ctype, vm.cndstack.last().unwrap());
    Ok(())
}

#[tailcall]
pub fn exec(vm: &mut UnpackVM, buffer: &[u8]) -> Result<(), PackerError> {
    match &vm.executable.code[vm.ip] {
        Instruction::Bool => { boolean(vm, buffer).map_err(|e| packer_error!("{}\nVM state: {:?}", e.to_string(), vm.ionsp))?; exec(vm, buffer) }

        Instruction::UInt{ size} => {
            match size {
                1 => { uint8(vm, buffer)?; exec(vm, buffer) }
                2 => { uint16(vm, buffer)?; exec(vm, buffer) }
                4 => { uint32(vm, buffer)?; exec(vm, buffer) }
                8 => { uint64(vm, buffer)?; exec(vm, buffer) }
                16 => { uint128(vm, buffer)?; exec(vm, buffer) }
                _ => unreachable!()
            }
        }

        Instruction::Int{ size} => {
            match size {
                1 => { int8(vm, buffer)?; exec(vm, buffer) }
                2 => { int16(vm, buffer)?; exec(vm, buffer) }
                4 => { int32(vm, buffer)?; exec(vm, buffer) }
                8 => { int64(vm, buffer)?; exec(vm, buffer) }
                16 => { int128(vm, buffer)?; exec(vm, buffer) }
                _ => unreachable!()
            }
        }

        Instruction::VarUInt => { varuint32(vm, buffer)?; exec(vm, buffer) }
        Instruction::VarInt => { varint32(vm, buffer)?; exec(vm, buffer) },

        Instruction::Float { size } => {
            match size {
                4 => { float32(vm, buffer)?; exec(vm, buffer) },
                8 => { float64(vm, buffer)?; exec(vm, buffer) },
                16 => { float128(vm, buffer)?; exec(vm, buffer) },
                _ => unreachable!()
            }
        }

        Instruction::Bytes => { bytes(vm, buffer)?; exec(vm, buffer) }
        Instruction::BytesRaw{ size } => { bytes_raw(vm, *size, buffer)?; exec(vm, buffer) }

        Instruction::Optional => { optional(vm, buffer)?; exec(vm, buffer) }
        Instruction::Extension => { extension(vm, buffer)?; exec(vm, buffer) }

        Instruction::PushCND(ctype) => { pushcnd(vm, buffer, ctype)?; exec(vm, buffer) }
        Instruction::PopCND => { popcnd!(vm)?; exec(vm, buffer) }
        Instruction::Jmp{ ptr} => { jmp!(vm, *ptr)?; exec(vm, buffer) }
        Instruction::JmpRet{ptr} => { jmpret!(vm, *ptr); exec(vm, buffer) }
        Instruction::JmpCND{ ptrdelta: target, value, delta} => { jmpcnd!(vm, *target, *value, *delta)?; exec(vm, buffer) }
        Instruction::JmpNotCND{ ptrdelta: target, value, delta} => { jmpnotcnd!(vm, *target, *value, *delta)?; exec(vm, buffer) }
        Instruction::Exit => {
            if exit!(vm)? {
                Ok(())
            } else {
                exec(vm, buffer)
            }
        }
        Instruction::Section(ctype, name) => { section!(vm, *ctype, name); exec(vm, buffer) },
        Instruction::Field(name) => { field!(vm, name); exec(vm, buffer) },
    }
}
