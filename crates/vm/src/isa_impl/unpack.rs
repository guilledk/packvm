use tailcall::tailcall;
use crate::{exit, jmp, jmpcnd, jmpnotcnd, packer_error, popcnd, jmpret, raise};
use crate::{
    utils::{
        PackerError,
        varint::{VarUInt32, VarInt32}
    },
    isa_impl::common::OpResult,
    Value,
    Instruction,
    UnpackVM
};

#[cfg(feature = "debug")]
macro_rules! vmlog {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) sp({:4}) csp({:4}) cnd({:4}) | {:80} | s: {:?}",
            $vm.ip,
            $vm.iostack.len(),
            $vm.csp,
            $vm.cndstack.last().unwrap_or(&-1),
            &format!("{}{}", $instr, format_args!($($args)*)),
            $vm.iostack.last(),
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
            let val = $ty::from_le_bytes(
                buf.try_into()
                    .map_err(|e| packer_error!("while unpacking {}: {}", stringify!($ty), e))?,
            );

            vm.iostack.push(Value::$variant(val));

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
pub fn boolean(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let val = match buffer[vm.bp] {
        0u8 => false,
        1u8 => true,
        _ => unreachable!()
    };
    vm.iostack.push(Value::Bool(val));
    vm.bp += 1;
    vmstep!(vm);
    vmlog!(vm, "bool", "()");
    Ok(())
}

#[inline(always)]
pub fn varuint32(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let (val, val_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("{}", e))?;
    vm.iostack.push(Value::VarUInt32(val.0));
    vm.bp += val_size;
    vmstep!(vm);
    vmlog!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn varint32(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let (val, val_size) = VarInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("{}", e))?;
    vm.iostack.push(Value::VarInt32(val.0));
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

    vm.iostack.push(Value::Float128(float_raw));
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
    vm.iostack.push(Value::Bytes(raw.to_vec()));
    vmstep!(vm);
    vmlog!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut UnpackVM, len: u8, buffer: &[u8]) -> OpResult {
    let raw = vmunpack!(vm, buffer, len as usize);
    vm.iostack.push(Value::Bytes(raw.to_vec()));
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
        vm.iostack.push(Value::None);
        vm.ip += 2;
        vmlog!(vm, "optional none", "()");
    }
    vm.bp += 1;
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    if vm.bp == buffer.len() {
        vm.iostack.push(Value::None);
        vm.ip += 2;
        vmlog!(vm, "extension stack empty", "()");
    } else {
        vm.ip += 1;
        vmlog!(vm, "extension", "()");
    }
    Ok(())
}

#[inline(always)]
pub fn pushcnd(vm: &mut UnpackVM, buffer: &[u8]) -> OpResult {
    let (cnd, cnd_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes cnd: {}", e))?;

    vm.bp += cnd_size;
    let cnd = cnd.0 as isize;
    vm.iostack.push(Value::Condition(cnd));
    vm.cndstack.push(cnd);
    vm.csp += 1;
    vmstep!(vm);
    vmlog!(vm, "pushcnd", "io -> ({})", cnd);
    Ok(())
}

#[tailcall]
#[cfg_attr(not(feature = "debug"), allow(unused_variables))]
pub fn exec(vm: &mut UnpackVM, buffer: &[u8]) -> Result<(), PackerError> {
    match &vm.program.code[vm.ip] {
        Instruction::Bool => { boolean(vm, buffer)?; exec(vm, buffer) }

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
        Instruction::Section(name) => { Err(packer_error!("Reached section instruction: {}", name))},
        Instruction::ProgramJmp{..} => { Err(packer_error!("Reached program jmp instruction")) },
    }
}
