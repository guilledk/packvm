#![allow(clippy::match_same_arms)]

use crate::isa::DataInstruction;
use crate::utils::numbers::U48;
use crate::{
    debug_log, exit, field,
    isa_impl::common::OpResult,
    jmp, jmpacnd, jmpret, jmptrap, packer_error, popcursor,
    utils::varint::{VarInt32, VarUInt32},
    Instruction, PackVM, Value,
};

macro_rules! vmgetio {
    ($vm:ident) => {{
        let cnd = $vm.cnd();
        let val = $vm.cursor.current();
        match val {
            Value::Array(arr) if cnd > 0 => {
                let idx = arr.len() - cnd as usize;
                Ok(&arr[idx])
            }
            Value::Struct(map) if $vm.fp != U48(0) => {
                let fname =
                    $vm.executable
                        .str_map
                        .get_by_left(&$vm.fp)
                        .ok_or(crate::packer_error!(
                            "Failed to resolve struct field name from id: {}",
                            $vm.fp
                        ))?;

                map.get(fname).ok_or(packer_error!(
                    "Failed to get field from id: {}, {}: {:#?}",
                    $vm.fp,
                    fname,
                    map
                ))
            }
            _ => Ok(val),
        }
    }};
}

macro_rules! vmgetio_mut {
    ($vm:ident) => {{
        let cnd = $vm.cnd();
        let val = $vm.cursor.current_mut();
        match val {
            Value::Array(arr) if cnd > 0 => {
                let idx = arr.len() - cnd as usize;
                Ok(&mut arr[idx])
            }
            Value::Struct(map) if $vm.fp != U48(0) => {
                let fname =
                    $vm.executable
                        .str_map
                        .get_by_left(&$vm.fp)
                        .ok_or(crate::packer_error!(
                            "Failed to resolve struct field name from id: {}",
                            $vm.fp
                        ))?;

                map.get_mut(fname).ok_or(packer_error!(
                    "Failed to get field from id: {}, {}",
                    $vm.fp,
                    fname
                ))
            }
            _ => Ok(val),
        }
    }};
}

/// Current slot, but ensure it is of the expected variant.
macro_rules! vmgetio_expect {
    ($vm:ident, $variant:pat_param, $name:literal) => {{
        let v = vmgetio!($vm)?;
        if !matches!(v, $variant) {
            return Err(packer_error!("Expected {}, got {:?}", $name, v));
        }
        v
    }};
}

/// Advance the instruction pointer by 1.
macro_rules! vmstep {
    ($vm:ident) => {
        $vm.ip += 1;
    };
}

/// Append raw bytes to the output buffer.
macro_rules! vmpack {
    ($vm:ident, $buf:ident, $bytes:expr) => {{
        $buf.extend_from_slice($bytes);
        $vm.bp = $buf.len() - 1;
    }};
}

#[inline(always)]
fn integer(vm: &mut PackVM, buf: &mut Vec<u8>, size: u8, signed: bool) -> OpResult {
    let val = vmgetio_expect!(vm, Value::Int(_), "Int");
    let n = match val {
        Value::Int(n) => n,
        _ => unreachable!(),
    };

    if signed {
        match size {
            1 => vmpack!(vm, buf, &(n.as_i64().unwrap() as i8).to_le_bytes()),
            2 => vmpack!(vm, buf, &(n.as_i64().unwrap() as i16).to_le_bytes()),
            4 => vmpack!(vm, buf, &(n.as_i64().unwrap() as i32).to_le_bytes()),
            8 => vmpack!(vm, buf, &n.as_i64().unwrap().to_le_bytes()),
            _ => unreachable!(),
        }
    } else {
        match size {
            1 => vmpack!(vm, buf, &(n.as_u64().unwrap() as u8).to_le_bytes()),
            2 => vmpack!(vm, buf, &(n.as_u64().unwrap() as u16).to_le_bytes()),
            4 => vmpack!(vm, buf, &(n.as_u64().unwrap() as u32).to_le_bytes()),
            8 => vmpack!(vm, buf, &n.as_u64().unwrap().to_le_bytes()),
            _ => unreachable!(),
        }
    }

    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn long(vm: &mut PackVM, buf: &mut Vec<u8>, signed: bool) -> OpResult {
    let val = vmgetio_expect!(vm, Value::Long(_), "Long");
    let n = match val {
        Value::Long(n) => n,
        _ => unreachable!(),
    };

    if signed {
        vmpack!(vm, buf, &n.as_i128().unwrap().to_le_bytes());
    } else {
        vmpack!(vm, buf, &n.as_u128().unwrap().to_le_bytes());
    }
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn boolean(vm: &mut PackVM, buf: &mut Vec<u8>) -> OpResult {
    let v = vmgetio_expect!(vm, Value::Bool(_), "Bool");
    let b = matches!(v, Value::Bool(true)) as u8;
    buf.push(b);
    vm.bp += 1;
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn float(vm: &mut PackVM, buf: &mut Vec<u8>, size: u8) -> OpResult {
    let val = vmgetio_expect!(vm, Value::Float(_), "Float");
    match (val, size) {
        (Value::Float(n), 4) => vmpack!(vm, buf, &(n.as_f32().unwrap()).to_le_bytes()),
        (Value::Float(n), 8) => vmpack!(vm, buf, &(n.as_f64()).to_le_bytes()),
        _ => return Err(packer_error!("Invalid float size/type")),
    };
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn leb128(vm: &mut PackVM, buf: &mut Vec<u8>, signed: bool) -> OpResult {
    let val = vmgetio_expect!(vm, Value::Int(_), "Int");
    let n = match val {
        Value::Int(n) => n,
        _ => unreachable!(),
    };
    let (raw, len) = if signed {
        VarInt32(
            n.as_i64()
                .ok_or(packer_error!("Expected a signed int for sleb128"))? as i32,
        )
        .encode()
    } else {
        VarUInt32(
            n.as_u64()
                .ok_or(packer_error!("Expected a signed int for sleb128"))? as u32,
        )
        .encode()
    };
    vmpack!(vm, buf, &raw[..len]);
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn bytes(vm: &mut PackVM, buf: &mut Vec<u8>) -> OpResult {
    let v = vmgetio_expect!(vm, Value::Bytes(_), "Bytes");
    let bytes = if let Value::Bytes(b) = v {
        b
    } else {
        unreachable!()
    };

    let (size_raw, size_len) = VarUInt32(bytes.len() as u32).encode();
    vmpack!(vm, buf, &size_raw[..size_len]);
    vmpack!(vm, buf, &bytes);

    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn string(vm: &mut PackVM, buf: &mut Vec<u8>) -> OpResult {
    let v = vmgetio_expect!(vm, Value::String(_), "String");
    let s = if let Value::String(s) = v {
        s
    } else {
        unreachable!()
    };

    let (size_raw, size_len) = VarUInt32(s.len() as u32).encode();
    vmpack!(vm, buf, &size_raw[..size_len]);
    vmpack!(vm, buf, s.as_bytes());

    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn bytes_raw(vm: &mut PackVM, buf: &mut Vec<u8>, len: U48) -> OpResult {
    let v = vmgetio_expect!(vm, Value::Bytes(_), "Bytes");
    let bytes = if let Value::Bytes(b) = v {
        b
    } else {
        unreachable!()
    };

    if len.0 != 0 && bytes.len() != len.0 as usize {
        return Err(packer_error!(
            "Raw bytes fixed-size mismatch: {} != {}",
            bytes.len(),
            len
        ));
    }
    vmpack!(vm, buf, &bytes);
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn optional(vm: &mut PackVM, buf: &mut Vec<u8>) -> OpResult {
    match vmgetio!(vm)? {
        Value::None => {
            buf.push(0);
            vm.ip += 2; // skip wrapped ops
        }
        _ => {
            buf.push(1);
            vmstep!(vm); // run wrapped ops next
        }
    }
    vm.bp += 1;
    Ok(())
}

#[inline(always)]
fn extension(vm: &mut PackVM) -> OpResult {
    match vmgetio!(vm)? {
        Value::None => {
            vm.ip += 2; // skip inner ops
        }
        _ => {
            vmstep!(vm);
        }
    }
    Ok(())
}

#[inline(always)]
fn pushcnd(vm: &mut PackVM, buf: &mut Vec<u8>) -> OpResult {
    let cnd = {
        let mut child_ptr: *mut Value = std::ptr::null_mut();
        let slot = vmgetio_mut!(vm)?;
        let cnd = match slot {
            Value::Array(arr) => {
                if !arr.is_empty() {
                    let cnd = arr.len() as u32;
                    vmstep!(vm);
                    child_ptr = slot as *mut _;
                    cnd
                } else {
                    let next_popcur = vm.executable.code[usize::from(vm.ip)..]
                        .iter()
                        .position(|op| op.cmp_type(&Instruction::PopCursor))
                        .ok_or(packer_error!("Can't find next CND pop"))?;

                    vm.ip += U48::from(next_popcur + 1);
                    0
                }
            }
            v => return Err(packer_error!("Expected Array, got {:?}", v)),
        };

        if !child_ptr.is_null() {
            unsafe { vm.cursor.push(child_ptr) };
        }

        cnd
    };

    if cnd > 0 {
        vm.push_cnd(cnd);
    }

    let (raw, len) = VarUInt32(cnd).encode();
    vmpack!(vm, buf, &raw[..len]);

    Ok(())
}

#[inline(always)]
#[cfg_attr(not(feature = "debug"), allow(unused_variables))]
fn section(vm: &mut PackVM, buf: &mut Vec<u8>, ctype: u8, sid: U48) -> OpResult {
    vm.ip += 1;

    if ctype == 0 {
        return Ok(());
    }

    let child_ptr: *mut Value;

    {
        let slot = vmgetio_mut!(vm)?;
        match slot {
            Value::Struct(map) => {
                if ctype == 1 {
                    /* enum-struct: encode the variant id */
                    let type_field = map.get("type").ok_or_else(|| {
                        packer_error!("enum struct missing `type` field: {:?}", map)
                    })?;

                    let variant_id = match type_field {
                        Value::String(var_name) => vm
                            .executable
                            .var_map
                            .get(&sid)
                            .ok_or(packer_error!("Could not find sid: {sid} in var map!"))?
                            .iter()
                            .position(|v| v == var_name)
                            .ok_or(packer_error!(
                                "Could not find variant name {var_name} in vars!"
                            ))?,
                        Value::Int(n) => n.as_u64().unwrap() as usize,
                        _ => return Err(packer_error!("`type` field is not Int")),
                    };

                    let (raw, len) = VarUInt32(variant_id as u32).encode();
                    buf.extend_from_slice(&raw[..len]);

                    if variant_id > 0 {
                        vm.ip += U48::from(2 * variant_id);
                    }
                }
            }
            _ => return Err(packer_error!("section: expected Struct, got {:?}", slot)),
        }
        child_ptr = slot as *mut _;
    }

    if ctype == 2 {
        unsafe { vm.cursor.push(child_ptr) };
    }

    Ok(())
}
pub fn exec(vm: &mut PackVM, buf: &mut Vec<u8>) -> OpResult {
    'dispatch: loop {
        debug_assert!(vm.ip.0 < vm.executable.code.len() as u64);
        debug_log!("{:?}", vm);
        let inst = unsafe { *vm.executable.code.get_unchecked(vm.ip.0 as usize) };

        match inst {
            Instruction::IO(op) => match op {
                DataInstruction::Bool => boolean(vm, buf)?,
                DataInstruction::UInt(16) => long(vm, buf, false)?,
                DataInstruction::UInt(size) => integer(vm, buf, size, false)?,
                DataInstruction::Int(16) => long(vm, buf, true)?,
                DataInstruction::Int(size) => integer(vm, buf, size, true)?,
                DataInstruction::Float(size) => float(vm, buf, size)?,
                DataInstruction::Leb128(signed) => leb128(vm, buf, signed)?,
                DataInstruction::Bytes => bytes(vm, buf)?,
                DataInstruction::BytesRaw(size) => bytes_raw(vm, buf, size)?,
                DataInstruction::String => string(vm, buf)?,
            },
            Instruction::Optional => optional(vm, buf)?,
            Instruction::Extension => extension(vm)?,
            Instruction::Section(ty, id) => section(vm, buf, ty, id)?,
            Instruction::PushCND => pushcnd(vm, buf)?,
            Instruction::PopCursor => popcursor!(vm)?,
            Instruction::Jmp(dst) => jmp!(vm, dst)?,
            Instruction::JmpRet(dst) => jmpret!(vm, dst),
            Instruction::JmpArrayCND => jmpacnd!(vm)?,
            Instruction::JmpTrap => jmptrap!(vm),
            Instruction::Field(name) => field!(vm, name),
            Instruction::Exit => {
                if exit!(vm)? {
                    break 'dispatch;
                }
            }
        }
    }
    Ok(())
}
