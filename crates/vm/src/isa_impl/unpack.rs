use crate::isa::DataInstruction;
use crate::utils::numbers::{Float, Integer, Long, U48};
use crate::{
    debug_log, exit, field, jmp, jmpacnd, jmpret, jmptrap, packer_error, popcursor,
};
use crate::{
    isa_impl::common::OpResult,
    utils::{
        varint::{VarInt32, VarUInt32},
        PackerError,
    },
    Instruction, PackVM, Value,
};
use std::collections::HashMap;

macro_rules! vmpushio {
    ($vm:ident, $val:expr) => {{
        let child_ptr: *mut Value;

        {
            let cnd = $vm.cnd();
            let val = $vm.cursor.current_mut();

            match val {
                Value::Array(arr) => {
                    let idx = arr.len() - cnd as usize;
                    let slot = &mut arr[idx];
                    *slot = $val;
                    child_ptr = slot as *mut _;
                }

                Value::Struct(map) => {
                    let fname = $vm.executable.str_map.get_by_left(&$vm.fp).ok_or_else(|| {
                        packer_error!("failed to resolve field name for id {}", $vm.fp)
                    })?;

                    let slot = map.entry(fname.to_string()).or_insert(Value::None);
                    *slot = $val;
                    child_ptr = slot as *mut _;
                }

                Value::None => {
                    *val = $val;
                    child_ptr = val as *mut _;
                }

                _ => {
                    return Err(packer_error!(
                        "section: expected array, struct, or none; got {:?}",
                        val
                    ))
                }
            }
        }

        // SAFETY: `child_ptr` lives as long as `vm.io`
        unsafe { $vm.cursor.push(child_ptr) };
    }};
}

macro_rules! vmsetio {
    ($vm:ident, $val:expr) => {{
        let cnd = $vm.cnd();
        let val = $vm.cursor.current_mut();
        match val {
            Value::Array(arr) => {
                let idx = arr.len() - cnd as usize;
                arr[idx] = $val;
            }
            Value::Struct(map) => {
                let fname =
                    $vm.executable
                        .str_map
                        .get_by_left(&$vm.fp)
                        .ok_or(crate::packer_error!(
                            "Failed to resolve struct field name from id: {}",
                            $vm.fp
                        ))?;

                map.insert(fname.to_string(), $val);
            }
            Value::None => {
                *val = $val;
            }
            _ => {
                return Err(packer_error!(
                    "Expected array struct or none but got: {:?}",
                    val
                ))
            }
        }
    }};
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
    }};
}

#[inline(always)]
fn boolean(vm: &mut PackVM, buffer: &[u8]) -> Result<(), PackerError> {
    let b = match buffer[vm.bp] {
        0u8 => false,
        1u8 => true,
        _ => {
            return Err(packer_error!(
                "Expected encoded boolean but got {} at buffer index {}",
                buffer[vm.bp],
                vm.bp
            ))
        }
    };
    vmsetio!(vm, Value::Bool(b));
    vm.bp += 1;
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn integer(vm: &mut PackVM, buffer: &[u8], size: u8, signed: bool) -> Result<(), PackerError> {
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
            _ => unreachable!(),
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
            _ => unreachable!(),
        }
    };
    vmsetio!(vm, val);
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn long(vm: &mut PackVM, buffer: &[u8], signed: bool) -> Result<(), PackerError> {
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
    Ok(())
}

#[inline(always)]
fn float(vm: &mut PackVM, buffer: &[u8], size: u8) -> Result<(), PackerError> {
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
    Ok(())
}

#[inline(always)]
fn leb128(vm: &mut PackVM, buffer: &[u8], signed: bool) -> OpResult {
    let (val, val_size) = if signed {
        let (varint, val_size) =
            VarInt32::decode(&buffer[vm.bp..]).map_err(|e| packer_error!("{}", e))?;
        (Value::Int(Integer::from(varint.0)), val_size)
    } else {
        let (varint, val_size) =
            VarUInt32::decode(&buffer[vm.bp..]).map_err(|e| packer_error!("{}", e))?;
        (Value::Int(Integer::from(varint.0)), val_size)
    };
    vmsetio!(vm, val);
    vm.bp += val_size;
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn bytes(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (len, len_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes len: {}", e))?;

    vm.bp += len_size;
    let raw = vmunpack!(vm, buffer, len.0 as usize);
    vmsetio!(vm, Value::Bytes(raw.to_vec()));
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn string(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (len, len_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes len: {}", e))?;

    vm.bp += len_size;
    let raw = vmunpack!(vm, buffer, len.0 as usize);
    vmsetio!(
        vm,
        Value::String(
            String::from_utf8(raw.to_vec()).map_err(|e| packer_error!("{}", e.to_string()))?
        )
    );
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn bytes_raw(vm: &mut PackVM, buffer: &[u8], len: U48) -> OpResult {
    let raw = vmunpack!(vm, buffer, len.0 as usize);
    vmsetio!(vm, Value::Bytes(raw.to_vec()));
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn optional(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    if buffer[vm.bp] == 1 {
        vm.ip += 1;
    } else {
        vmsetio!(vm, Value::None);
        vm.ip += 2;
    }
    vm.bp += 1;
    Ok(())
}

#[inline(always)]
fn extension(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    if vm.bp == buffer.len() {
        vmsetio!(vm, Value::None);
        vm.ip += 2;
    } else {
        vm.ip += 1;
    }
    Ok(())
}

#[inline(always)]
fn pushcnd(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (cnd, cnd_size) = VarUInt32::decode(&buffer[vm.bp..])
        .map_err(|e| packer_error!("while unpacking bytes cnd: {}", e))?;
    vm.bp += cnd_size;

    if cnd.0 > 0 {
        let mut arr = Vec::with_capacity(cnd.0 as usize);
        for _ in 0..cnd.0 as usize {
            arr.push(Value::None);
        }
        vmpushio!(vm, Value::Array(arr));
        vmstep!(vm);
        vm.push_cnd(cnd.0);
    } else {
        let next_popcur = vm.executable.code[usize::from(vm.ip)..]
            .iter()
            .position(|op| op.cmp_type(&Instruction::PopCursor))
            .ok_or(packer_error!("Can't find next CND pop"))?;

        vm.ip += U48::from(next_popcur + 1);
        vmsetio!(vm, Value::Array(Vec::new()));
    }

    Ok(())
}

#[inline(always)]
fn section(vm: &mut PackVM, buffer: &[u8], ctype: u8, sid: U48) -> OpResult {
    vm.ip += 1;

    if ctype == 0 {
        return Ok(());
    }

    if !vm.ef {
        vmpushio!(vm, Value::Struct(HashMap::new()));
    }
    vm.ef = false;

    if ctype == 1 {
        let (cnd, cnd_size) = VarUInt32::decode(&buffer[vm.bp..])
            .map_err(|e| packer_error!("while unpacking bytes cnd: {}", e))?;
        vm.bp += cnd_size;

        if cnd.0 > 0 {
            vm.ip += U48::from(2 * cnd.0 as u64);
        }

        vm.ef = true;

        let var_name = vm
            .executable
            .var_map
            .get(&sid)
            .ok_or(packer_error!("Could not find sid: {sid} in var map!"))?[cnd.0 as usize]
            .clone();

        match vm.cursor.current_mut() {
            Value::Struct(values) => {
                values.insert("type".to_string(), Value::String(var_name));
            }
            _ => {
                return Err(packer_error!(
                    "expected struct to be target value but got: {:?}",
                    vm.cursor.current()
                ))
            }
        }
    }
    Ok(())
}

pub fn exec(vm: &mut PackVM, buf: &[u8]) -> OpResult {
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
            Instruction::Extension => extension(vm, buf)?,
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