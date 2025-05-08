use crate::utils::numbers::{Float, Integer, Long};
use crate::{debug_log, exit, field, jmp, jmpacnd, jmpret, jmpscnd, packer_error, popcursor};
use crate::{
    isa_impl::common::OpResult,
    utils::{
        varint::{VarInt32, VarUInt32},
        PackerError,
    },
    Instruction, PackVM, Value,
};
use std::collections::HashMap;
use tailcall::tailcall;

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
fn varuint32(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (varint, val_size) =
        VarUInt32::decode(&buffer[vm.bp..]).map_err(|e| packer_error!("{}", e))?;

    vmsetio!(vm, Value::VarUInt32(varint.0));
    vm.bp += val_size;
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn varint32(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let (varint, val_size) =
        VarInt32::decode(&buffer[vm.bp..]).map_err(|e| packer_error!("{}", e))?;
    vmsetio!(vm, Value::VarInt32(varint.0));
    vm.bp += val_size;
    vmstep!(vm);
    Ok(())
}

#[inline(always)]
fn float128(vm: &mut PackVM, buffer: &[u8]) -> OpResult {
    let float_raw: [u8; 16] = vmunpack!(vm, buffer, 16)
        .try_into()
        .map_err(|e| packer_error!("{}", e))?;

    vmsetio!(vm, Value::Float128(float_raw));
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
fn bytes_raw(vm: &mut PackVM, buffer: &[u8], len: usize) -> OpResult {
    let raw = vmunpack!(vm, buffer, len);
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
        vm.cndstack.push(cnd.0);
    } else {
        let next_jmpacnd = vm.executable.code[vm.ip..]
            .iter()
            .position(|op| match op {
                Instruction::JmpArrayCND(_) => true,
                _ => false,
            })
            .ok_or(packer_error!("Can't find next CND pop"))?;

        vm.ip += next_jmpacnd + 1;
        vmsetio!(vm, Value::Array(Vec::new()));
    }

    Ok(())
}

#[inline(always)]
#[cfg_attr(not(feature = "debug"), allow(unused_variables))]
fn section(vm: &mut PackVM, buffer: &[u8], ctype: u8, id: usize) -> OpResult {
    if !vm.ef {
        vmpushio!(vm, Value::Struct(HashMap::new()));
    }
    vm.ef = false;

    if ctype == 1 {
        let (cnd, cnd_size) = VarUInt32::decode(&buffer[vm.bp..])
            .map_err(|e| packer_error!("while unpacking bytes cnd: {}", e))?;
        vm.bp += cnd_size;

        vm.et = cnd.0;
        vm.ef = true;

        match vm.cursor.current_mut() {
            Value::Struct(values) => {
                values.insert("type".to_string(), Value::Int(Integer::from(cnd.0)));
            }
            _ => {
                return Err(packer_error!(
                    "expected struct to be target value but got: {:?}",
                    vm.cursor.current()
                ))
            }
        }
    }

    vm.ip += 1;
    Ok(())
}

#[tailcall]
pub fn exec(vm: &mut PackVM, buffer: &[u8]) -> Result<(), PackerError> {
    debug_log!("{:?}", vm);
    match vm.executable.code[vm.ip] {
        Instruction::Bool => {
            boolean(vm, buffer)?;
            exec(vm, buffer)
        }

        Instruction::UInt { size } => {
            if size == 16 {
                long(vm, buffer, false)?
            } else {
                integer(vm, buffer, size, false)?
            };
            exec(vm, buffer)
        }
        Instruction::Int { size } => {
            if size == 16 {
                long(vm, buffer, true)?
            } else {
                integer(vm, buffer, size, true)?
            };
            exec(vm, buffer)
        }

        Instruction::VarUInt => {
            varuint32(vm, buffer)?;
            exec(vm, buffer)
        }
        Instruction::VarInt => {
            varint32(vm, buffer)?;
            exec(vm, buffer)
        }

        Instruction::Float { size } => match size {
            4 | 8 => {
                float(vm, buffer, size)?;
                exec(vm, buffer)
            }
            16 => {
                float128(vm, buffer)?;
                exec(vm, buffer)
            }
            _ => unreachable!(),
        },

        Instruction::Bytes => {
            bytes(vm, buffer)?;
            exec(vm, buffer)
        }
        Instruction::BytesRaw { size } => {
            bytes_raw(vm, buffer, size)?;
            exec(vm, buffer)
        }
        Instruction::String => {
            string(vm, buffer)?;
            exec(vm, buffer)
        }

        Instruction::Optional => {
            optional(vm, buffer)?;
            exec(vm, buffer)
        }
        Instruction::Extension => {
            extension(vm, buffer)?;
            exec(vm, buffer)
        }

        Instruction::PushCND => {
            pushcnd(vm, buffer)?;
            exec(vm, buffer)
        }
        Instruction::PopCursor => {
            popcursor!(vm)?;
            exec(vm, buffer)
        }
        Instruction::Jmp { ptr } => {
            jmp!(vm, ptr)?;
            exec(vm, buffer)
        }
        Instruction::JmpRet { ptr } => {
            jmpret!(vm, ptr);
            exec(vm, buffer)
        }
        Instruction::JmpArrayCND(ptr) => {
            jmpacnd!(vm, ptr)?;
            exec(vm, buffer)
        }
        Instruction::JmpVariant(variant, ptr) => {
            jmpscnd!(vm, variant, ptr)?;
            exec(vm, buffer)
        }
        Instruction::Exit => {
            if exit!(vm)? {
                Ok(())
            } else {
                exec(vm, buffer)
            }
        }
        Instruction::Section(ctype, id) => {
            section(vm, buffer, ctype, id)?;
            exec(vm, buffer)
        }
        Instruction::Field(name) => {
            field!(vm, name);
            exec(vm, buffer)
        }
    }
}
