use crate::utils::numbers::{Float, Integer, Long, U48};
use std::cmp::PartialEq;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fmt::Debug;
use std::mem::discriminant;

/// Helper that prints a byte slice as `0x…` hex.
struct HexSlice<'a>(&'a [u8]);

impl<'a> Debug for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq)]
pub enum Value {
    None,
    Bool(bool),

    Int(Integer),
    Long(Long),
    Float(Float),

    Bytes(Vec<u8>),
    String(String),

    Array(Vec<Value>),
    Struct(HashMap<String, Value>),
}

impl Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None => f.write_str("None"),
            Value::Bool(b) => f.write_str(b.to_string().as_str()),
            Value::Int(i) => f.write_str(i.to_string().as_str()),
            Value::Long(l) => f.write_str(l.to_string().as_str()),
            Value::Float(fl) => f.write_str(fl.to_string().as_str()),
            Value::Bytes(bytes) => f.debug_tuple("Bytes").field(&HexSlice(bytes)).finish(),
            Value::String(s) => f.write_str(format!("\"{s}\"").as_str()),
            Value::Array(v) => f.debug_list().entries(v).finish(),
            Value::Struct(map) => f.debug_map().entries(map).finish(),
        }
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Bool(value)
    }
}

impl From<Integer> for Value {
    fn from(value: Integer) -> Self {
        Value::Int(value)
    }
}

impl From<u8> for Value {
    fn from(value: u8) -> Self {
        Value::Int(value.into())
    }
}

impl From<i8> for Value {
    fn from(value: i8) -> Self {
        Value::Int(value.into())
    }
}

impl From<u16> for Value {
    fn from(value: u16) -> Self {
        Value::Int(value.into())
    }
}

impl From<i16> for Value {
    fn from(value: i16) -> Self {
        Value::Int(value.into())
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Value::Int(value.into())
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Value::Int(value.into())
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Value::Int(value.into())
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Value::Int(value.into())
    }
}

impl From<u128> for Value {
    fn from(value: u128) -> Self {
        Value::Long(value.into())
    }
}

impl From<i128> for Value {
    fn from(value: i128) -> Self {
        Value::Long(value.into())
    }
}

impl From<Long> for Value {
    fn from(value: Long) -> Self {
        Value::Long(value)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Value::Float(value.into())
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Value::Float(value.into())
    }
}

impl From<Float> for Value {
    fn from(value: Float) -> Self {
        Value::Float(value)
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::String(s.clone())
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::String(value.to_string())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Value::Bytes(value)
    }
}

impl From<Vec<String>> for Value {
    fn from(value: Vec<String>) -> Self {
        Value::Array(value.into_iter().map(Value::String).collect())
    }
}

impl<T> From<Option<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Option<T>) -> Self {
        if let Some(v) = value {
            v.into()
        } else {
            Value::None
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None => write!(f, "None"),
            Value::Bool(v) => write!(f, "{v}"),

            Value::Int(v) => write!(f, "{v}"),
            Value::Long(v) => write!(f, "{v}"),

            Value::Float(v) => write!(f, "{v}"),

            Value::Bytes(vec) => write!(f, "Bytes({:?})", HexSlice(vec)),
            Value::String(s) => write!(f, "String({s})"),

            Value::Array(vals) => write!(f, "Array({vals:?})"),
            Value::Struct(fields) => write!(f, "Struct({fields:?})"),
        }
    }
}

/// Recursively collect human‑readable differences between two `Value`s.
/// An empty vector means the two values are identical.
pub fn diff_values(left: &Value, right: &Value) -> Option<Vec<String>> {
    fn walk(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
        // Fast path: identical => nothing to do
        if a == b {
            return;
        }

        match (a, b) {
            (Value::Array(xs), Value::Array(ys)) => {
                let max_len = xs.len().max(ys.len());
                for i in 0..max_len {
                    let p = format!("{path}[{i}]");
                    match (xs.get(i), ys.get(i)) {
                        (Some(vx), Some(vy)) => walk(vx, vy, &p, out),
                        (Some(_), None) => out.push(format!("{p}: only on left")),
                        (None, Some(_)) => out.push(format!("{p}: only on right")),
                        _ => {}
                    }
                }
            }

            (Value::Struct(xs), Value::Struct(ys)) => {
                let keys: BTreeSet<_> = xs.keys().chain(ys.keys()).collect();
                for key in keys {
                    let p = if path.is_empty() {
                        format!(".{key}")
                    } else {
                        format!("{path}.{key}")
                    };
                    match (xs.get(key), ys.get(key)) {
                        (Some(vx), Some(vy)) => walk(vx, vy, &p, out),
                        (Some(_), None) => out.push(format!("{p}: only on left")),
                        (None, Some(_)) => out.push(format!("{p}: only on right")),
                        _ => {}
                    }
                }
            }

            // scalar variants with same discriminant but different content
            (Value::Bool(x), Value::Bool(y)) => out.push(format!("{path}: Bool {x} ≠ {y}")),
            (Value::Int(x), Value::Int(y)) => out.push(format!("{path}: Int {x:?} ≠ {y:?}")),
            (Value::Long(x), Value::Long(y)) => out.push(format!("{path}: Long {x:?} ≠ {y:?}")),
            (Value::Float(x), Value::Float(y)) => out.push(format!("{path}: Float {x:?} ≠ {y:?}")),
            (Value::Bytes(x), Value::Bytes(y)) => {
                out.push(format!("{path}: Bytes len {} ≠ {}", x.len(), y.len()))
            }
            (Value::String(x), Value::String(y)) => {
                out.push(format!("{path}: String \"{x}\" ≠ \"{y}\""))
            }

            // any other variant mismatch
            (l, r) => out.push(format!(
                "{path}: variant mismatch (left={:?}, right={:?})",
                discriminant(l),
                discriminant(r)
            )),
        }
    }

    let mut diffs = Vec::new();
    walk(left, right, "", &mut diffs);
    if diffs.is_empty() {
        return None;
    }
    Some(diffs)
}

#[derive(Debug, PartialEq, Clone)]
pub enum DataInstruction {
    Bool,
    UInt(u8),
    Int(u8),
    Leb128(bool),
    Float(u8),
    Bytes,         // bytes with LEB128 encoded size first
    BytesRaw(U48), // raw bytes, if param is > 0 do size check on stack value
    String,        // utf-8 string with LEB128 encoded len
}

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum DataOPCode {
    Bool = 0,
    UInt = 1,
    Int = 2,
    Leb128 = 3,
    Float = 4,
    Bytes = 5,
    BytesRaw = 6,
    String = 7,
}

impl From<u8> for DataOPCode {
    fn from(value: u8) -> Self {
        match value {
            0 => DataOPCode::Bool,
            1 => DataOPCode::UInt,
            2 => DataOPCode::Int,
            3 => DataOPCode::Leb128,
            4 => DataOPCode::Float,
            5 => DataOPCode::Bytes,
            6 => DataOPCode::BytesRaw,
            7 => DataOPCode::String,
            _ => unreachable!(),
        }
    }
}

impl From<&DataInstruction> for DataOPCode {
    fn from(value: &DataInstruction) -> Self {
        match value {
            DataInstruction::Bool => DataOPCode::Bool,
            DataInstruction::UInt(_) => DataOPCode::UInt,
            DataInstruction::Int(_) => DataOPCode::Int,
            DataInstruction::Leb128(_) => DataOPCode::Leb128,
            DataInstruction::Float(_) => DataOPCode::Float,
            DataInstruction::Bytes => DataOPCode::Bytes,
            DataInstruction::BytesRaw(_) => DataOPCode::BytesRaw,
            DataInstruction::String => DataOPCode::String,
        }
    }
}

impl From<&[u8; 7]> for DataInstruction {
    fn from(op: &[u8; 7]) -> Self {
        match op[0].into() {
            DataOPCode::Bool => DataInstruction::Bool,
            DataOPCode::UInt => DataInstruction::UInt(op[1]),
            DataOPCode::Int => DataInstruction::Int(op[1]),
            DataOPCode::Leb128 => DataInstruction::Leb128(op[1] == 1),
            DataOPCode::Float => DataInstruction::Float(op[1]),
            DataOPCode::Bytes => DataInstruction::Bytes,
            DataOPCode::BytesRaw => {
                DataInstruction::BytesRaw(U48::from(
                    &op[1..7].try_into().unwrap(),
                ))
            },
            DataOPCode::String => DataInstruction::String,
        }
    }
}

impl From<&DataInstruction> for [u8; 7] {
    fn from(value: &DataInstruction) -> [u8; 7] {
        let opcode = DataOPCode::from(value);
        let mut raw = [0u8; 7];
        raw[0] = opcode as u8;
        match value {
            DataInstruction::UInt(size) => {
                raw[1] = *size;
            }
            DataInstruction::Int(size) => {
                raw[1] = *size;
            }
            DataInstruction::Leb128(signed) => {
                raw[1] = if *signed { 1 } else { 0 };
            }
            DataInstruction::Float(size) => {
                raw[1] = *size;
            }
            DataInstruction::BytesRaw(size) => {
                let bytes: [u8; 6] = (*size).into();
                raw[1..7].copy_from_slice(&bytes);
            }
            _ => ()
        }
        raw
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Instruction {
    // IO manipulation, what to pack/unpack next
    IO(DataInstruction),

    Optional,  // next value is optional, encode a flag as a u8 before
    Extension, // extensions are like optionals but they dont encode a flag in a u8

    /// structure marks
    // indicates a new program section
    Section(
        u8,  // struct type: 1 = enum, 2 = struct
        U48, // program id
    ),
    Field(U48), // indicate field name string id for next value

    /// jumps
    // absolute jmp
    Jmp(U48),

    // perform absolute jmp and return on next Exit instruction
    JmpRet(U48),

    // jump depending on et register
    JmpVariant(
        u32, // et value
        u16, // rel location to jump to
    ),

    // jump trap, jump to section for pid based on first ram value ptr
    JmpTrap,

    /// array specific
    // jump to prev instruction if array cnd > 0
    JmpArrayCND,

    // push condition from io into ram
    // used to indicate array len
    PushCND,

    /// other
    // maybe pop a node from the cursor stack
    PopCursor,

    // exit program or if ptrs remain in the return stack, pop one and jmp to it
    Exit,
}

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum OPCode {
    IO = 0,
    Optional = 1,
    Extension = 2,
    Section = 3,
    Field = 4,
    Jmp = 5,
    JmpRet = 6,
    JmpVariant = 7,
    JmpTrap = 8,
    JmpArrayCND = 9,
    PushCND = 10,
    PopCursor = 11,
    Exit = 12,
}

impl From<u8> for OPCode {
    #[inline(always)]
    fn from(value: u8) -> Self {
        match value {
            0 => OPCode::IO,
            1 => OPCode::Optional,
            2 => OPCode::Extension,
            3 => OPCode::Section,
            4 => OPCode::Field,
            5 => OPCode::Jmp,
            6 => OPCode::JmpRet,
            7 => OPCode::JmpVariant,
            8 => OPCode::JmpTrap,
            9 => OPCode::JmpArrayCND,
            10 => OPCode::PushCND,
            11 => OPCode::PopCursor,
            12 => OPCode::Exit,
            _ => panic!("Unknown opcode {}", value),
        }
    }
}

impl From<&Instruction> for OPCode {
    fn from(value: &Instruction) -> Self {
        match value {
            Instruction::IO(_) => OPCode::IO,
            Instruction::Optional => OPCode::Optional,
            Instruction::Extension => OPCode::Extension,
            Instruction::Section(_, _) => OPCode::Section,
            Instruction::Field(_) => OPCode::Field,
            Instruction::Jmp(_) => OPCode::Jmp,
            Instruction::JmpRet(_) => OPCode::JmpRet,
            Instruction::JmpVariant(_, _) => OPCode::JmpVariant,
            Instruction::JmpTrap => OPCode::JmpTrap,
            Instruction::JmpArrayCND => OPCode::JmpArrayCND,
            Instruction::PushCND => OPCode::PushCND,
            Instruction::PopCursor => OPCode::PopCursor,
            Instruction::Exit => OPCode::Exit,
        }
    }
}

impl From<&[u8; 8]> for Instruction {
    fn from(op: &[u8; 8]) -> Self {
        match OPCode::from(op[0]) {
            OPCode::IO => Instruction::IO(DataInstruction::from(&op[1..8].try_into().unwrap())),
            OPCode::Optional => Instruction::Optional,
            OPCode::Extension => Instruction::Extension,
            OPCode::Section => Instruction::Section(op[1], U48::from(&op[2..8].try_into().unwrap())),
            OPCode::Field => Instruction::Field(U48::from(&op[2..8].try_into().unwrap())),
            OPCode::Jmp => Instruction::Jmp(U48::from(&op[2..8].try_into().unwrap())),
            OPCode::JmpRet => Instruction::JmpRet(U48::from(&op[2..8].try_into().unwrap())),
            OPCode::JmpVariant => Instruction::JmpVariant(
                u32::from_le_bytes(op[2..6].try_into().unwrap()),
                u16::from_le_bytes(op[6..8].try_into().unwrap()),
            ),
            OPCode::JmpTrap => Instruction::JmpTrap,
            OPCode::JmpArrayCND => Instruction::JmpArrayCND,
            OPCode::PushCND => Instruction::PushCND,
            OPCode::PopCursor => Instruction::PopCursor,
            OPCode::Exit => Instruction::Exit,
        }
    }
}

impl From<&Instruction> for [u8; 8] {
    fn from(value: &Instruction) -> Self {
        let opcode = OPCode::from(value);
        let mut raw = [0u8; 8];
        raw[0] = opcode as u8;
        let rest: [u8; 7] = match value {
            Instruction::IO(dataop) => dataop.into(),
            Instruction::Section(ctype, sid) => {
                let sid: [u8; 6] = (*sid).into();
                [*ctype, sid[0], sid[1], sid[2], sid[3], sid[4], sid[5]]
            }
            Instruction::Field(fid) => {
                let fid: [u8; 6] = (*fid).into();
                [0, fid[0], fid[1], fid[2], fid[3], fid[4], fid[5]]
            }
            Instruction::Jmp(ptr) => {
                let ptr: [u8; 6] = (*ptr).into();
                [0, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]]
            }
            Instruction::JmpRet(ptr) => {
                let ptr: [u8; 6] = (*ptr).into();
                [0, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]]
            }
            Instruction::JmpVariant(var_idx, rel_ptr) => {
                let var_idx: [u8; 4] = var_idx.to_le_bytes();
                let rel_ptr: [u8; 2] = rel_ptr.to_le_bytes();
                [0, var_idx[0], var_idx[1], var_idx[2], var_idx[3], rel_ptr[0], rel_ptr[1]]
            }
            _ => [0; 7]
        };
        raw[1..8].copy_from_slice(&rest);
        raw
    }
}

impl Instruction {
    pub fn cmp_type(&self, other: &Instruction) -> bool {
        discriminant(self) == discriminant(other)
    }
}

pub const STD_TYPES: [&str; 18] = [
    "bool", "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "uleb128",
    "sleb128", "f32", "f64", "bytes", "str", "raw",
];

#[macro_export]
macro_rules! is_std_type {
    ($type_name:expr) => {{
        if STD_TYPES.contains($type_name) {
            return true;
        }
        if $type_name.starts_with("raw(") {
            return true;
        }
        return false;
    }};
}

#[macro_export]
macro_rules! instruction_for {
    ($ty:expr) => {
        match $ty {
            "bool" => Some(DataInstruction::Bool),

            "u8" => Some(DataInstruction::UInt(1)),
            "u16" => Some(DataInstruction::UInt(2)),
            "u32" => Some(DataInstruction::UInt(4)),
            "u64" => Some(DataInstruction::UInt(8)),
            "u128" => Some(DataInstruction::UInt(16)),

            "i8" => Some(DataInstruction::Int(1)),
            "i16" => Some(DataInstruction::Int(2)),
            "i32" => Some(DataInstruction::Int(4)),
            "i64" => Some(DataInstruction::Int(8)),
            "i128" => Some(DataInstruction::Int(16)),

            "uleb128" => Some(DataInstruction::Leb128(false)),
            "sleb128" => Some(DataInstruction::Leb128(true)),

            "f32" => Some(DataInstruction::Float(4)),
            "f64" => Some(DataInstruction::Float(8)),

            "bytes" => Some(DataInstruction::Bytes),
            "str" => Some(DataInstruction::String),

            "raw" => Some(DataInstruction::BytesRaw(U48(0))),

            _ => {
                if $ty.starts_with("raw(") {
                    let size = U48::from(
                        $ty.split('(')
                            .nth(1)
                            .and_then(|s| s.split(')').next())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_default(),
                    );

                    Some(DataInstruction::BytesRaw(size))
                } else {
                    None
                }
            }
        }
    };
}
