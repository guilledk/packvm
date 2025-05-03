// https://github.com/AntelopeIO/leap/blob/92b6fec5e949660bae78e90ebf555fe71ab06940/libraries/chain/abi_serializer.cpp#L89

/*
void abi_serializer::configure_built_in_types() {
    built_in_types.emplace("bool",                      pack_unpack<uint8_t>());
    built_in_types.emplace("int8",                      pack_unpack<int8_t>());
    built_in_types.emplace("uint8",                     pack_unpack<uint8_t>());
    built_in_types.emplace("int16",                     pack_unpack<int16_t>());
    built_in_types.emplace("uint16",                    pack_unpack<uint16_t>());
    built_in_types.emplace("int32",                     pack_unpack<int32_t>());
    built_in_types.emplace("uint32",                    pack_unpack<uint32_t>());
    built_in_types.emplace("int64",                     pack_unpack<int64_t>());
    built_in_types.emplace("uint64",                    pack_unpack<uint64_t>());
    built_in_types.emplace("int128",                    pack_unpack<int128_t>());
    built_in_types.emplace("uint128",                   pack_unpack<uint128_t>());
    built_in_types.emplace("varint32",                  pack_unpack<fc::signed_int>());
    built_in_types.emplace("varuint32",                 pack_unpack<fc::unsigned_int>());

    built_in_types.emplace("float32",                   pack_unpack<float>());
    built_in_types.emplace("float64",                   pack_unpack<double>());
    built_in_types.emplace("float128",                  pack_unpack<float128_t>());

    built_in_types.emplace("time_point",                pack_unpack<fc::time_point>());
    built_in_types.emplace("time_point_sec",            pack_unpack<fc::time_point_sec>());
    built_in_types.emplace("block_timestamp_type",      pack_unpack<block_timestamp_type>());

    built_in_types.emplace("name",                      pack_unpack<name>());

    built_in_types.emplace("bytes",                     pack_unpack<bytes>());
    built_in_types.emplace("string",                    pack_unpack<string>());

    built_in_types.emplace("checksum160",               pack_unpack<checksum160_type>());
    built_in_types.emplace("checksum256",               pack_unpack<checksum256_type>());
    built_in_types.emplace("checksum512",               pack_unpack<checksum512_type>());

    built_in_types.emplace("public_key",                pack_unpack_deadline<public_key_type>());
    built_in_types.emplace("signature",                 pack_unpack_deadline<signature_type>());

    built_in_types.emplace("symbol",                    pack_unpack<symbol>());
    built_in_types.emplace("symbol_code",               pack_unpack<symbol_code>());
    built_in_types.emplace("asset",                     pack_unpack<asset>());
    built_in_types.emplace("extended_asset",            pack_unpack<extended_asset>());
}

Any other type should be able to be represented by a sequence of these types

 */
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::mem::discriminant;
use crate::utils::varint::{VarInt32, VarUInt32};

#[derive(Debug, Clone, PartialEq)]
pub enum Exception {
    VariantIndexNotInJumpTable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    None,
    Bool(bool),

    // unsigned
    Uint8 (u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Uint128(u128),

    // signed
    Int8 (i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Int128(i128),

    // var-len encoded integers
    VarUInt32(u32),
    VarInt32(i32),

    // floats
    Float32(f32),
    Float64(f64),
    Float128([u8; 16]),

    Bytes(Vec<u8>),
    String(String),

    Array(Vec<Value>),
    Struct(HashMap<String, Value>),
}


#[macro_export]
macro_rules! value_payload_size {
    ($value:expr) => {
        match $value {
            Value::Bool(_) => 1,

            Value::Uint8(_) => 1,
            Value::Uint16(_) => 2,
            Value::Uint32(_) => 4,
            Value::Uint64(_) => 8,
            Value::Uint128(_) => 16,

            Value::Int8(_) => 1,
            Value::Int16(_) => 2,
            Value::Int32(_) => 4,
            Value::Int64(_) => 8,
            Value::Int128(_) => 16,

            Value::VarUInt32(v) => {
                if *v < 0x80 { 1 }
                else if *v < 0x4000 { 2 }
                else if *v < 0x200000 { 3 }
                else if *v < 0x10000000 { 4 }
                else { 5 }
            },
            Value::VarInt32(v) => {
                let zigzag = ((*v << 1) ^ (*v >> 31)) as u32;
                if zigzag < 0x80 { 1 }
                else if zigzag < 0x4000 { 2 }
                else if zigzag < 0x200000 { 3 }
                else if zigzag < 0x10000000 { 4 }
                else { 5 }
            },

            Value::Float32(_) => 4,
            Value::Float64(_) => 8,
            Value::Float128(_) => 16,

            Value::Bytes(ref v) => {
                let len = v.len();
                let len_prefix_size = if len < 0x80 { 1 }
                    else if len < 0x4000 { 2 }
                    else if len < 0x200000 { 3 }
                    else if len < 0x10000000 { 4 }
                    else { 5 };
                len_prefix_size + len
            },

            Value::Array(v) => {
                let v = v.len() as u32;
                if v < 0x80 { 1 }
                else if v < 0x4000 { 2 }
                else if v < 0x200000 { 3 }
                else if v < 0x10000000 { 4 }
                else { 5 }
            }

            _ => 0
        }
    };
}

#[macro_export]
macro_rules! payload_size {
    ($values:expr) => {{
        let mut total_size = 0;
        for val in $values {
            total_size += crate::value_payload_size!(val);
        }
        total_size
    }};
}

macro_rules! impl_value_from {
    ($( ($src:ty, $dst:ident) ),* $(,)?) => {
        $(impl From<$src> for Value {
            #[inline] fn from(v: $src) -> Self { Value::$dst(v) }
        })*

        $(impl From<&$src> for Value {
            #[inline] fn from(v: &$src) -> Self { Value::$dst(*v) }
        })*
    };
}

impl_value_from!(
    (bool, Bool),
    (u8, Uint8), (u16, Uint16), (u32, Uint32), (u64, Uint64), (u128, Uint128),
    (i8, Int8), (i16, Int16), (i32, Int32), (i64, Int64), (i128, Int128),
    (f32, Float32), (f64, Float64)
);

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

impl From<VarUInt32> for Value {
    fn from(value: VarUInt32) -> Self {
        Value::VarUInt32(value.0)
    }
}

impl From<VarInt32> for Value {
    fn from(value: VarInt32) -> Self {
        Value::VarInt32(value.0)
    }
}

impl From<[u8; 16]> for Value {
    fn from(value: [u8; 16]) -> Self {
        Value::Float128(value)
    }
}

impl<T> From<Option<T>> for Value where T: Into<Value> {
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
            Value::Bool(v) => write!(f, "{}", v),

            Value::Uint8(v) => write!(f, "{}", v),
            Value::Uint16(v) => write!(f, "{}", v),
            Value::Uint32(v) => write!(f, "{}", v),
            Value::Uint64(v) => write!(f, "{}", v),
            Value::Uint128(v) => write!(f, "{}", v),

            Value::Int8(v) => write!(f, "{}", v),
            Value::Int16(v) => write!(f, "{}", v),
            Value::Int32(v) => write!(f, "{}", v),
            Value::Int64(v) => write!(f, "{}", v),
            Value::Int128(v) => write!(f, "{}", v),

            Value::VarUInt32(v) => write!(f, "{}", v),
            Value::VarInt32(v) => write!(f, "{}", v),

            Value::Float32(v) => write!(f, "{}", v),
            Value::Float64(v) => write!(f, "{}", v),
            Value::Float128(bytes) => write!(f, "Float128({:02x?})", bytes),

            Value::Bytes(vec) => write!(f, "Bytes({:02x?})", vec),
            Value::String(s) => write!(f, "String({})", s),

            Value::Array(vals) => write!(f, "Array({:?})", vals),
            Value::Struct(fields) => write!(f, "Struct({:?})", fields),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Instruction {
    // IO manipulation, what to pack/unpack next
    Bool,
    UInt{ size: u8 },
    Int{ size: u8 },
    VarUInt,
    VarInt,
    Float{ size: u8 },
    Bytes,  // bytes with LEB128 encoded size first
    BytesRaw{ size: u8},  // raw bytes, if param is > 0 do size check on stack value
    String,  // utf-8 string with LEB128 encoded len

    Optional,  // next value is optional, encode a flag as a u8 before
    Extension,  // extensions are like optionals but they dont encode a flag in a u8

    // structure marks

    Section(  // indicates a new program section
        u8,  // struct type: 1 = enum, 2 = struct
        usize  // program id
    ),

    Field(usize),  // indicate field name string id for next value

    // push condition from io into condition stack
    // param is cnd type, 0 = array len, 1 = enum variant
    PushCND(u8),

    // discard condition from stack
    PopCND,

    // jumps
    Jmp { ptr: usize },  // absolute jmp

    // perform absolute jmp and return on next Exit instruction
    JmpRet{ ptr: usize },


    // conditional jumps based on first value on condition stack

    // jump to ptr if current condition == value
    JmpStructCND(
        u32,  // cnd value
        usize  // location to jump to
    ),

    // jump to pointer if condition > 0
    JmpArrayCND(usize),

    // exit program or if ptrs remain in the return stack, pop one and jmp to it
    Exit,
}

impl Instruction {
    pub fn validate_asm(src: &Instruction, dst: &Instruction) -> bool {
        discriminant(src) == discriminant(dst)
    }
}

pub const STD_TYPES: [&str; 39] = [
    "bool", "boolean",

    "uint8", "u8",
    "uint16", "u16",
    "uint32", "u32",
    "uint64", "u64",
    "uint128", "u128",

    "int8", "i8",
    "int16", "i16",
    "int32", "i32",
    "int64", "i64",
    "int128", "i128",

    "uleb128", "varuint32",
    "sleb128", "varint32",

    "float32", "f32",
    "float64", "f64",
    "float128", "f128",

    "bytes", "str", "string",

    "sum160",
    "sum256",
    "sum512",

    "raw",
];

#[macro_export]
macro_rules! instruction_for {
    ($ty:expr) => {
        match $ty {
            "bool" | "boolean" => Some(Instruction::Bool),

            "uint8" | "u8" => Some(Instruction::UInt{ size: 1 }),
            "uint16" | "u16" => Some(Instruction::UInt{ size: 2 }),
            "uint32" | "u32" => Some(Instruction::UInt{ size: 4 }),
            "uint64" | "u64" => Some(Instruction::UInt{ size: 8 }),
            "uint128" | "u128" => Some(Instruction::UInt{ size: 16 }),

            "int8" | "i8" => Some(Instruction::Int{ size: 1 }),
            "int16" | "i16" => Some(Instruction::Int{ size: 2 }),
            "int32" | "i32" => Some(Instruction::Int{ size: 4 }),
            "int64" | "i64" => Some(Instruction::Int{ size: 8 }),
            "int128" | "i128" => Some(Instruction::Int{ size: 16 }),

            "uleb128" | "varuint32" => Some(Instruction::VarUInt),
            "sleb128" | "varint32" => Some(Instruction::VarInt),

            "float32" | "f32" => Some(Instruction::Float{ size: 4 }),
            "float64" | "f64" => Some(Instruction::Float{ size: 8 }),
            "float128" | "f128" => Some(Instruction::Float{ size: 16 }),

            "bytes" => Some(Instruction::Bytes),
            "str" | "string" => Some(Instruction::String),

            "sum160" => Some(Instruction::BytesRaw{ size: 20 }),
            "sum256" => Some(Instruction::BytesRaw{ size: 32 }),
            "sum512" => Some(Instruction::BytesRaw{ size: 64 }),

            "raw" => Some(Instruction::BytesRaw{ size: 0 }),

            _ => None,
        }
    };
}