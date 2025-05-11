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
*/
use crate::utils::numbers::Integer;
use crate::{
    compiler::{EnumDef, SourceCode, StructDef, TypeAlias, TypeDef},
    is_std_type,
    isa::STD_TYPES,
    utils::TypeCompileError,
    Value,
};
use antelope::chain::action::PermissionLevel;
use antelope::chain::authority::{Authority, KeyWeight, PermissionLevelWeight, WaitWeight};
use antelope::chain::checksum::{Checksum160, Checksum256, Checksum512};
use antelope::chain::key_type::{KeyType, KeyTypeTrait};
use antelope::chain::public_key::PublicKey;
use antelope::chain::signature::Signature;
use antelope::{
    chain::{
        abi::{
            ABIResolvedType, ABITypeResolver, ABIView, AbiField, AbiStruct, AbiTypeDef, AbiVariant,
            ShipABI, ABI,
        },
        asset::{Asset, Symbol, SymbolCode},
        binary_extension::BinaryExtension,
        name::Name,
    },
    serializer::{Encoder, Packer},
};
use std::collections::HashMap;

impl TypeAlias for AbiTypeDef {
    fn new_type_name(&self) -> &str {
        &self.new_type_name
    }

    fn from_type_name(&self) -> &str {
        &self.r#type
    }
}

impl TypeDef for AbiField {
    fn name(&self) -> &str {
        &self.name
    }

    fn type_name(&self) -> &str {
        &self.r#type
    }
}

impl EnumDef for AbiVariant {
    fn name(&self) -> &str {
        &self.name
    }

    fn variants(&self) -> &[String] {
        self.types.as_slice()
    }
}

impl StructDef<AbiField> for AbiStruct {
    fn name(&self) -> &str {
        &self.name
    }

    fn fields(&self) -> &[AbiField] {
        self.fields.as_slice()
    }
}

#[derive(Debug, Clone)]
pub struct AntelopeSourceCode {
    aliases: Vec<AbiTypeDef>,
    structs: Vec<AbiStruct>,
    enums: Vec<AbiVariant>,
}

impl Default for AntelopeSourceCode {
    fn default() -> Self {
        let mut aliases = vec![];
        let mut structs = vec![];
        include_antelope_stdtypes(&mut aliases, &mut structs);
        Self {
            aliases,
            structs,
            enums: Default::default(),
        }
    }
}

fn expand_struct_base<ABI: ABIView>(abi: &ABI, s: &mut AbiStruct) -> Result<(), TypeCompileError> {
    if !s.base.is_empty() {
        let (resolved_type, _) =
            abi.resolve_type(&s.base)
                .ok_or(TypeCompileError::new(format_args!(
                    "Couldn\'t resolve type for struct {} base {}",
                    s.name, s.base
                )))?;

        let base_fields = match resolved_type {
            ABIResolvedType::Struct(struct_meta) => Ok(struct_meta.fields.clone()),
            _ => Err(TypeCompileError::new(format_args!(
                "Expected base field type to be a struct but got {resolved_type:?}"
            ))),
        }?;

        let mut fields = Vec::with_capacity(base_fields.len() + s.fields().len());
        fields.extend(base_fields);
        fields.extend(s.fields.clone());

        s.fields = fields;
    }
    Ok(())
}

fn include_antelope_stdtypes(aliases: &mut Vec<AbiTypeDef>, structs: &mut Vec<AbiStruct>) {
    for (new_type, alias_type) in [
        ("uint8", "u8"),
        ("uint16", "u16"),
        ("uint32", "u32"),
        ("uint64", "u64"),
        ("uint128", "u128"),
        ("int8", "i8"),
        ("int16", "i16"),
        ("int32", "i32"),
        ("int64", "i64"),
        ("int128", "i128"),
        ("varuint32", "uleb128"),
        ("varint32", "sleb128"),
        ("float32", "f32"),
        ("float64", "f64"),
        ("float128", "raw(16)"),
        ("string", "str"),
        ("name", "u64"),
        ("account_name", "u64"),
        ("symbol", "u64"),
        ("symbol_code", "u64"),
        ("rd160", "raw(20)"),
        ("checksum160", "raw(20)"),
        ("sha256", "raw(32)"),
        ("checksum256", "raw(32)"),
        ("transaction_id", "raw(32)"),
        ("checksum512", "raw(64)"),
        ("time_point", "u64"),
        ("time_point_sec", "u32"),
        ("block_timestamp_type", "u32"),
        ("public_key", "raw(34)"),
        ("signature", "raw(66)"),
    ]
    .iter()
    .rev()
    {
        aliases.insert(
            0,
            AbiTypeDef {
                new_type_name: new_type.to_string(),
                r#type: alias_type.to_string(),
            },
        );
    }

    let extra_structs = [
        AbiStruct {
            name: "asset".to_string(),
            base: String::default(),
            fields: vec![
                AbiField {
                    name: "amount".to_string(),
                    r#type: "i64".to_string(),
                },
                AbiField {
                    name: "symbol".to_string(),
                    r#type: "u64".to_string(),
                },
            ],
        },
        AbiStruct {
            name: "extended_asset".to_string(),
            base: String::default(),
            fields: vec![
                AbiField {
                    name: "quantity".to_string(),
                    r#type: "asset".to_string(),
                },
                AbiField {
                    name: "contract".to_string(),
                    r#type: "name".to_string(),
                },
            ],
        },
        // AbiStruct{
        //     name: "signature".to_string(),
        //     base: String::default(),
        //     fields: vec![
        //         AbiField {name: "key_type".to_string(), r#type: "u8".to_string()},
        //         AbiField {name: "value".to_string(), r#type: "raw(66)".to_string()},
        //     ]
        // }
    ];

    for (i, struct_def) in extra_structs.iter().enumerate() {
        structs.insert(i, struct_def.clone());
    }
}

macro_rules! impl_try_from_abi {
    ($($abi:ty), + $(,)? => $target:ty) => {
        $(
            impl ::core::convert::TryFrom<&$abi> for $target {
                type Error = TypeCompileError;

                fn try_from(abi: &$abi) -> Result<$target, Self::Error> {
                    let mut aliases = abi.types().to_vec();
                    let mut structs = abi.structs().to_vec();

                    include_antelope_stdtypes(
                        &mut aliases,
                        &mut structs,
                    );

                    let enums = abi.variants().to_vec();

                    for struct_def in structs.iter_mut() {
                        expand_struct_base(abi, struct_def)?;
                    }

                    Ok(Self { aliases, enums, structs })
                }
            }

            impl ::core::convert::TryFrom<$abi> for $target {
                type Error = TypeCompileError;

                fn try_from(abi: $abi) -> Result<$target, Self::Error> {
                    <$target as ::core::convert::TryFrom<&$abi>>::try_from(&abi)
                }
            }
        )+
    };
}

impl_try_from_abi!(ABI, ShipABI => AntelopeSourceCode);

impl SourceCode<AbiTypeDef, AbiField, AbiVariant, AbiStruct> for AntelopeSourceCode {
    fn structs(&self) -> &[AbiStruct] {
        self.structs.as_slice()
    }
    fn enums(&self) -> &[AbiVariant] {
        self.enums.as_slice()
    }

    fn aliases(&self) -> &[AbiTypeDef] {
        self.aliases.as_slice()
    }

    fn resolve_alias(&self, alias: &str) -> Option<String> {
        self.aliases
            .iter()
            .find(|a| a.new_type_name == alias)
            .map(|t| t.r#type.clone())
    }

    fn is_std_type(&self, ty: &str) -> bool {
        let ty = match self.resolve_alias(ty) {
            Some(ty) => ty,
            None => ty.to_string(),
        };
        is_std_type!(&ty.as_str())
    }

    fn is_alias_of(&self, alias: &str, ty: &str) -> bool {
        self.aliases
            .iter()
            .any(|a| a.new_type_name == alias && a.r#type == ty)
    }

    fn is_variant(&self, ty: &str) -> bool {
        self.enums.iter().any(|e| e.name == ty)
    }

    fn is_variant_of(&self, ty: &str, var: &str) -> bool {
        match self.enums.iter().find(|e| e.name == var) {
            Some(variant) => variant.types.contains(&ty.to_string()),
            None => false,
        }
    }
}

impl From<SymbolCode> for Value {
    fn from(value: SymbolCode) -> Self {
        value.into()
    }
}

impl From<Symbol> for Value {
    fn from(value: Symbol) -> Self {
        Into::<u64>::into(value).into()
    }
}

impl From<Asset> for Value {
    fn from(value: Asset) -> Self {
        Value::Struct(HashMap::from([
            ("amount".to_string(), value.amount().into()),
            ("symbol".to_string(), value.symbol().into()),
        ]))
    }
}

impl From<Name> for Value {
    fn from(value: Name) -> Self {
        value.value().into()
    }
}

impl From<ABI> for Value {
    fn from(value: ABI) -> Self {
        let mut encoder = Encoder::new(0);
        value.pack(&mut encoder);
        Value::Bytes(encoder.get_bytes().to_vec())
    }
}

impl<T> From<BinaryExtension<T>> for Value
where
    T: Packer + Default,
    for<'a> Value: From<&'a T>,
{
    fn from(value: BinaryExtension<T>) -> Value {
        match value.value() {
            Some(v) => v.into(),
            None => Value::None,
        }
    }
}

impl From<BinaryExtension<u128>> for Value {
    fn from(value: BinaryExtension<u128>) -> Value {
        match value.value() {
            Some(v) => (*v).into(),
            None => Value::None,
        }
    }
}

impl From<Checksum160> for Value {
    fn from(value: Checksum160) -> Self {
        Value::Bytes(value.data.to_vec())
    }
}

impl From<Checksum256> for Value {
    fn from(value: Checksum256) -> Self {
        Value::Bytes(value.data.to_vec())
    }
}

impl From<Checksum512> for Value {
    fn from(value: Checksum512) -> Self {
        Value::Bytes(value.data.to_vec())
    }
}

impl From<KeyType> for Value {
    fn from(value: KeyType) -> Self {
        value.to_index().into()
    }
}

impl From<PublicKey> for Value {
    fn from(value: PublicKey) -> Self {
        let mut raw = vec![value.key_type.to_index()];
        raw.extend_from_slice(value.value.as_slice());
        Value::Bytes(raw)
    }
}

impl From<KeyWeight> for Value {
    fn from(value: KeyWeight) -> Self {
        Value::Struct(HashMap::from([
            ("key".to_string(), value.key.into()),
            ("weight".to_string(), value.weight.into()),
        ]))
    }
}

impl From<Vec<KeyWeight>> for Value {
    fn from(value: Vec<KeyWeight>) -> Self {
        Value::Array(value.into_iter().map(Into::into).collect())
    }
}

impl From<PermissionLevel> for Value {
    fn from(value: PermissionLevel) -> Self {
        Value::Struct(HashMap::from([
            ("permission".to_string(), value.permission.into()),
            ("actor".to_string(), value.actor.into()),
        ]))
    }
}

impl From<PermissionLevelWeight> for Value {
    fn from(value: PermissionLevelWeight) -> Self {
        Value::Struct(HashMap::from([
            ("weight".to_string(), value.weight.into()),
            ("permission".to_string(), value.permission.into()),
        ]))
    }
}

impl From<Vec<PermissionLevelWeight>> for Value {
    fn from(value: Vec<PermissionLevelWeight>) -> Self {
        Value::Array(value.into_iter().map(Into::into).collect())
    }
}

impl From<Authority> for Value {
    fn from(value: Authority) -> Self {
        Value::Struct(HashMap::from([
            (
                "threshold".to_string(),
                Value::Int(Integer::from(value.threshold)),
            ),
            ("keys".to_string(), value.keys.into()),
            ("accounts".to_string(), value.accounts.into()),
            ("waits".to_string(), value.waits.into()),
        ]))
    }
}

impl From<Vec<Authority>> for Value {
    fn from(value: Vec<Authority>) -> Self {
        Value::Array(value.into_iter().map(Into::into).collect())
    }
}

impl From<WaitWeight> for Value {
    fn from(value: WaitWeight) -> Self {
        Value::Struct(HashMap::from([
            (
                "wait_sec".to_string(),
                Value::Int(Integer::from(value.wait_sec)),
            ),
            (
                "weight".to_string(),
                Value::Int(Integer::from(value.weight)),
            ),
        ]))
    }
}

impl From<Vec<WaitWeight>> for Value {
    fn from(value: Vec<WaitWeight>) -> Self {
        Value::Array(value.into_iter().map(Into::into).collect())
    }
}

impl From<Signature> for Value {
    fn from(value: Signature) -> Self {
        Value::Struct(HashMap::from([
            ("key_type".to_string(), value.key_type.into()),
            ("value".to_string(), value.value.into()),
        ]))
    }
}
