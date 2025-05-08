use std::collections::HashMap;
use antelope::{
    chain::{
        abi::{ABIResolvedType, ABITypeResolver, ABIView, AbiField, AbiStruct, AbiTypeDef, AbiVariant, ShipABI, ABI},
        asset::{Asset, Symbol, SymbolCode},
        binary_extension::BinaryExtension,
        name::Name
    },
    serializer::{Encoder, Packer}
};
use antelope::chain::action::PermissionLevel;
use antelope::chain::authority::{Authority, KeyWeight, PermissionLevelWeight, WaitWeight};
use antelope::chain::checksum::{Checksum160, Checksum256, Checksum512};
use antelope::chain::key_type::{KeyType, KeyTypeTrait};
use antelope::chain::public_key::PublicKey;
use antelope::chain::signature::Signature;
use crate::{compiler::{EnumDef, SourceCode, StructDef, TypeAlias, TypeDef}, utils::TypeCompileError, isa::STD_TYPES, Value, is_std_type};
use crate::utils::numbers::Integer;

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

#[derive(Debug, Clone, Default)]
pub struct AntelopeSourceCode {
    aliases: Vec<AbiTypeDef>,
    structs: Vec<AbiStruct>,
    enums: Vec<AbiVariant>,
}


fn expand_struct_base<ABI: ABIView>(abi: &ABI, s: &mut AbiStruct) -> Result<(), TypeCompileError> {
    if s.base != "" {
        let (resolved_type, _) = abi.resolve_type(&s.base)
            .ok_or(
                TypeCompileError::new(
                    format_args!("Couldn\'t resolve type for struct {} base {}", s.name, s.base)))?;

        let base_fields = match resolved_type {
            ABIResolvedType::Struct(struct_meta) => {
                Ok(struct_meta.fields.clone())
            }
            _ => {
                Err(TypeCompileError::new(
                    format_args!("Expected base field type to be a struct but got {:?}", resolved_type)
                ))
            }
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
        ("name", "u64"),
        ("account_name", "u64"),

        ("symbol", "u64"),
        ("symbol_code", "u64"),

        ("rd160", "sum160"),
        ("checksum160", "sum160"),

        ("sha256", "sum256"),
        ("checksum256", "sum256"),

        ("checksum512", "sum512"),

        ("transaction_id", "sum256"),

        ("time_point", "u64"),
        ("time_point_sec", "u32"),
        ("block_timestamp_type", "u32"),

        ("public_key", "raw(34)"),
        ("signature", "raw(66)"),

    ] {
        aliases.insert(0, AbiTypeDef {
            new_type_name: new_type.to_string(),
            r#type: alias_type.to_string()
        });
    }

    let extra_structs = [
        AbiStruct{
            name: "asset".to_string(),
            base: String::default(),
            fields: vec![
                AbiField {name: "amount".to_string(), r#type: "i64".to_string()},
                AbiField {name: "symbol".to_string(), r#type: "u64".to_string()},
            ]
        },

        AbiStruct{
            name: "extended_asset".to_string(),
            base: String::default(),
            fields: vec![
                AbiField {name: "quantity".to_string(), r#type: "asset".to_string()},
                AbiField {name: "contract".to_string(), r#type: "name".to_string()},
            ]
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

impl SourceCode<
    AbiTypeDef,
    AbiField,
    AbiVariant,
    AbiStruct
> for AntelopeSourceCode {
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
        if let Some(t) = self.aliases.iter().find(|a| a.new_type_name == alias) {
            Some(t.r#type.clone())
        } else {
            None
        }
    }

    fn is_std_type(&self, ty: &str) -> bool {
        let ty = match self.resolve_alias(ty) {
            Some(ty) => ty,
            None => ty.to_string()
        };
        is_std_type!(&ty.as_str())
    }

    fn is_alias_of(&self, alias: &str, ty: &str) -> bool {
        self.aliases.iter()
            .any(|a| a.new_type_name == alias && a.r#type == ty)
    }

    fn is_variant(&self, ty: &str) -> bool {
        self.enums.iter().find(|e| e.name == ty).is_some()
    }

    fn is_variant_of(&self, ty: &str, var: &str) -> bool {
        match self.enums.iter()
            .find(|e| e.name == var) {
            Some(variant) => variant.types.contains(&ty.to_string()),
            None => false
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
        Value::Struct(HashMap::from(
            [
                ("amount".to_string(), value.amount().into()),
                ("symbol".to_string(), value.symbol().into()),
            ]
        ))
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
    T: Packer + Default, for<'a> Value: From<&'a T>,
{
    fn from(value: BinaryExtension<T>) -> Value {
        match value.value() {
            Some(v) => v.into(),
            None    => Value::None,
        }
    }
}

impl From<BinaryExtension<u128>> for Value {
    fn from(value: BinaryExtension<u128>) -> Value {
        match value.value() {
            Some(v) => v.clone().into(),
            None    => Value::None,
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
            ("threshold".to_string(), Value::Int(Integer::from(value.threshold))),
            ("keys".to_string(), value.keys.into()),
            ("accounts".to_string(), value.accounts.into()),
            ("waits".to_string(), value.waits.into()),
        ]))
    }
}

impl From<WaitWeight> for Value {
    fn from(value: WaitWeight) -> Self {
        Value::Struct(HashMap::from([
            ("wait_sec".to_string(), Value::Int(Integer::from(value.wait_sec))),
            ("weight".to_string(), Value::Int(Integer::from(value.weight))),
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
        match value.key_type {
            _ => Value::Struct(HashMap::from([
                ("key_type".to_string(), value.key_type.into()),
                ("value".to_string(), value.value.into()),
            ])),
        }
    }
}