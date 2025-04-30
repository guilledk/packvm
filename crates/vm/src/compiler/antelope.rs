use antelope::chain::abi::{ABIResolvedType, ABITypeResolver, ABIView, AbiField, AbiStruct, AbiTypeDef, AbiVariant, ShipABI, ABI, STD_TYPES};
use antelope::chain::binary_extension::BinaryExtension;
use antelope::serializer::Packer;
use crate::compiler::{EnumDef, SourceCode, StructDef, TypeAlias, TypeDef};
use crate::{IOStackValue, Value};
use crate::utils::TypeCompileError;

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

fn include_antelope_stdtypes(aliases: &mut Vec<AbiTypeDef>) {
    for (new_type, alias_type) in [
        ("name", "u64"),
        ("checksum160", "sum160"),
        ("checksum256", "sum256"),
        ("checksum512", "sum512"),

        ("transaction_id", "sum256"),

        ("time_point", "u64"),
        ("time_point_sec", "u32"),
        ("block_timestamp_type", "u32"),

        ("public_key", "raw"),
        ("signature", "raw")

    ] {
        aliases.insert(0, AbiTypeDef {
            new_type_name: new_type.to_string(),
            r#type: alias_type.to_string()
        });
    }
}

impl TryFrom<ABI> for AntelopeSourceCode {
    type Error = TypeCompileError;
    fn try_from(abi: ABI) -> Result<AntelopeSourceCode, TypeCompileError> {
        let mut aliases = abi.types().to_vec();
        include_antelope_stdtypes(&mut aliases);

        let enums = abi.variants().to_vec();
        let mut structs = abi.structs().to_vec();
        for struct_def in structs.iter_mut() {
            expand_struct_base(&abi, struct_def)?;
        }
        Ok(AntelopeSourceCode {
            aliases,
            enums,
            structs
        })
    }
}

impl TryFrom<ShipABI> for AntelopeSourceCode {
    type Error = TypeCompileError;
    fn try_from(abi: ShipABI) -> Result<AntelopeSourceCode, TypeCompileError> {
        let mut aliases = abi.types().to_vec();
        include_antelope_stdtypes(&mut aliases);

        let enums = abi.variants().to_vec();
        let mut structs = abi.structs().to_vec();
        for struct_def in structs.iter_mut() {
            expand_struct_base(&abi, struct_def)?;
        }
        Ok(AntelopeSourceCode {
            aliases,
            enums,
            structs
        })
    }
}

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
        STD_TYPES.contains(&ty.as_str())
    }

    fn is_alias_of(&self, alias: &str, ty: &str) -> bool {
        self.aliases.iter()
            .any(|a| a.new_type_name == alias && a.r#type == ty)
    }

    fn is_variant_of(&self, ty: &str, var: &str) -> bool {
        match self.enums.iter()
            .find(|e| e.name == var) {
            Some(variant) => variant.types.contains(&ty.to_string()),
            None => false
        }
    }
}

impl<T: IOStackValue> IOStackValue for BinaryExtension<T>
where
    T: Packer + Default,
{
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        match &self.value {
            Some(v) => v.push_to_stack(out),
            None    => out.push(Value::None),
        }
    }
}
