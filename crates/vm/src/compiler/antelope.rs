use antelope::chain::abi::{ABIResolvedType, ABITypeResolver, ABIView, AbiField, AbiStruct, AbiTypeDef, AbiVariant, ShipABI, ABI};
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

impl TryFrom<ABI> for AntelopeSourceCode {
    type Error = TypeCompileError;
    fn try_from(abi: ABI) -> Result<AntelopeSourceCode, TypeCompileError> {
        let aliases = abi.types().to_vec();
        let enums = abi.variants().to_vec();
        let mut structs = abi.structs().to_vec();
        for struct_def in structs.iter_mut() {
            expand_struct_base(&abi, struct_def)?;
        }
        println!("{:#?}\n{:#?}\n{:#?}", aliases, enums, structs);
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
        let aliases = abi.types().to_vec();
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
