pub mod antelope;

use std::collections::HashMap;
use crate::instruction_for;
use crate::isa::{Exception, Instruction};
use crate::isa::payload_base_size_of;
use crate::compiler_error;
use crate::utils::TypeCompileError;

#[macro_export]
macro_rules! compile_or_panic {
    ($maybe_err:expr) => {
        $maybe_err
            .unwrap_or_else(
                |e| panic!("Compiler error:{}", e.to_string())
            )
    };
}

#[macro_export]
macro_rules! compile_or_raise {
    ($maybe_err:expr, $($arg:tt)*) => {
        $maybe_err
            .map_err(
                |e| compiler_error!(
                    "{}:\n\t{}",
                    format!($($arg)*),
                    e.to_string()
                )
            )
    };
}

#[macro_export]
macro_rules! compile {
    ($src:expr, $name:expr) => {
        compile!($src, 0, $name)
    };
    ($src:expr, $pid:expr, $name:expr) => {
        compile_or_panic!(
            compile_program($src, $pid, $name.to_string())
        )
    };
}

#[macro_export]
macro_rules! compile_source {
    ($src:ident) => {
        compile_or_panic!(
            compile_source(&$src)
        )
    }
}

pub trait TypeAlias {
    fn new_type_name(&self) -> &str;
    fn from_type_name(&self) -> &str;
}

pub trait TypeDef {
    fn name(&self) -> &str;
    fn type_name(&self) -> &str;
}

pub trait EnumDef {
    fn name(&self) -> &str;
    fn variants(&self) -> &[String];
}

pub trait StructDef<
    T: TypeDef
> {
    fn name(&self) -> &str;
    fn fields(&self) -> &[T];
}

pub trait SourceCode<
    Alias: TypeAlias,
    Type: TypeDef,
    Enum: EnumDef,
    Struct: StructDef<Type>,
> {
    fn structs(&self) -> &[Struct];
    fn enums(&self) -> &[Enum];
    fn aliases(&self) -> &[Alias];
}


#[derive(Debug)]
pub struct Program {
    pub id: u64,
    pub name: String,
    pub code: Vec<Instruction>,
    pub base_size: usize,
}

impl Clone for Program {
    fn clone(&self) -> Self {
        Program {
            id: self.id,
            name: self.name.clone(),
            code: self.code.clone(),
            base_size: self.base_size,
        }
    }
}

fn compile_optional<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut opt_stack = Vec::new();
    compile_type(src, &type_name, &mut opt_stack)?;

    code.push(Instruction::Optional(opt_stack.len() as u8));
    compile_type(src, &type_name, code)?;
    Ok(())
}

fn compile_extension<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut ext_stack = Vec::new();
    compile_type(src, &type_name, &mut ext_stack)?;

    code.push(Instruction::Extension(ext_stack.len() as u8));
    compile_type(src, &type_name, code)?;
    Ok(())
}

fn compile_array<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut arr_stack = Vec::new();
    compile_type(src, &type_name, &mut arr_stack)?;

    code.push(Instruction::PushCND);
    // first instruction of array loop
    let array_ptr = code.len();
    compile_type(src, &type_name, code)?;
    code.push(Instruction::JmpNotCND(array_ptr, 0, -1));
    code.push(Instruction::PopCND);
    Ok(())
}

fn compile_enum<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    var_meta: &E,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut variants = Vec::new();
    for var_type in var_meta.variants() {
        let mut var_stack = Vec::new();
        compile_type(src, var_type, &mut var_stack)?;
        variants.push((var_type.clone(), var_stack));
    }

    let vars_count = variants.len();
    // location of PopCND, the first op in the structure
    let header_start_ptr = code.len();

    // one JmpCND for each var + initial PopCND + Raise post jump table
    let header_jmp_ops_count = vars_count + 1 + 1;
    // location of first var definition instruction
    let jmp_table_end_ptr = header_start_ptr + header_jmp_ops_count;

    // pre-calculate start ptr of each structure
    let mut current_ptr = jmp_table_end_ptr;
    let mut var_start_ptrs = Vec::new();
    // pre-calculate location of first instruction post variants code
    let mut end_ptr = jmp_table_end_ptr;
    for (i, (_, var_code)) in variants.iter().enumerate() {
        var_start_ptrs.push(current_ptr);
        current_ptr += var_code.len();
        end_ptr += var_code.len();
        // all but last variant impl have extra Jmp
        if i < vars_count - 1 {
            end_ptr += 1;
            current_ptr += 1;
        }
    }

    // finally build variant definition full code
    // set condition to the length of the array from the stack
    code.push(Instruction::PushCND);

    // variant index based jump table
    for (i, var_start_ptr) in var_start_ptrs.iter().enumerate() {
        code.push(Instruction::JmpCND(*var_start_ptr, i as isize, 0));
    }

    // add a raise immediately after jump table to guard against wrong var indexes on the stack
    code.push(Instruction::Raise(Exception::VariantIndexNotInJumpTable));

    // finally add each of the variant implementations code and their Jmp to post definition
    for (i, (var_name, _)) in variants.iter().enumerate() {
        // recompile actual var code in order to get correct jump ptrs
        compile_type(src, var_name, code)?;
        if i < vars_count - 1 {
            code.push(Instruction::Jmp(end_ptr));
        }
    }

    code.push(Instruction::PopCND);

    Ok(())
}

pub fn compile_type<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut _type = if let Some(type_meta) = src.aliases().iter().find(|t| t.new_type_name() == type_name) {
        type_meta.from_type_name().to_string()
    } else {
        type_name.to_string()
    };

    if let Some(mut std_op) = instruction_for!(_type.as_str()) {
        code.append(&mut std_op);
        return Ok(());
    }

    // Handle modifiers
    if _type.ends_with("?") {
        _type.pop();
        let maybe_err = compile_optional(src, &_type, code);
        return compile_or_raise!(
            maybe_err,
            "while compiling optional {}:",
            _type
        );
    }

    if _type.ends_with("[]") {
        _type.truncate(_type.len().saturating_sub(2));
        let maybe_err = compile_array(src, &_type, code);
        return compile_or_raise!(
            maybe_err,
            "while compiling array: {}",
            _type
        );
    }
    if _type.ends_with("$") {
        _type.pop();
        let maybe_err = compile_extension(src, &_type, code);
        return compile_or_raise!(
            maybe_err,
            "while compiling extension: {}",
            _type
        );
    }

    if let Some(var_meta) = src.enums().iter().find(|v| v.name() == _type) {
        let maybe_err = compile_enum(src, var_meta, code);
        return compile_or_raise!(
            maybe_err,
            "while compiling enum: {}",
            _type
        );
    }

    if let Some(struct_meta) = src.structs().iter().find(|s| s.name() == _type) {
        for field in struct_meta.fields() {
            let maybe_err = compile_type(src, field.type_name(), code);
            compile_or_raise!(
                maybe_err,
                "while compiling struct field {}.{}:",
                _type, field.name()
            )?;
        }
        return Ok(());
    }

    Err(compiler_error!("unknown type '{}'", _type))
}

pub fn compile_program<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    id: u64,
    name: String,
) -> Result<Program, TypeCompileError> {
    let mut code = Vec::new();
    compile_type(src, &name, &mut code)
        .map_err(|e| compiler_error!(
            "\n\tWhile compiling program {}:\n\t{}",
            name, e.to_string())
        )?;
    code.push(Instruction::Exit(0));
    let base_size = code.iter()
        .map(|op| payload_base_size_of(op))
        .sum();
    Ok(Program {
        id,
        name,
        code,
        base_size
    })
}
pub fn compile_source<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
) -> Result<HashMap<String, Program>, TypeCompileError> {
    let mut programs = HashMap::new();
    for variant in src.enums() {
        programs.insert(
            variant.name().to_string(),
            compile_program(
                src,
                programs.len() as u64,
                variant.name().to_string(),
            )?
        );
    }

    for struct_meta in src.structs() {
        programs.insert(
            struct_meta.name().to_string(),
            compile_program(
                src,
                programs.len() as u64,
                struct_meta.name().to_string(),
            )?
        );
    }

    for alias in src.aliases() {
        programs.insert(
            alias.new_type_name().to_string(),
            programs.get(&alias.from_type_name().to_string())
                .ok_or(compiler_error!("expected alias {} to already be resolved", alias.from_type_name()))?
                .clone()
        );
    }

    Ok(programs)
}