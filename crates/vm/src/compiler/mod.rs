pub mod antelope;
pub mod assembly;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use crate::{debug_log, instruction_for};
use crate::isa::Instruction;
use crate::isa::payload_base_size_of;
use crate::compiler_error;
use crate::utils::TypeCompileError;

#[inline(always)]
pub fn ok_or_panic<T, E: Error>(maybe_err: Result<T, E>) -> T {{
    maybe_err
        .unwrap_or_else(
            |e| panic!("Compiler error: {}", e.to_string())
        )
}}

#[inline(always)]
pub fn ok_or_raise<
    Args: fmt::Display,
    T,
    E: Error
>(maybe_err: Result<T, E>, args: Args) -> Result<T, TypeCompileError> {
    maybe_err
        .map_err(
            |e| compiler_error!(
                "{}:\n\t{}",
                format!("{}", args),
                e.to_string()
            )
        )
}

#[macro_export]
macro_rules! compile {
    ($src:expr, $name:expr) => {{
        compile!($src, 0, $name)
    }};
    ($src:expr, $pid:expr, $name:expr) => {{
        let mut ns = ::packvm::compiler::ProgramNamespace::default();
        ::packvm::compiler::ok_or_panic(
            ::packvm::compiler::compile_program($src, $name.to_string(), &mut ns)
        );
        ns.get_program($name).unwrap().clone()
    }};
}

#[macro_export]
macro_rules! compile_source {
    ($src:ident) => {
        ::packvm::compiler::ok_or_panic(
            ::packvm::compiler::compile_source(&$src)
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
    fn resolve_alias(&self, alias: &str) -> Option<String>;

    fn is_std_type(&self, ty: &str) -> bool;
    fn is_alias_of(&self, alias: &str, ty: &str) -> bool;

    fn is_variant_of(&self, ty: &str, var: &str) -> bool;
}

pub struct Program {
    pub id: u64,
    pub name: String,
    pub code: Vec<Instruction>,
    pub deps: HashSet<String>,
    pub base_size: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ProgramNamespace {
    ns: HashMap<String, Program>,
}

impl ProgramNamespace {

    pub fn get_program(&self, name: &str) -> Option<&Program> {
        self.ns.get(name)
    }

    pub fn get_program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.ns.get_mut(name)
    }
    pub fn get_program_or_init(&mut self, name: &str) -> &mut Program {
        if self.ns.contains_key(name) {
            return self.ns.get_mut(name).unwrap()
        }
        let prog = Program {
            id: self.ns.len() as u64,
            name: name.to_string(),
            code: Vec::new(),
            deps: HashSet::new(),
            base_size: 0,
        };
        self.ns.insert(name.to_string(), prog);
        self.ns.get_mut(name).unwrap()
    }

    pub fn len(&self) -> usize {
        self.ns.len()
    }
}

impl<'a> IntoIterator for &'a ProgramNamespace {
    type Item = &'a Program;
    type IntoIter = std::vec::IntoIter<&'a Program>;

    fn into_iter(self) -> Self::IntoIter {
        let mut programs = self.ns.iter()
            .map(|(_name, prog)| prog)
            .collect::<Vec<&Program>>();
        programs.sort_by(|a, b| a.id.cmp(&b.id));
        programs.into_iter()
    }
}

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Program[{}] \"{}\"\nbase size: {}\ndeps: {:?}\n",
            self.id, self.name, self.base_size, self.deps
        )?;
        writeln!(f, "Code: [")?;
        for (idx, op) in self.code.iter().enumerate() {
            writeln!(f, "\t{:3}: {:?}", idx, op)?;
        }
        writeln!(f, "]")
    }
}

impl Clone for Program {
    fn clone(&self) -> Self {
        Program {
            id: self.id,
            name: self.name.clone(),
            code: self.code.clone(),
            deps: self.deps.clone(),
            base_size: self.base_size,
        }
    }
}

#[cfg_attr(not(feature = "debug"), allow(unused_variables))]
pub fn compile_type_ops<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    type_name: &str,
    depth: usize
) -> Result<Instruction, TypeCompileError> {
    debug_log!(
        "{}Compile type ops for: {}",
        "\t".repeat(depth),
        type_name
    );

    let type_name = match src.resolve_alias(type_name) {
        Some(t) => t,
        None => type_name.to_string(),
    };

    if let Some(std_op) = instruction_for!(type_name.as_str()) {
        return Ok(std_op);
    }

    if let Some(_var_meta) = src.enums().iter().find(|v| v.name() == type_name) {
        return Ok(Instruction::ProgramJmp {name: type_name.to_string(), ptr: 0, ret: 0});
    }

    if let Some(_struct_meta) = src.structs().iter().find(|s| s.name() == type_name) {
        return Ok(Instruction::ProgramJmp {name: type_name.to_string(), ptr: 0, ret: 0});
    }

    Err(compiler_error!("unknown or not resolved type '{}'", type_name))
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
    depth: usize
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    debug_log!(
        "{}Compile optional: {}",
        "\t".repeat(depth),
        type_name
    );
    code.push(Instruction::Optional);
    code.push(compile_type_ops(src, type_name, depth)?);
    Ok(code)
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
    depth: usize
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    debug_log!(
        "{}Compile extension: {}",
        "\t".repeat(depth),
        type_name
    );
    code.push(Instruction::Optional);
    code.push(compile_type_ops(src, type_name, depth)?);
    Ok(code)
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
    depth: usize
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    debug_log!(
        "{}Compile array: {}",
        "\t".repeat(depth),
        type_name
    );

    code.push(Instruction::PushCND);

    code.push(compile_type_ops(src, type_name, depth)?);

    code.push(Instruction::JmpNotCND{
        ptrdelta: -1,
        value: 0,
        delta: -1
    });

    code.push(Instruction::PopCND);

    Ok(code)
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
    depth: usize
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();

    debug_log!(
        "{}Compile enum: {}",
        "\t".repeat(depth),
        var_meta.name()
    );

    let variants = var_meta.variants();

    if variants.len() == 1 {
        code.push(Instruction::PushCND);
        code.push(compile_type_ops(src, &variants[0], depth)?);
        code.push(Instruction::PopCND);
        return Ok(code)
    }

    let vars_count = variants.len();

    let end_ptr = (vars_count * 3) + 1;

    // finally build variant definition full code
    // set condition to the length of the array from the stack
    code.push(Instruction::PushCND);

    // variant index based jump table
    for (i, _var_name) in var_meta.variants().iter().enumerate() {
        code.push(Instruction::JmpCND{
            ptrdelta: (i + vars_count + 1) as isize,
            value: i as isize,
            delta: 0
        });
    }

    #[cfg(feature = "debug")]
    {
        // add a raise immediately after jump table to guard against wrong var indexes on the stack
        code.push(Instruction::Raise { ex: crate::Exception::VariantIndexNotInJumpTable });
    }

    // finally add each of the variant implementations code and their Jmp to post definition
    for (i, var_name) in var_meta.variants().iter().enumerate() {
        code.push(compile_type_ops(src, var_name, depth + 1)?);
        if vars_count - i > 1 {
            code.push(Instruction::Jmp{
                info: format!("end of {}", var_meta.name()), ptr: end_ptr
            });
        }
    }

    code.push(Instruction::PopCND);

    Ok(code)
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
    program: &mut Program,
) -> Result<(), TypeCompileError> {
    debug_log!("\t\tCompile type: {}", type_name);

    let mut type_name = match src.resolve_alias(type_name) {
        Some(resolved) => resolved,
        None => type_name.to_string()
    };

    if let Some(op) = instruction_for!(type_name.as_str()) {
        program.code.push(op);
        return Ok(());
    }

    if type_name.ends_with("?") {
        type_name.pop();
        let maybe_err = compile_optional(src, &type_name, 3);
        let opt_code = ok_or_raise(
            maybe_err,
            format_args!(
                "while compiling optional {}:", type_name
            )
        )?;
        program.code.extend(opt_code);
        return Ok(());
    }

    if type_name.ends_with("$") {
        type_name.pop();
        let maybe_err = compile_extension(src, &type_name, 3);
        let ext_code = ok_or_raise(
            maybe_err,
            format_args!(
                "while compiling extension: {}",
                type_name
            )
        )?;
        program.code.extend(ext_code);
        return Ok(());
    }

    if type_name.ends_with("[]") {
        type_name.truncate(type_name.len().saturating_sub(2));
        let maybe_err = compile_array(src, &type_name, 3);
        let arr_code = ok_or_raise(
            maybe_err,
            format_args!(
                "while compiling array: {}",
                type_name
            )
        )?;
        program.code.extend(arr_code);
        return Ok(());
    }

    if let Some(var_meta) = src.enums().iter().find(|v| v.name() == type_name) {
        if program.name != var_meta.name() {
            program.code.push(Instruction::ProgramJmp {
                name: var_meta.name().to_string(),
                ptr: 0,
                ret: 0
            });
            return Ok(());
        } else {
            let maybe_err = compile_enum(src, var_meta, 3);
            let var_opts = ok_or_raise(
                maybe_err,
                format_args!(
                    "while compiling enum: {}",
                    type_name
                )
            )?;
            program.code.extend(var_opts);
            return Ok(());
        }
    }

    if let Some(struct_meta) = src.structs().iter().find(|s| s.name() == type_name) {
        for field in struct_meta.fields() {
            match instruction_for!(field.type_name()) {
                Some(op) => program.code.push(op),
                None => {
                    // program.code.push(Instruction::ProgramJmp {
                    //     name: field.type_name().to_string(),
                    //     ptr: 0, ret: 0
                    // });
                    compile_type(src, &field.type_name(), program)?;
                },
            }
        }
        return Ok(());
    }

    Err(compiler_error!("unknown type '{}'", type_name))
}

pub fn compile_program<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
    program_name: String,
    namespace: &mut ProgramNamespace
) -> Result<(), TypeCompileError> {
    debug_log!("\tCompile program: {}", program_name);

    if src.is_std_type(&program_name) {
        return Ok(());
    }

    if src.resolve_alias(&program_name).is_some() {
        return Ok(())
    }

    let mut program = namespace.get_program_or_init(&program_name);

    compile_type(src, &program_name, &mut program)
        .map_err(|e| compiler_error!(
            "\n\tWhile compiling program {}:\n\t{}",
            program_name, e.to_string())
        )?;

    // gather dependencies
    for op in program.code.iter() {
        match op {
            Instruction::ProgramJmp {
                name, ptr: _, ret: _
            } => {
                program.deps.insert(name.clone());
            },
            _ => ()
        }
    }

    program.code.push(Instruction::Exit);
    program.base_size = program.code.iter()
        .map(|op| payload_base_size_of(op))
        .sum();

    Ok(())
}
pub fn compile_source<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S>,
>(
    src: &Source,
) -> Result<ProgramNamespace, TypeCompileError> {
    let mut ns = ProgramNamespace::default();
    debug_log!("Compile source structs...");
    for struct_meta in src.structs() {
        compile_program(
            src,
            struct_meta.name().to_string(),
            &mut ns
        )?
    }

    debug_log!("Compile source enums...");
    for variant in src.enums() {
        compile_program(
            src,
            variant.name().to_string(),
            &mut ns
        )?;
    }

    Ok(ns)
}