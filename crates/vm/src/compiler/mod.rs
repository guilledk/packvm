pub mod antelope;
pub mod assembly;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use bimap::BiHashMap;
use crate::{debug_log, instruction_for};
use crate::isa::Instruction;
use crate::isa::payload_base_size_of;
use crate::compiler_error;
use crate::utils::{TypeCompileError};

#[inline(always)]
pub fn ok_or_panic<T, E: Error>(maybe_err: Result<T, E>) -> T {{
    maybe_err
        .unwrap_or_else(
            |e| panic!("Compiler error:\n\t{}", e.to_string())
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

    // predicates
    fn is_std_type(&self, ty: &str) -> bool;
    fn is_alias_of(&self, alias: &str, ty: &str) -> bool;
    fn is_variant(&self, ty: &str) -> bool;
    fn is_variant_of(&self, ty: &str, var: &str) -> bool;

    fn program_id_for(&self, name: &str) -> Option<usize> {
        if let Some(id) = self.structs().iter().position(|s| s.name() == name) {
            return Some(id);
        }

        if let Some(id) = self.enums().iter().position(|s| s.name() == name) {
            return Some(id + self.structs().len());
        }

        None
    }
}

#[derive(Default)]
pub struct Program {
    pub id: usize,
    pub name: String,

    pub code: Vec<Instruction>,
    pub deps: HashSet<usize>,
    pub strings: Vec<String>,

    pub base_size: usize,
}

#[derive(Debug, Clone)]
pub struct ProgramNamespace<
    'a,
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Debug
> {
    src: &'a Source,
    ns: HashMap<usize, Program>,
    strings: BiHashMap<usize, String>,
    _marker: PhantomData<(A, T, E, S)>,
}

impl<
    'a,
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Debug
> ProgramNamespace<'a, A, T, E, S, Source> {
    pub fn from_source(src: &'a Source) -> Self {
        Self {
            src,
            ns: HashMap::default(),
            strings: BiHashMap::default(),
            _marker: PhantomData::default(),
        }
    }

    pub fn get_program_by_name(&self, name: &str) -> Option<&Program> {
        if let Some(id) = self.src.program_id_for(name) {
            return self.ns.get(&id);
        }
        None
    }

    pub fn get_program(&self, id: &usize) -> Option<&Program> {
        self.ns.get(id)
    }

    pub fn get_program_or_init(&mut self, name: &str) -> Result<&mut Program, TypeCompileError> {
        let id = self.src.program_id_for(name)
            .ok_or(compiler_error!("Program \"{}\" unknown", name))?;

        Ok(self.ns.entry(id).or_insert_with(|| {
            Program {
                id,
                name: name.to_string(),
                code: Vec::new(),
                deps: HashSet::new(),
                strings: Vec::new(),
                base_size: 0,
            }
        }))
    }

    pub fn len(&self) -> usize {
        self.ns.len()
    }

    pub fn calculate_string_map(&mut self) -> () {
        self.strings.clear();
        let mut field_id = self.len();
        for program in self.ns.values().collect::<Vec<&Program>>() {
            self.strings.insert(program.id, program.name.clone());
            for string in &program.strings {
                if self.strings.contains_right(string) {
                    continue;
                }
                self.strings.insert(field_id, string.clone());
                field_id += 1;
            }
        }
    }
}

impl<
    'a,
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Debug
> IntoIterator for &'a ProgramNamespace<'a, A, T, E, S, Source> {
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

impl Debug for Program {
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
            strings: self.strings.clone(),
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

    if src.enums().iter().find(|v| v.name() == type_name).is_some() ||
        src.structs().iter().find(|s| s.name() == type_name).is_some() {
        return Ok(Instruction::JmpRet {
            ptr: src.program_id_for(&type_name)
                .ok_or(
                    compiler_error!("Failed to resolve id of program: {}", type_name)
                )?.clone(),
        });
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
    code.push(Instruction::Extension);
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

    code.push(Instruction::PushCND(0));

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
        code.push(Instruction::PushCND(1));
        code.push(compile_type_ops(src, &variants[0], depth)?);
        code.push(Instruction::PopCND);
        return Ok(code)
    }

    let vars_count = variants.len();

    let end_ptr = (vars_count * 3) + 1;

    // finally build variant definition full code
    // set condition to the length of the array from the stack
    code.push(Instruction::PushCND(1));

    // variant index based jump table
    for (i, _var_name) in var_meta.variants().iter().enumerate() {
        code.push(Instruction::JmpCND{
            ptrdelta: (i + vars_count) as isize,
            value: i as isize,
            delta: 0
        });
    }

    // finally add each of the variant implementations code and their Jmp to post definition
    for (i, var_name) in var_meta.variants().iter().enumerate() {
        code.push(compile_type_ops(src, var_name, depth + 1)?);
        if vars_count - i > 1 {
            code.push(Instruction::Jmp{ptr: end_ptr});
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
            program.code.push(Instruction::JmpRet {
                ptr: src.program_id_for(var_meta.name())
                    .ok_or(compiler_error!("Failed to resolve id of program: {}", var_meta.name()))?
                    .clone(),
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
        for (i, field) in struct_meta.fields().iter().enumerate() {
            program.code.push(Instruction::Field(i));
            program.strings.push(field.name().to_string());
            match instruction_for!(field.type_name()) {
                Some(op) => program.code.push(op),
                None => {
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
    Source: SourceCode<A, T, E, S> + Debug,
>(
    src: &Source,
    program_name: String,
    namespace: &mut ProgramNamespace<A, T, E, S, Source>,
) -> Result<(), TypeCompileError> {
    debug_log!("\tCompile program: {}", program_name);

    if src.is_std_type(&program_name) {
        return Ok(());
    }

    if src.resolve_alias(&program_name).is_some() {
        return Ok(())
    }

    let mut program = namespace.get_program_or_init(&program_name)?;

    compile_type(src, &program_name, &mut program)
        .map_err(|e| compiler_error!(
            "\n\tWhile compiling program {}:\n\t{}",
            program_name, e.to_string())
        )?;

    let ctype = if src.is_variant(&program_name) {
        1u8
    } else {
        2u8
    };

    program.code.insert(
        0,
        Instruction::Section(
            ctype,
            program.id
        )
    );

    // gather dependencies
    for op in program.code.iter() {
        match op {
            Instruction::JmpRet {
                ptr: id
            } => {
                program.deps.insert(*id);
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
    Source: SourceCode<A, T, E, S> + Debug,
>(
    src: &Source,
) -> Result<ProgramNamespace<A, T, E, S, Source>, TypeCompileError> {
    let mut ns = ProgramNamespace::from_source(src);
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

    ns.calculate_string_map();

    Ok(ns)
}