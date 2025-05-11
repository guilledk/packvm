pub mod antelope;
pub mod assembly;

pub use assembly::assemble;

use crate::compiler_error;
use crate::isa::{DataInstruction, Instruction, STD_TYPES};
use crate::utils::numbers::U48;
use crate::utils::TypeCompileError;
use crate::{debug_log, instruction_for};
use bimap::BiHashMap;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

#[inline(always)]
pub fn ok_or_panic<T, E: Error>(maybe_err: Result<T, E>) -> T {
    {
        maybe_err.unwrap_or_else(|e| panic!("Compiler error:\n\t{e}"))
    }
}

#[inline(always)]
pub fn ok_or_raise<Args: fmt::Display, T, E: Error>(
    maybe_err: Result<T, E>,
    args: Args,
) -> Result<T, TypeCompileError> {
    maybe_err.map_err(|e| compiler_error!("{}:\n\t{}", format!("{}", args), e.to_string()))
}

#[macro_export]
macro_rules! compile {
    ($src:expr, $name:expr) => {{
        compile!($src, 0, $name)
    }};
    ($src:expr, $pid:expr, $name:expr) => {{
        let mut ns = ::packvm::compiler::ProgramNamespace::default();
        ::packvm::compiler::ok_or_panic(::packvm::compiler::compile_program(
            $src,
            $name.to_string(),
            &mut ns,
        ));
        ns.get_program($name).unwrap().clone()
    }};
}

#[macro_export]
macro_rules! compile_source {
    ($src:ident) => {
        ::packvm::compiler::ok_or_panic(::packvm::compiler::compile_source(&$src))
    };
}

#[macro_export]
macro_rules! get_str_or_unknown {
    ($str_map:expr, $id:expr) => {
        match $str_map.get_by_left($id) {
            Some(s) => s.clone(),
            None => format!("unknown str({})", $id),
        }
    };
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

pub trait StructDef<T: TypeDef> {
    fn name(&self) -> &str;
    fn fields(&self) -> &[T];
}

pub const RESERVED_IDS: usize = 1 + STD_TYPES.len();

pub trait SourceCode<Alias: TypeAlias, Type: TypeDef, Enum: EnumDef, Struct: StructDef<Type>> {
    fn structs(&self) -> &[Struct];
    fn enums(&self) -> &[Enum];
    fn aliases(&self) -> &[Alias];
    fn resolve_alias(&self, alias: &str) -> Option<String>;

    // predicates
    fn is_std_type(&self, ty: &str) -> bool;
    fn is_alias_of(&self, alias: &str, ty: &str) -> bool;
    fn is_variant(&self, ty: &str) -> bool;
    fn is_variant_of(&self, ty: &str, var: &str) -> bool;

    fn program_id_for(&self, name: &str) -> Option<U48> {
        let name = match self.resolve_alias(name) {
            Some(name) => name,
            None => name.to_string(),
        };

        if let Some(id) = self.structs().iter().position(|s| s.name() == name) {
            return Some((id + RESERVED_IDS).into());
        }

        if let Some(id) = self.enums().iter().position(|s| s.name() == name) {
            return Some((id + self.structs().len() + RESERVED_IDS).into());
        }

        None
    }
}

pub struct Program {
    pub id: U48,
    pub name: String,

    pub code: Vec<Instruction>,
    pub deps: HashSet<U48>,
    pub strings: Vec<String>,
}

impl Program {
    pub fn index(&self) -> usize {
        usize::from(self.id) - RESERVED_IDS
    }
}

impl Default for Program {
    fn default() -> Self {
        Self {
            id: U48::from(RESERVED_IDS),
            name: Default::default(),
            code: Default::default(),
            deps: Default::default(),
            strings: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProgramNamespace<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
> {
    src: Source,
    ns: HashMap<U48, Program>,
    strings: BiHashMap<U48, String>,
    _marker: PhantomData<(A, T, E, S)>,
}

impl<
        A: TypeAlias,
        T: TypeDef,
        E: EnumDef,
        S: StructDef<T>,
        Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
    > ProgramNamespace<A, T, E, S, Source>
{
    pub fn from_source(src: &Source) -> Self {
        Self {
            src: src.clone(),
            ns: HashMap::default(),
            strings: BiHashMap::default(),
            _marker: PhantomData,
        }
    }

    pub fn get_program_by_name(&self, name: &str) -> Option<&Program> {
        if let Some(id) = self.src.program_id_for(name) {
            return self.ns.get(&id);
        }
        None
    }

    pub fn get_program(&self, id: &U48) -> Option<&Program> {
        self.ns.get(id)
    }

    pub fn get_program_or_init(&mut self, name: &str) -> Result<&mut Program, TypeCompileError> {
        let id = self
            .src
            .program_id_for(name)
            .ok_or(compiler_error!("Program \"{}\" unknown", name))?;

        Ok(self.ns.entry(id).or_insert_with(|| Program {
            id,
            name: name.to_string(),
            code: Vec::new(),
            deps: HashSet::new(),
            strings: Vec::new(),
        }))
    }

    pub fn set_program(&mut self, program: Program) -> Option<Program> {
        self.ns.insert(program.id, program)
    }

    pub fn len(&self) -> usize {
        self.ns.len()
    }

    pub fn calculate_string_map(&mut self) {
        self.strings.clear();

        // insert reserved strings
        self.strings.insert(U48(0), "__reserved".to_string());
        for i in 1..RESERVED_IDS {
            self.strings
                .insert(U48::from(i), format!("__reserved_{}", STD_TYPES[i - 1]));
        }

        let mut field_id = U48::from(self.len() + RESERVED_IDS);
        for program in self.into_iter().cloned().collect::<Vec<Program>>() {
            self.strings.insert(program.id, program.name.clone());
            for string in &program.strings {
                if self.strings.contains_right(string) {
                    continue;
                }
                self.strings.insert(field_id, string.clone());
                field_id += U48(1);
            }
        }
        #[cfg(feature = "debug")]
        {
            let mut strings = self
                .strings
                .iter()
                .map(|(id, s)| (*id, s.clone()))
                .collect::<Vec<(U48, String)>>();
            strings.sort();
            debug_log!("Calulated string map: [");
            for s in strings {
                debug_log!("{:?}", s);
            }
            debug_log!("]");
        }
    }
}

impl<
        'a,
        A: TypeAlias,
        T: TypeDef,
        E: EnumDef,
        S: StructDef<T>,
        Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
    > IntoIterator for &'a ProgramNamespace<A, T, E, S, Source>
{
    type Item = &'a Program;
    type IntoIter = std::vec::IntoIter<&'a Program>;

    fn into_iter(self) -> Self::IntoIter {
        let mut programs = self
            .ns.values()
            .collect::<Vec<&Program>>();
        programs.sort_by(|a, b| a.id.cmp(&b.id));
        programs.into_iter()
    }
}

impl Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Program[{}] \"{}\"\ndeps: {:?}\n",
            self.id, self.name, self.deps
        )?;
        writeln!(f, "Code: [")?;
        for (idx, op) in self.code.iter().enumerate() {
            writeln!(f, "\t{idx:3}: {op:?}")?;
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
    depth: usize,
) -> Result<Instruction, TypeCompileError> {
    debug_log!("{}Compile type ops for: {}", "\t".repeat(depth), type_name);

    let type_name = match src.resolve_alias(type_name) {
        Some(t) => t,
        None => type_name.to_string(),
    };

    if let Some(std_op) = instruction_for!(type_name.as_str()) {
        return Ok(Instruction::IO(std_op));
    }

    if src.enums().iter().any(|v| v.name() == type_name)
        || src
            .structs()
            .iter()
            .any(|s| s.name() == type_name)
    {
        return Ok(Instruction::JmpRet(
            src.program_id_for(&type_name)
                .ok_or(compiler_error!(
                    "Failed to resolve id of program: {}",
                    type_name
                ))?,
        ));
    }

    Err(compiler_error!(
        "unknown or not resolved type '{}'",
        type_name
    ))
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
    depth: usize,
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    debug_log!("{}Compile optional: {}", "\t".repeat(depth), type_name);
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
    depth: usize,
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    debug_log!("{}Compile extension: {}", "\t".repeat(depth), type_name);
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
    depth: usize,
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    debug_log!("{}Compile array: {}", "\t".repeat(depth), type_name);

    code.push(Instruction::PushCND);

    code.push(compile_type_ops(src, type_name, depth)?);

    code.push(Instruction::JmpArrayCND(U48(0))); // ptr will be filled by assembler == final pos of instruction - 1
    code.push(Instruction::PopCursor);

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
    depth: usize,
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();

    debug_log!("{}Compile enum: {}", "\t".repeat(depth), var_meta.name());

    let variants = var_meta.variants();

    // if variants.len() == 1 {
    //     code.push(Instruction::PushCND(1));
    //     code.push(compile_type_ops(src, &variants[0], depth)?);
    //     code.push(Instruction::PopCND);
    //     return Ok(code)
    // }

    let vars_count = variants.len();

    let end_ptr = vars_count * 3;

    // variant index based jump table
    for (i, _var_name) in var_meta.variants().iter().enumerate() {
        code.push(Instruction::JmpVariant(i as u32, (vars_count + i) as u16));
    }

    // finally add each of the variant implementations code and their Jmp to post definition
    for (i, var_name) in var_meta.variants().iter().enumerate() {
        code.push(compile_type_ops(src, var_name, depth + 1)?);
        if vars_count - i > 1 {
            code.push(Instruction::Jmp(end_ptr.into()));
        }
    }

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
        None => type_name.to_string(),
    };

    if let Some(op) = instruction_for!(type_name.as_str()) {
        program.code.push(Instruction::IO(op));
        return Ok(());
    }

    if type_name.ends_with("?") {
        type_name.pop();
        let maybe_err = compile_optional(src, &type_name, 3);
        let opt_code = ok_or_raise(
            maybe_err,
            format_args!("while compiling optional {type_name}:"),
        )?;
        program.code.extend(opt_code);
        return Ok(());
    }

    if type_name.ends_with("$") {
        type_name.pop();
        let maybe_err = compile_extension(src, &type_name, 3);
        let ext_code = ok_or_raise(
            maybe_err,
            format_args!("while compiling extension: {type_name}"),
        )?;
        program.code.extend(ext_code);
        return Ok(());
    }

    if type_name.ends_with("[]") {
        type_name.truncate(type_name.len().saturating_sub(2));
        let maybe_err = compile_array(src, &type_name, 3);
        let arr_code = ok_or_raise(
            maybe_err,
            format_args!("while compiling array: {type_name}"),
        )?;
        program.code.extend(arr_code);
        return Ok(());
    }

    if let Some(var_meta) = src.enums().iter().find(|v| v.name() == type_name) {
        return if program.name != var_meta.name() {
            program.code.push(Instruction::JmpRet(
                src.program_id_for(var_meta.name())
                    .ok_or(compiler_error!(
                        "Failed to resolve id of program: {}",
                        var_meta.name()
                    ))?,
            ));
            Ok(())
        } else {
            let maybe_err = compile_enum(src, var_meta, 3);
            let var_opts = ok_or_raise(
                maybe_err,
                format_args!("while compiling enum: {type_name}"),
            )?;
            program.code.extend(var_opts);
            Ok(())
        };
    }

    if let Some(struct_meta) = src.structs().iter().find(|s| s.name() == type_name) {
        return if program.name != struct_meta.name() {
            program.code.push(Instruction::JmpRet(
                src.program_id_for(struct_meta.name())
                    .ok_or(compiler_error!(
                        "Failed to resolve id of program: {}",
                        struct_meta.name()
                    ))?,
            ));
            Ok(())
        } else {
            for (i, field) in struct_meta.fields().iter().enumerate() {
                program.code.push(Instruction::Field(i.into()));
                program.strings.push(field.name().to_string());
                match instruction_for!(field.type_name()) {
                    Some(op) => program.code.push(Instruction::IO(op)),
                    None => {
                        compile_type(src, field.type_name(), program)?;
                    }
                }
            }
            Ok(())
        };
    }

    Err(compiler_error!("unknown type '{}'", type_name))
}

pub fn compile_program<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
>(
    src: &Source,
    program_name: String,
    namespace: &mut ProgramNamespace<A, T, E, S, Source>,
) -> Result<(), TypeCompileError> {
    debug_log!("\tCompile program: {}", program_name);

    if src.is_std_type(&program_name) {
        debug_log!("\t\t{} is a standard type, skip...", program_name);
        return Ok(());
    }

    if src.resolve_alias(&program_name).is_some() {
        debug_log!("\t\t{} is an alias, skip...", program_name);
        return Ok(());
    }

    let program = namespace.get_program_or_init(&program_name)?;

    compile_type(src, &program_name, program).map_err(|e| {
        compiler_error!(
            "\n\tWhile compiling program {}:\n\t{}",
            program_name,
            e.to_string()
        )
    })?;

    let ctype = if src.is_variant(&program_name) {
        1u8
    } else {
        2u8
    };

    // gather dependencies
    for op in program.code.iter() {
        if let Instruction::JmpRet(id) = op {
            program.deps.insert(*id);
        }
    }

    program
        .code
        .insert(0, Instruction::Section(ctype, program.id));

    if ctype == 2u8 {
        program.code.push(Instruction::PopCursor);
    }
    program.code.push(Instruction::Exit);

    debug_log!("\t\t{} compiled.", program_name);

    Ok(())
}
pub fn compile_source<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
>(
    src: &Source,
) -> Result<ProgramNamespace<A, T, E, S, Source>, TypeCompileError> {
    let mut ns = ProgramNamespace::from_source(src);
    debug_log!("Compile source structs...");
    for struct_meta in src.structs() {
        compile_program(src, struct_meta.name().to_string(), &mut ns)?
    }

    debug_log!("Compile source enums...");
    for variant in src.enums() {
        compile_program(src, variant.name().to_string(), &mut ns)?;
    }

    ns.calculate_string_map();

    Ok(ns)
}
