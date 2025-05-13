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
use itertools::Itertools;
use sha2::{Digest, Sha256};

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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeModifier {
    Array = 0,
    Optional = 1,
    Extension = 2
}

impl From<u8> for TypeModifier {
    fn from(value: u8) -> Self {
        match value {
            0 => TypeModifier::Array,
            1 => TypeModifier::Optional,
            2 => TypeModifier::Extension,
            _ => unreachable!()
        }
    }
}

impl From<TypeModifier> for u8 {
    fn from(value: TypeModifier) -> Self {
        value as u8
    }
}

pub const TRAP_COUNT: usize = 3;
pub const RESERVED_IDS: usize = 1 + STD_TYPES.len();

#[derive(Debug, Clone)]
pub struct RunTarget {
    pub pid: U48,
    pub modifier: Option<TypeModifier>,
}

impl RunTarget {
    pub fn new(pid: U48, modifier: Option<TypeModifier>) -> Self {
        Self { pid, modifier }
    }
}

impl From<(U48, Option<u8>)> for RunTarget {
    fn from(value: (U48, Option<u8>)) -> Self {
        let (pid, modifier) = value;
        let modifier = if let Some(modifier) = modifier {
            Some(match modifier {
                0 => TypeModifier::Array,
                1 => TypeModifier::Optional,
                2 => TypeModifier::Extension,
                _ => panic!("unexpected type modifier {modifier}!")
            })
        } else {
            None
        };
        RunTarget { pid, modifier }
    }
}

pub trait SourceCode<Alias: TypeAlias, Type: TypeDef, Enum: EnumDef, Struct: StructDef<Type>> {
    fn structs(&self) -> &[Struct];
    fn enums(&self) -> &[Enum];
    fn aliases(&self) -> &[Alias];
    fn resolve_alias(&self, alias: &str) -> Option<String>;

    fn resolve_modifier(&self, name: &str) -> Option<(String, TypeModifier)> {
        if name.ends_with("[]") {
            Some((name[..name.len() - 2].to_string(), TypeModifier::Array))
        } else if name.ends_with("?") {
            Some((name[..name.len() - 1].to_string(), TypeModifier::Optional))
        } else if name.ends_with("$") {
            Some((name[..name.len() - 1].to_string(), TypeModifier::Extension))
        } else {
            None
        }
    }

    // predicates
    fn is_std_type(&self, ty: &str) -> bool;
    fn is_alias_of(&self, alias: &str, ty: &str) -> bool;
    fn is_variant(&self, ty: &str) -> bool;
    fn is_variant_of(&self, ty: &str, var: &str) -> bool;

    fn program_id_for(&self, name: &str) -> Option<RunTarget> {
        let mut modifier = None;
        let name = if let Some((unmod_name, modi)) = self.resolve_modifier(name) {
            modifier = Some(modi);

            unmod_name
        } else {
            name.to_string()
        };

        let name = self.resolve_alias(&name).unwrap_or_else(|| name);

        let maybe_id = if let Some(id) = self.structs().iter().position(|s| s.name() == name) {
            Some((id + RESERVED_IDS).into())
        } else if let Some(id) = self.enums().iter().position(|s| s.name() == name) {
            Some((id + self.structs().len() + RESERVED_IDS).into())
        } else {
            None
        };

        if let Some(pid) = maybe_id {
            return Some(RunTarget::new(pid, modifier));
        }
        None
    }

    fn checksum(&self) -> [u8; 32] {
        let mut h = Sha256::new();

        for s in self.structs() {
            h.update(s.name().as_bytes());

            for f in s.fields() {
                h.update(f.name().as_bytes());
                h.update(f.type_name().as_bytes());
            }
        }

        for e in self.enums() {
            h.update(e.name().as_bytes());
            for v in e.variants() {
                h.update(v.as_bytes());
            }
        }

        for a in self.aliases() {
            h.update(a.from_type_name().as_bytes());
            h.update(a.new_type_name().as_bytes());
        }

        h.update(TRAP_COUNT.to_le_bytes());
        h.update(RESERVED_IDS.to_le_bytes());

        h.finalize().into()
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
        usize::from(self.id) - RESERVED_IDS + TRAP_COUNT
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

pub fn insert_reserved_strings(str_map: &mut BiHashMap<U48, String>) {
    str_map.insert(U48(0), "__reserved".to_string());
    for i in 1..RESERVED_IDS {
        str_map
            .insert(U48::from(i), format!("__reserved_{}", STD_TYPES[i - 1]));
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
        if let Some(trgt) = self.src.program_id_for(name) {
            return self.ns.get(&trgt.pid);
        }
        None
    }

    pub fn get_program(&self, id: &U48) -> Option<&Program> {
        self.ns.get(id)
    }

    pub fn get_program_or_init(&mut self, name: &str) -> Result<&mut Program, TypeCompileError> {
        let trgt = self
            .src
            .program_id_for(name)
            .ok_or(compiler_error!("Program \"{}\" unknown", name))?;

        Ok(self.ns.entry(trgt.pid).or_insert_with(|| Program {
            id: trgt.pid,
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

    pub fn is_empty(&self) -> bool {
        self.ns.is_empty()
    }

    pub fn sorted_str_map(&self) -> Vec<(&U48, &String)> {
        self.strings.iter()
            .sorted_by_key(|(k, _)| k.0)
            .collect()
    }

    pub fn calculate_string_map(&mut self) {
        self.strings.clear();

        insert_reserved_strings(&mut self.strings);

        for (id, name) in self.into_iter()
            .map(|p| (p.id.clone(), p.name.clone()))
            .collect::<Vec<(U48, String)>>()
        {
            self.strings.insert(id, name);
        }

        let mut field_id = U48::from(self.strings.len());
        for p_strings in self.into_iter()
            .map(|p| p.strings.clone())
            .collect::<Vec<Vec<String>>>()
        {
            for string in p_strings {
                if self.strings.contains_right(&string) {
                    continue;
                }
                self.strings.insert(field_id, string);
                field_id += U48(1);
            }
        }
        #[cfg(feature = "debug")]
        {
            let smap = self.sorted_str_map();
            debug_log!("Calulated string map: [");
            for entry in smap {
                debug_log!("\t{:?}", entry);
            }
            debug_log!("]");
        }
    }

    pub fn checksum(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.src.checksum());

        for (sid, str) in self.sorted_str_map() {
            h.update(&Into::<[u8; 6]>::into(sid));
            h.update(str.as_bytes());
        }

        h.finalize().into()
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
        let mut programs = self.ns.values().collect::<Vec<&Program>>();
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
        || src.structs().iter().any(|s| s.name() == type_name)
    {
        return Ok(Instruction::JmpRet(src.program_id_for(&type_name).ok_or(
            compiler_error!("Failed to resolve id of program: {}", type_name),
        )?.pid));
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

    code.push(Instruction::JmpArrayCND);
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

    if variants.len() == 1 {
        code.push(compile_type_ops(src, &variants[0], depth)?);
        return Ok(code)
    }

    let vars_count = variants.len();

    let end_ptr = vars_count * 2;

    // // variant index based jump table
    // for (i, _var_name) in var_meta.variants().iter().enumerate() {
    //     code.push(Instruction::JmpVariant(i as u32, (vars_count + i) as u16));
    // }

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
                src.program_id_for(var_meta.name()).ok_or(compiler_error!(
                    "Failed to resolve id of program: {}",
                    var_meta.name()
                ))?.pid,
            ));
            Ok(())
        } else {
            let maybe_err = compile_enum(src, var_meta, 3);
            let var_opts =
                ok_or_raise(maybe_err, format_args!("while compiling enum: {type_name}"))?;
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
                    ))?.pid,
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
