use crate::compiler::{EnumDef, ProgramNamespace, SourceCode, StructDef, TypeAlias, TypeDef};
use crate::compiler_error;
use crate::isa::Instruction;
use crate::utils::numbers::U48;
use crate::utils::TypeCompileError;
use crate::{debug_log, get_str_or_unknown};
use bimap::BiHashMap;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

#[macro_export]
macro_rules! assemble {
    ($src_ns:expr) => {
        ::packvm::compiler::ok_or_panic(::packvm::compiler::assembly::assemble($src_ns));
    };
}

#[derive(Clone)]
pub struct Executable {
    pub code: Vec<Instruction>,
    pub str_map: BiHashMap<U48, String>,
}

impl Debug for Executable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Executable:",)?;
        writeln!(f, "Code: [")?;
        for (idx, op) in self.code.iter().enumerate() {
            writeln!(f, "\t{idx:3}: {op:?}")?;
        }
        writeln!(f, "]")?;
        writeln!(f, "Strings: [")?;
        for i in 0..self.str_map.len() {
            let not_str = format!("unknown {i}");
            let str = self.str_map.get_by_left(&U48::from(i)).unwrap_or(&not_str);
            writeln!(f, "\t{i:4}: {str:?}")?;
        }
        writeln!(f, "]")
    }
}

impl Executable {
    fn simple_jmp_str(&self, ptr: U48) -> String {
        let op = &self.code[usize::from(ptr)];
        match op {
            Instruction::Section(ctype, id) => {
                let type_str = match ctype {
                    1 => "emum",
                    2 => "struct",
                    _ => unreachable!(),
                };
                let sec_str = get_str_or_unknown!(self.str_map, id);
                format!("{type_str} {sec_str}")
            }
            Instruction::JmpRet(ptr) => self.simple_jmp_str(*ptr),
            Instruction::JmpVariant(_, ptr) => self.simple_jmp_str(U48(*ptr as u64)),
            _ => format!("{op:?}"),
        }
    }
    pub fn pretty_op_string(&self, i: U48) -> String {
        let op = &self.code[usize::from(i)];
        match op {
            Instruction::Section(ctype, id) => {
                let type_str = match ctype {
                    1 => "emum(1)",
                    2 => "struct(2)",
                    _ => unreachable!(),
                };
                let sec_str = get_str_or_unknown!(self.str_map, id);
                format!("Section({type_str}, {sec_str})")
            }
            Instruction::Field(id) => format!("Field({})", get_str_or_unknown!(self.str_map, id)),
            Instruction::Jmp(ptr) => format!("{:?} -> {}", op, self.simple_jmp_str(*ptr)),
            Instruction::JmpRet(ptr) => {
                format!("{:?} -> {}", op, self.simple_jmp_str(*ptr))
            }
            Instruction::JmpVariant(_, ptr) => {
                format!(
                    "{:?} -> {}",
                    op,
                    self.simple_jmp_str(U48::from(*ptr as u64))
                )
            }
            _ => format!("{op:?}"),
        }
    }

    pub fn pretty_string(&self) -> String {
        let mut s = String::new();
        for i in 0..self.code.len() {
            let op_str = self.pretty_op_string(U48::from(i));
            s += format!("\n\t{i}: {op_str}").as_str();
        }

        s
    }
}

fn assemble_sections<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
>(
    src_ns: &ProgramNamespace<A, T, E, S, Source>,
    executable: &mut Vec<Instruction>,
    sections: &HashMap<U48, U48>,
) -> Result<(), TypeCompileError> {
    let mut sec_keys = sections.keys().collect::<Vec<&U48>>();
    sec_keys.sort();
    for sec_name in sec_keys {
        let start_ptr = *sections
            .get(sec_name)
            .ok_or(compiler_error!("Couldn't find section {}", sec_name))?;

        let sec_program = src_ns.get_program(sec_name).ok_or(compiler_error!(
            "Couldn't find section program {}",
            sec_name
        ))?;

        debug_log!("Assemble section {} ({})", sec_name, sec_program.name);

        let mut ptr = usize::from(start_ptr);
        let mut found_exit = false;
        while ptr < executable.len() {
            match executable[ptr].clone() {
                Instruction::Exit => {
                    found_exit = true;
                }
                Instruction::Jmp(jptr) => {
                    executable[ptr] = Instruction::Jmp(start_ptr + jptr);
                }
                Instruction::JmpArrayCND(_) => {
                    executable[ptr] = Instruction::JmpArrayCND(U48(ptr as u64 - 1));
                }
                Instruction::Field(rel_str_id) => {
                    let src_strings = &sec_program.strings;
                    let field_name = match sec_program.strings.get(usize::from(rel_str_id)) {
                        Some(name) => Ok(name),
                        None => Err(compiler_error!(
                            "Couldn't find str of rel id {} in strings: {:#?}\nProgram code: {:#?}\nAt location: {ptr}\n{}",
                            &rel_str_id,
                            src_strings,
                            sec_program.code,
                            Executable { code: executable.clone(), str_map: src_ns.strings.clone() }.pretty_string()
                        ))
                    }?;

                    let str_id = *src_ns.strings.get_by_right(field_name.as_str()).ok_or(
                        compiler_error!("Couldn't find absolute id of field str: {}", field_name),
                    )?;

                    executable[ptr] = Instruction::Field(str_id);
                }
                Instruction::JmpRet(id) => {
                    executable[ptr] = Instruction::JmpRet(
                        *sections
                            .get(&id)
                            .ok_or(compiler_error!("Couldn't find section {}", id))?,
                    );
                }
                _ => (),
            }
            if found_exit {
                break;
            } else {
                ptr += 1;
            }
        }
        if !found_exit {
            return Err(compiler_error!(
                "Ran out of code while looking for exit of section: {}",
                sec_name
            ));
        }
    }
    Ok(())
}

pub fn assemble<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Clone + Default + Debug,
>(
    src_ns: &ProgramNamespace<A, T, E, S, Source>,
) -> Result<Executable, TypeCompileError> {
    let mut code = Vec::default();

    // namespace .into_iter() is guaranteed to be in order of pid
    for program in src_ns.into_iter() {
        // insert jump table entry for program, for now ptr will just contain the pid
        // will be fixed during section assembly
        code.insert(program.index(), Instruction::Jmp(program.id));
    }

    let mut sections = HashMap::new();
    for program in src_ns.into_iter() {
        let section_ptr = U48::from(code.len());
        sections.insert(program.id, section_ptr);
        // fix jump table entry
        code[program.index()] = Instruction::Jmp(section_ptr);
        // append program code at the end of executable
        code.extend(program.code.clone());
    }

    assemble_sections(src_ns, &mut code, &sections)?;

    let exec = Executable {
        code,
        str_map: src_ns.strings.clone(),
    };

    #[cfg(feature = "debug")]
    {
        // validate
        for (jmp_i, op) in exec.code[..src_ns.len()].iter().cloned().enumerate() {
            match op {
                Instruction::Jmp(ptr) => {
                    let pid = U48::from(jmp_i + crate::compiler::RESERVED_IDS);

                    let src_program = src_ns
                        .get_program(&pid)
                        .ok_or(compiler_error!("Couldn't find source program: {}", pid))?;

                    let mut i = usize::from(ptr);
                    while !exec.code[i].cmp_type(&Instruction::Exit) {
                        let rel_i = i - usize::from(ptr);
                        let asm_op = &exec.code[i];
                        let src_op = &src_program.code[rel_i];
                        if !src_op.cmp_type(asm_op) {
                            debug_log!("{} different at {}: {:?} -> {:?}", pid, i, src_op, asm_op);
                            debug_log!("Source:\n{:#?}", src_program);
                            return Err(compiler_error!("Validation falied!"));
                        }
                        i += 1;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(exec)
}
