use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem::discriminant;
use bimap::BiHashMap;
use crate::compiler::{EnumDef, ProgramNamespace, SourceCode, StructDef, TypeAlias, TypeDef};
use crate::debug_log;
use crate::isa::Instruction;
use crate::compiler_error;
use crate::utils::TypeCompileError;

#[macro_export]
macro_rules! assemble {
    ($src_ns:expr) => {
        ::packvm::compiler::ok_or_panic(
            ::packvm::compiler::assembly::assemble($src_ns)
        );
    };
}

#[derive(Clone)]
pub struct Executable {
    pub code: Vec<Instruction>,
    pub str_map: BiHashMap<usize, String>,
}

impl Debug for Executable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Executable:",
        )?;
        writeln!(f, "Code: [")?;
        for (idx, op) in self.code.iter().enumerate() {
            writeln!(f, "\t{:3}: {:?}", idx, op)?;
        }
        writeln!(f, "]")?;
        writeln!(f, "Strings: [")?;
        for i in 0..self.str_map.len() {
            let not_str = format!("unknown {}", i);
            let str = self.str_map.get_by_left(&i)
                .unwrap_or(&not_str);
            writeln!(f, "\t{:4}: {:?}", i, str)?;
        }
        writeln!(f, "]")
    }
}

impl Executable {
    pub fn pretty_string(&self) -> String {
        fn get_str_or_unknown(ex: &Executable, id: usize) -> &str {
            match ex.str_map.get_by_left(&id) {
                Some(s) => s,
                None => "unknown target",
            }
        }

        let mut s = String::new();
        let mut jmp_table_ended = false;
        for i in 0..self.code.len() {
            let op = &self.code[i];
            jmp_table_ended |= discriminant(op) != discriminant(&Instruction::Jmp {ptr: 0});
            let msg = if !jmp_table_ended {
                get_str_or_unknown(self, i)
            } else {
                match op {
                    Instruction::Section(_, id) => {
                        get_str_or_unknown(self, *id)
                    }
                    Instruction::Field(id) => {
                        get_str_or_unknown(self, *id)
                    }
                    _ => ""
                }
            };
            s += format!("\n\t{i}: {op:?}").as_str();
            if !msg.is_empty() {
                s += format!("  # {msg}").as_str();
            }
        }

        s
    }
}

fn assemble_sections<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Debug
>(
    src_ns: &ProgramNamespace<A, T, E, S, Source>,
    executable: &mut Vec<Instruction>,
    sections: &HashMap<usize, usize>,
) -> Result<(), TypeCompileError> {
    let mut sec_keys = sections.keys().collect::<Vec<&usize>>();
    sec_keys.sort();
    for sec_name in sec_keys {
        let start_ptr = sections.get(sec_name)
            .ok_or(compiler_error!("Couldn't find section {}", sec_name))?
            .clone();

        let sec_program = src_ns.get_program(sec_name)
            .ok_or(compiler_error!("Couldn't find section program {}", sec_name))?;

        debug_log!("Assemble section {} ({})", sec_name, sec_program.name);

        let mut ptr = start_ptr;
        let mut found_exit = false;
        while ptr < executable.len() || found_exit {
            match executable[ptr].clone() {
                Instruction::Exit => {
                    found_exit = true;
                    break;
                },
                Instruction::Jmp { ptr: jptr } => {
                    executable[ptr] = Instruction::Jmp {
                        ptr: start_ptr + jptr
                    };
                },
                Instruction::JmpStructCND(cnd, jptr) => {
                    executable[ptr] = Instruction::JmpStructCND(cnd, ptr + jptr);
                }
                Instruction::JmpArrayCND(_) => {
                    executable[ptr] = Instruction::JmpArrayCND(ptr - 1);
                }
                Instruction::Field(rel_str_id) => {
                    let field_name = sec_program.strings.get(rel_str_id)
                        .ok_or(compiler_error!("Couldn't find str of field id: {}", &rel_str_id))?;

                    let str_id = src_ns.strings.get_by_right(field_name.as_str())
                        .ok_or(compiler_error!("Couldn't find absolute id of field str: {}", field_name))?
                        .clone();

                    executable[ptr] = Instruction::Field(str_id);
                }
                Instruction::JmpRet { ptr: id } => {
                    executable[ptr] = Instruction::JmpRet {
                        ptr: sections.get(&id)
                            .ok_or(compiler_error!("Couldn't find section {}", id))?
                            .clone(),
                    }
                }
                _ => ()
            }
            ptr += 1;
        }
        if !found_exit {
            return Err(compiler_error!("Ran out of code while looking for exit of section: {}", sec_name));
        }
    }
    Ok(())
}

pub fn assemble<
    A: TypeAlias,
    T: TypeDef,
    E: EnumDef,
    S: StructDef<T>,
    Source: SourceCode<A, T, E, S> + Debug
>(
    src_ns: &ProgramNamespace<A, T, E, S, Source>,
) -> Result<Executable, TypeCompileError> {
    let mut code = Vec::new();

    // namespace .into_iter() is guaranteed to be in order of pid
    for program in src_ns.into_iter() {
        // insert jump table entry for program, for now ptr will just contain the pid
        // will be fixed during section assembly
        code.insert(program.id, Instruction::Jmp {
            ptr: program.id
        });
    }

    let mut sections = HashMap::new();
    for program in src_ns.into_iter() {
        let section_ptr = code.len();
        sections.insert(program.id, section_ptr);
        // fix jump table entry
        code[program.id] = Instruction::Jmp {ptr: section_ptr};
        // append program code at the end of executable
        code.extend(program.code.clone());
    }

    assemble_sections(
        src_ns,
        &mut code,
        &sections,
    )?;

    let exec = Executable{
        code,
        str_map: src_ns.strings.clone(),
    };

    #[cfg(feature = "debug")]
    {
        // validate
        for (jmp_i, op) in exec.code[0..src_ns.len()].iter().cloned().enumerate() {
            match op {
                Instruction::Jmp { ptr } => {

                    let src_program = src_ns.get_program(&jmp_i)
                        .ok_or(compiler_error!("Couldn't find source program: {}", jmp_i))?;

                    let mut i = ptr;
                    while exec.code[i].clone() != Instruction::Exit {
                        let rel_i = i - ptr;
                        let asm_op = &exec.code[i];
                        let src_op = &src_program.code[rel_i];
                        if !Instruction::validate_asm(src_op, asm_op) {
                            debug_log!("{} different at {}: {:?} -> {:?}", jmp_i, i, src_op, asm_op);
                            debug_log!("Source:\n{:#?}", src_program);
                            return Err(compiler_error!("Validation falied!"));
                        }
                        i += 1;
                    }
                },
                _ => unreachable!()
            }
        }
    }

    Ok(exec)
}
