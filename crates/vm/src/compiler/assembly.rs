use std::collections::HashMap;
use crate::compiler::ProgramNamespace;
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

fn assemble_section(
    executable: &mut Vec<Instruction>,
    sections: &HashMap<String, usize>,
    sec_name: &str,
) -> Result<(), TypeCompileError> {
    let start_ptr = sections.get(sec_name)
        .ok_or(compiler_error!("Couldn't find section {}", sec_name))?
        .clone();

    debug_log!("Assemble section {}", sec_name);

    let mut ptr = start_ptr;
    let mut found_exit = false;
    while ptr < executable.len() || found_exit {

        match executable[ptr].clone() {
            Instruction::Exit => {
                found_exit = true;
                break;
            },
            Instruction::Jmp {info, ptr: jptr} => {
                executable[ptr] = Instruction::Jmp {
                    info,
                    ptr: start_ptr + jptr
                };
            },
            Instruction::ProgramJmp {name, ptr: _, ret: _} => {
                executable[ptr] = Instruction::JmpRet {
                    info: name.clone(),
                    ptr: sections.get(&name)
                        .ok_or(compiler_error!("Couldn't find section {}", name))?
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
    Ok(())
}

pub fn assemble(
    src_ns: &ProgramNamespace
) -> Result<Vec<Instruction>, TypeCompileError> {
    let program_count = src_ns.len();

    let mut executable = Vec::new();

    for program in src_ns.into_iter() {
        executable.insert(program.id as usize, Instruction::Jmp {
            info: program.name.clone(),
            ptr: 0
        });
        executable.push(Instruction::Section(program.name.clone()));
        executable.extend(program.code.clone());
    }

    let mut sections = HashMap::new();
    for i in 0..program_count {
        match executable[i].clone() {
            Instruction::Jmp {info, ptr: _} => {
                let mut section_ptr = program_count;
                while section_ptr < executable.len() {
                    if let Instruction::Section(section_name) = &executable[section_ptr] {
                        if section_name == &info {
                            break;
                        }
                    }
                    section_ptr += 1;
                }
                sections.insert(info.clone(), section_ptr + 1);
                executable[i] = Instruction::Jmp {info: info.clone(), ptr: section_ptr + 1}
            }
            _ => ()
        }
    }

    for section in sections.keys().cloned() {
        assemble_section(
            &mut executable,
            &sections,
            &section,
        )?
    }

    #[cfg(feature = "debug")]
    {
        for op in executable.iter().enumerate() {
            debug_log!("{:?}", op)
        }
        // validate
        for op in executable[0..src_ns.len()].iter().cloned() {
            match op {
                Instruction::Jmp { info, ptr } => {
                    if info.contains("end of") { continue; }

                    let src_program = src_ns.get_program(&info)
                        .ok_or(compiler_error!("Couldn't find source program: {}", info))?;

                    let mut i = ptr;
                    while executable[i].clone() != Instruction::Exit {
                        let rel_i = i - ptr;
                        let asm_op = &executable[i];
                        let src_op = &src_program.code[rel_i];
                        if !Instruction::validate_asm(src_op, asm_op) {
                            debug_log!("{} different at {}: {:?} -> {:?}", &info, i, src_op, asm_op);
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

    Ok(executable)
}
