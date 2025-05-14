use crate::compiler::{compile_array, compile_extension, compile_optional, insert_reserved_strings, EnumDef, ProgramNamespace, SourceCode, StructDef, TypeAlias, TypeDef, RESERVED_IDS, TRAP_COUNT};
use crate::compiler_error;
use crate::isa::{DataInstruction, Instruction};
use crate::utils::numbers::U48;
use crate::utils::{bytes_to_hex, TypeCompileError};
use crate::{debug_log, get_str_or_unknown};
use bimap::BiHashMap;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use crate::utils::varint::VarUInt32;

#[macro_export]
macro_rules! assemble {
    ($src_ns:expr) => {
        ::packvm::compiler::ok_or_panic(::packvm::compiler::assembly::assemble($src_ns));
    };
}

#[derive(Clone, PartialEq)]
pub struct Executable {
    pub ns_checksum: [u8; 32],
    pub code: Vec<Instruction>,
    pub str_map: BiHashMap<U48, String>,
    pub var_map: HashMap<U48, Vec<String>>,
}

impl Debug for Executable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pretty_string())
    }
}

impl Executable {
    pub fn get_string(&self, id: &U48) -> &String {
        self.str_map.get_by_left(id)
            .expect(&format!("Could not find string for id: {id}"))
    }

    fn simple_jmp_str(&self, ptr: U48) -> String {
        let op = &self.code[usize::from(ptr)];
        match op {
            Instruction::Section(ctype, id) => {
                let type_str = match ctype {
                    0 => "trap",
                    1 => "enum",
                    2 => "struct",
                    _ => unreachable!(),
                };
                let sec_str = get_str_or_unknown!(self.str_map, id);
                format!("{type_str} {sec_str}")
            }
            Instruction::JmpRet(ptr) => self.simple_jmp_str(*ptr),
            _ => format!("{op:?}"),
        }
    }
    pub fn pretty_op_string(&self, i: U48) -> String {
        let op = &self.code[usize::from(i)];
        match op {
            Instruction::Section(ctype, id) => {
                let type_str = match ctype {
                    0 => "trap",
                    1 => "enum(1)",
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
            _ => format!("{op:?}"),
        }
    }

    pub fn pretty_string(&self) -> String {
        let mut s = format!("Executable({}):\n", bytes_to_hex(&self.ns_checksum));
        s += "Code: [\n";
        for i in 0..self.code.len() {
            let op_str = self.pretty_op_string(U48::from(i));
            s += format!("\n\t{i}: {op_str}").as_str();
        }
        s += "]\n";

        s += "Strings [\n";
        for i in 0..self.str_map.len() {
            let not_str = format!("unknown {i}");
            let str = self.str_map.get_by_left(&U48::from(i)).unwrap_or(&not_str);
            s += &format!("\t{i:4}: {str:?}\n");
        }
        s += "]";

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
    executable: &mut Executable,
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

        if src_ns.src.is_variant(&sec_program.name) {
            let var_meta = src_ns.src.enums()
                .iter()
                .find(|v| v.name() == sec_program.name)
                .ok_or(compiler_error!("Could not find enum src for program {}", sec_program.name))?;

            let mut vars = Vec::new();

            for variant in var_meta.variants() {
                vars.push(variant.clone());
            }

            executable.var_map.insert(sec_program.id, vars);
        }

        debug_log!("Assemble section {} ({})", sec_name, sec_program.name);

        let mut ptr = usize::from(start_ptr);
        let mut found_exit = false;
        while ptr < executable.code.len() {
            match executable.code[ptr].clone() {
                Instruction::Exit => {
                    found_exit = true;
                }
                Instruction::Jmp(jptr) => {
                    executable.code[ptr] = Instruction::Jmp(start_ptr + jptr);
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
                            executable.pretty_string()
                        ))
                    }?;

                    let str_id = *src_ns.strings.get_by_right(field_name.as_str()).ok_or(
                        compiler_error!("Couldn't find absolute id of field str: {}", field_name),
                    )?;

                    executable.code[ptr] = Instruction::Field(str_id);
                }
                Instruction::JmpRet(id) => {
                    executable.code[ptr] = Instruction::JmpRet(
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
    for i in 0..TRAP_COUNT {
        code.push(Instruction::Jmp(U48::from(i as u64)));
    }

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

    let mut exec = Executable {
        ns_checksum: src_ns.checksum(),
        code,
        str_map: src_ns.strings.clone(),
        var_map: HashMap::new(),
    };

    assemble_sections(src_ns, &mut exec, &sections)?;

    // traps
    let mut arr_code = compile_array(&src_ns.src, "u8", 1)?;
    arr_code.iter_mut()
        .for_each(|i| {
            if *i == Instruction::IO(DataInstruction::UInt(1)) {
                *i = Instruction::JmpTrap;
            }
        });
    arr_code.insert(0, Instruction::Section(0, U48(0)));
    arr_code.push(Instruction::Exit);

    exec.code[0] = Instruction::Jmp(U48::from(exec.code.len()));
    exec.code.extend(arr_code);

    let mut opt_code = compile_optional(&src_ns.src, "u8", 1)?;
    opt_code.iter_mut()
        .for_each(|i| if *i == Instruction::IO(DataInstruction::UInt(1)) {
            *i = Instruction::JmpTrap;
        });
    opt_code.insert(0, Instruction::Section(0, U48(0)));
    opt_code.push(Instruction::Exit);

    exec.code[1] = Instruction::Jmp(U48::from(exec.code.len()));
    exec.code.extend(opt_code);

    let mut ext_code = compile_extension(&src_ns.src, "u8", 1)?;
    ext_code.iter_mut()
        .for_each(|i| if *i == Instruction::IO(DataInstruction::UInt(1)) {
            *i = Instruction::JmpTrap;
        });
    ext_code.insert(0, Instruction::Section(0, U48(0)));
    ext_code.push(Instruction::Exit);

    exec.code[2] = Instruction::Jmp(U48::from(exec.code.len()));
    exec.code.extend(ext_code);

    #[cfg(feature = "debug")]
    for (jmp_i, op) in exec.code[TRAP_COUNT..src_ns.len()+TRAP_COUNT].iter().cloned().enumerate() {
        match op {
            Instruction::Jmp(ptr) => {
                let pid = U48::from(jmp_i + RESERVED_IDS );
                // validate section looks similar to source program code
                let src_program = src_ns
                    .get_program(&pid)
                    .ok_or(compiler_error!("Couldn't find source program: {}", pid))?;

                let mut i = usize::from(ptr);
                while exec.code[i] != Instruction::Exit {
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
            _ => return Err(compiler_error!("Reached non Jmp instruction while evaluating jmp table")),
        }
    }

    Ok(exec)
}

impl From<&Executable> for Vec<u8> {
    fn from(exec: &Executable) -> Self {
        let mut artifact: Vec<u8> = Vec::with_capacity(exec.code.len() * 8);
        for op in exec.code.iter() {
            let rawop: [u8; 8] = op.into();
            artifact.extend_from_slice(&rawop);
        }

        // encode string map
        // first u32 with total map len
        let str_map_len_raw = ((exec.str_map.len() - RESERVED_IDS) as u32).to_le_bytes();
        artifact.extend_from_slice(&str_map_len_raw);

        // for each string, leb128 encoded len, then utf8 bytes
        for i in RESERVED_IDS..exec.str_map.len() {
            let s = exec.str_map.get_by_left(&U48::from(i))
                .expect(&format!("Failed to get str({i}) for map"));

            let s_leb = VarUInt32::from(s.len() as u32);
            let (raw, rlen) = s_leb.encode();
            artifact.extend_from_slice(&raw[..rlen]);
            artifact.extend_from_slice(&s.as_bytes());
        }

        // encode var map
        // first u32 with total map len
        let var_map_len_raw = (exec.var_map.len() as u32).to_le_bytes();
        artifact.extend_from_slice(&var_map_len_raw);

        // for each string array, leb128 encoded total len, then for each str
        // leb128 str len + str bytes
        for (pid, variants) in &exec.var_map {
            // pid as u48 bytes
            let pid_raw: [u8; 6] = (*pid).into();
            artifact.extend_from_slice(&pid_raw);

            // total len
            let s_leb = VarUInt32::from(variants.len() as u32);
            let (raw, rlen) = s_leb.encode();
            artifact.extend_from_slice(&raw[..rlen]);

            for s in variants {
                let s_leb = VarUInt32::from(s.len() as u32);
                let (raw, rlen) = s_leb.encode();
                artifact.extend_from_slice(&raw[..rlen]);

                artifact.extend_from_slice(&s.as_bytes());
            }
        }

        // add namespace checksum
        artifact.extend_from_slice(&exec.ns_checksum);

        // encode amount of operations as u64 at the end
        let op_len_raw = (exec.code.len() as u64).to_le_bytes();
        artifact.extend_from_slice(&op_len_raw);

        artifact
    }
}

impl TryFrom<&[u8]> for Executable {
    type Error = String;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let op_len = u64::from_le_bytes(raw[raw.len() - 8..].try_into().unwrap()) as usize;

        let mut code = Vec::with_capacity(op_len);
        let mut ptr = 0;
        while code.len() < op_len {
            code.push(Instruction::from(&raw[ptr..ptr + 8].try_into().unwrap()));
            ptr += 8;
        }

        // decode string map
        let mut str_map: BiHashMap<U48, String> = BiHashMap::new();

        // read map len as u32
        let str_map_len = u32::from_le_bytes(raw[ptr..ptr + 4].try_into().unwrap()) as usize;
        ptr += 4;

        while str_map.len() < str_map_len {
            // read leb128 encoded str len
            let (s_leb, size) = VarUInt32::decode(&raw[ptr..])
                .map_err(|e| e.to_string())?;
            let s_len = s_leb.0 as usize;
            ptr += size;

            // read utf8 string
            let str = String::from_utf8(raw[ptr..ptr + s_len].to_vec())
                .map_err(|e| e.to_string())?;
            ptr += s_len;

            // insert into map
            str_map.insert(U48::from(str_map.len() + RESERVED_IDS), str);
        }

        insert_reserved_strings(&mut str_map);

        // decode var map
        let mut var_map: HashMap<U48, Vec<String>> = HashMap::new();

        // read map len as u32
        let var_map_len = u32::from_le_bytes(raw[ptr..ptr + 4].try_into().unwrap()) as usize;
        ptr += 4;

        while var_map.len() < var_map_len {
            let pid = U48::from(&raw[ptr..ptr + 6].try_into().unwrap());
            ptr += 6;

            // read leb128 encoded str array len
            let (ss_leb, size) = VarUInt32::decode(&raw[ptr..])
                .map_err(|e| e.to_string())?;
            let ss_len = ss_leb.0 as usize;
            ptr += size;

            let mut strings = Vec::with_capacity(ss_len);
            while strings.len() < ss_len {
                // read leb128 encoded str len
                let (s_leb, size) = VarUInt32::decode(&raw[ptr..])
                    .map_err(|e| e.to_string())?;
                let s_len = s_leb.0 as usize;
                ptr += size;

                // read utf8 string
                let str = String::from_utf8(raw[ptr..ptr + s_len].to_vec())
                    .map_err(|e| e.to_string())?;
                ptr += s_len;

                strings.push(str);
            }

            var_map.insert(pid, strings);
        }

        // read namespace checksum
        let ns_checksum: [u8; 32] = raw[ptr..ptr+32].try_into().unwrap();
        ptr += 32;

        // skip over already read op count u64
        ptr += 8;

        if ptr != raw.len() {
            return Err(format!("Final pointer location not equal to end: {} != {}", ptr, raw.len()));
        }

        Ok(Executable{
            ns_checksum,
            code,
            str_map,
            var_map,
        })
    }
}