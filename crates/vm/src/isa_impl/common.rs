use crate::utils::PackerError;

pub(crate) type OpResult = Result<(), PackerError>;

#[macro_export]
macro_rules! popcnd {
    ($vm:ident) => {{
        if $vm.cndstack.len() > 1 {
            $vm.cndstack.pop();
        }
        $vm.ip += 1;

        match $vm.nsp_last() {
            NamespacePart::ArrayNode => {
                $vm.ionsp.pop();
            }
            NamespacePart::ArrayIndex => {
                $vm.ionsp.pop();
                $vm.ionsp.pop();
            }
            _ => ()
        }
        vmlog!($vm, "popcnd", "()");
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmp {
    ($vm:ident, $ptr:expr) => {{
        $vm.ip = $ptr;
        vmlog!($vm, "jmp", "({})", $ptr);
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpscnd {
    ($vm:ident, $variant:expr, $ptr:expr) => {{
        if $vm.cnd() == $variant {
            $vm.ip = $ptr;
            vmlog!(
                $vm,
                "jmp struct cnd",
                "({}, {}) triggered", $variant, $ptr
            );
        } else {
            $vm.ip += 1;
            vmlog!(
                $vm,
                "jmp struct cnd",
                "({}, {}) pass", $variant, $ptr
            );
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpacnd {
    ($vm:ident, $ptr:expr) => {{
        let cnd = $vm.cnd_mut();
        *cnd -= 1;
        let cnd = *cnd;
        if cnd > 0 {
            $vm.ip = $ptr;
            vmlog!(
                $vm,
                "jmp array cnd",
                "({}) ptr: {} triggered", cnd, $ptr
            );
        } else {
            $vm.ip += 1;
            vmlog!(
                $vm,
                "jmp array cnd",
                "({}) ptr: {} pass", cnd, $ptr
            );
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpret {
    ($vm:ident, $ptr:expr) => {
        $vm.retstack.push($vm.ip);
        $vm.ip = $ptr;

        vmlog!(
            $vm,
            "jmpret",
            "({})",
            $ptr
        );
    };
}

#[macro_export]
macro_rules! section {
    ($vm:ident, $ctype:expr, $id:expr) => {{
        let fname = $vm.executable.str_map.get_by_left(&$id)
            .ok_or(crate::packer_error!("Failed to resolve struct name from section id: {}", $id))?;

        $vm.ionsp.push(NamespacePart::StructNode($ctype, fname.clone()));
        $vm.ip += 1;

        vmlog!(
            $vm,
            "section",
            "({}, {})",
            $ctype, fname
        );
    }};
}

#[macro_export]
macro_rules! field {
    ($vm:ident, $id:expr) => {{
        match $vm.nsp_last() {
            NamespacePart::StructNode(_, _) => (),
            NamespacePart::StructField(_) => { $vm.ionsp.pop(); },
            _ => return Err(crate::packer_error!("Expected Struct on nsp last, but got {:?}", $vm.nsp_last())),
        }
        let fname = $vm.executable.str_map.get_by_left(&$id)
            .ok_or(crate::packer_error!("Failed to resolve struct field name from id: {}", $id))?;

        $vm.ionsp.push(NamespacePart::StructField(fname.clone()));
        $vm.ip += 1;

        vmlog!(
            $vm,
            "field",
            "({})",
            fname
        );
    }};
}

#[macro_export]
macro_rules! exit {
    ($vm:ident) => {{
        match $vm.nsp_last() {
            NamespacePart::StructNode(_, _) => { $vm.ionsp.pop(); }
            NamespacePart::StructField(_) => {
                $vm.ionsp.pop();
                $vm.ionsp.pop();
            }
            _ => ()
        }

        let exit = $vm.retstack.len() == 1;
        if !exit {
            $vm.ip = $vm.retstack.pop().unwrap() + 1;
        }
        vmlog!(
            $vm,
            "exit",
            "(): {}", exit
        );
        Ok(exit)
    }};
}