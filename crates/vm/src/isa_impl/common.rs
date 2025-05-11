use crate::utils::PackerError;

pub(crate) type OpResult = Result<(), PackerError>;

#[macro_export]
macro_rules! popcursor {
    ($vm:ident) => {{
        $vm.cursor.pop();
        $vm.ip += 1;
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmp {
    ($vm:ident, $ptr:expr) => {{
        $vm.ip = $ptr;
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpvariant {
    ($vm:ident, $variant:expr, $ptr:expr) => {{
        if $vm.et == $variant {
            $vm.ip += $ptr;
        } else {
            $vm.ip += 1;
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmptrap {
    ($vm:ident) => {{
        $vm.retstack.push($vm.ip);
        let pid = u64::from_le_bytes($vm.ram[..8].try_into().unwrap());
        $vm.ip = U48(pid);
    }};
}

#[macro_export]
macro_rules! jmpacnd {
    ($vm:ident) => {{
        let cnd = $vm.sub_cnd(1);
        if cnd > 0 {
            $vm.ip -= 1;
        } else {
            $vm.pop_cnd();
            $vm.ip += 1;
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpret {
    ($vm:ident, $ptr:expr) => {
        $vm.retstack.push($vm.ip);
        $vm.ip = $ptr;
    };
}

#[macro_export]
macro_rules! field {
    ($vm:ident, $id:expr) => {{
        $vm.fp = $id;
        $vm.ip += 1;
    }};
}

#[macro_export]
macro_rules! exit {
    ($vm:ident) => {{
        let exit = $vm.retstack.len() == 1;
        if !exit {
            $vm.ip = $vm.retstack.pop().unwrap() + 1;
        }
        Ok(exit)
    }};
}
