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
macro_rules! jmpacnd {
    ($vm:ident, $ptr:expr) => {{
        let cnd = $vm.cnd_mut();
        *cnd -= 1;
        let cnd = *cnd;
        if cnd > 0 {
            $vm.ip = $ptr;
        } else {
            $vm.cndstack.pop();
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