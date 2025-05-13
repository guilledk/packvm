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
macro_rules! jmptrap {
    ($vm:ident) => {{
        $vm.push_ret();
        $vm.ip = $vm.pid();
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
    ($vm:ident, $ptr:expr) => {{
        $vm.push_ret();
        $vm.ip = $ptr;
    }};
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
        let exit = $vm.retp == 1;
        if !exit {
            $vm.ip = $vm.retstack[$vm.retp] + 1;
            $vm.retp -= 1;
        }
        Ok(exit)
    }};
}
