use crate::utils::PackerError;

pub(crate) type OpResult = Result<(), PackerError>;

#[macro_export]
macro_rules! popcnd {
    ($vm:ident) => {{
        if $vm.cndstack.len() > 1 {
            $vm.cndstack.pop();
        }
        $vm.ip += 1;
        $vm.ionsp.pop();
        $vm.ionsp.pop();
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
macro_rules! jmpcnd {
    ($vm:ident, $ptrdelta:expr, $value:expr, $delta:expr) => {{
        let csp = $vm.cndstack.len() - 1;
        $vm.cndstack[csp] += $delta;
        if $vm.cndstack[csp] == $value {
            if $ptrdelta.is_negative() {
                $vm.ip -= $ptrdelta.abs() as usize;
            } else {
                $vm.ip += $ptrdelta as usize;
            }
            vmlog!(
                $vm,
                "jmpcnd",
                "(t: {}, v: {}, d: {}) triggered", $ptrdelta, $value, $delta
            );
        } else {
            $vm.ip += 1;           // fall-through
            vmlog!(
                $vm,
                "jmpcnd",
                "(t: {}, v: {}, d: {})", $ptrdelta, $value, $delta
            );
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpnotcnd {
    ($vm:ident, $ptrdelta:expr, $value:expr, $delta:expr) => {{
        let csp = $vm.cndstack.len() - 1;
        $vm.cndstack[csp] += $delta;
        if $vm.cndstack[csp] != $value {
            if $ptrdelta.is_negative() {
                $vm.ip -= $ptrdelta.abs() as usize;
            } else {
                $vm.ip += $ptrdelta as usize;
            }
            vmlog!(
                $vm,
                "jmpnotcnd",
                "(t: {}, v: {}, d: {}) triggered", $ptrdelta, $value, $delta
            );
        } else {
            $vm.ip += 1;           // fall-through
            vmlog!(
                $vm,
                "jmpnotcnd",
                "(t: {}, v: {}, d: {})", $ptrdelta, $value, $delta
            );
        }
        Ok(())
    }};
}

#[macro_export]
macro_rules! jmpret {
    ($vm:ident, $name:expr, $ptr:expr) => {
        $vm.retstack.push($vm.ip);
        $vm.ip = $ptr;

        vmlog!(
            $vm,
            "jmpret",
            "({}, {})",
            $name, $ptr
        );
    };
}

#[macro_export]
macro_rules! raise {
    ($vm:ident, $e:ident) => {{
        vmlog!(
            $vm,
            "raise",
            "({:?})",
            $e
        );
        Err(crate::packer_error!("raise exception: {:?}", $e))
    }};
}

#[macro_export]
macro_rules! exit {
    ($vm:ident) => {{
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