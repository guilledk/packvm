pub mod numbers;
pub mod varint;

#[inline(always)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[macro_export]
#[cfg(feature = "debug")]
macro_rules! debug_log {
    ($($args:tt)*) => {{
        println!("{}", format_args!($($args)*));
    }};
}

#[macro_export]
#[cfg(not(feature = "debug"))]
macro_rules! debug_log {
    ($($args:tt)*) => {{}};
}

#[macro_export]
macro_rules! define_error {
    ($name:ident) => {
        #[derive(Debug, ::thiserror::Error)]
        #[error("{reason}")]
        pub struct $name {
            pub reason: String,
        }

        impl $name {
            pub fn new(args: impl ::core::fmt::Display) -> Self {
                Self {
                    reason: args.to_string(),
                }
            }

            pub fn fmt(args: ::core::fmt::Arguments<'_>) -> Self {
                Self {
                    reason: args.to_string(),
                }
            }
        }
    };
}

define_error!(ResolveStrIDError);
define_error!(TypeCompileError);
#[macro_export]
macro_rules! compiler_error {
    ($($arg:tt)*) => {{
        let bt = std::backtrace::Backtrace::capture();
        let s = format!($($arg)*);
        $crate::utils::TypeCompileError::fmt(format_args!("{}\n{:#?}", s, bt))
    }};
}

define_error!(PackerError);
#[macro_export]
macro_rules! packer_error {
    ($($arg:tt)*) => {
        $crate::utils::PackerError::fmt(format_args!($($arg)*))
    };
}

/// Used by VMStruct & VMEnum macros to resolve enum variants vm name correctly
pub trait VmTypeName {
    const NAME: &'static str;
}