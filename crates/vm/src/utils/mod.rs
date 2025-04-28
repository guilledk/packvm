pub mod varint;

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

define_error!(TypeCompileError);
#[macro_export]
macro_rules! compiler_error {
    ($($arg:tt)*) => {
        $crate::utils::TypeCompileError::fmt(format_args!($($arg)*))
    };
}

define_error!(PackerError);
#[macro_export]
macro_rules! packer_error {
    ($($arg:tt)*) => {
        $crate::utils::PackerError::fmt(format_args!($($arg)*))
    };
}