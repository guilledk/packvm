use core::fmt::{self, Debug, Display};

macro_rules! numeric_wrapper {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            enum $priv:ident {
                $pos_variant:ident($pos_ty:ty),
                $neg_variant:ident($neg_ty:ty)
            }
            unsigned: [$($u_ty:ty),* $(,)?],
            signed:   [$($s_ty:ty),* $(,)?]
        }
    ) => {
        #[derive(Copy, Clone, Debug, PartialEq)]
        enum $priv {
            $pos_variant($pos_ty),
            $neg_variant($neg_ty),
        }

        $(#[$meta])*
        #[derive(Copy, Clone, PartialEq)]
        $vis struct $name {
            n: $priv,
        }

        impl $name {
            pub const fn is_signed(&self) -> bool {
                matches!(self.n, $priv::$neg_variant(..))
            }
            pub const fn is_unsigned(&self) -> bool {
                matches!(self.n, $priv::$pos_variant(..))
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Debug::fmt(&self.n, f)
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.n {
                    $priv::$pos_variant(v) => Display::fmt(&v, f),
                    $priv::$neg_variant(v) => Display::fmt(&v, f),
                }
            }
        }

        $(
            impl From<$u_ty> for $name {
                #[inline]
                fn from(n: $u_ty) -> Self {
                    Self { n: $priv::$pos_variant(n as $pos_ty) }
                }
            }
        )*

        $(
            impl From<$s_ty> for $name {
                #[inline]
                fn from(n: $s_ty) -> Self {
                    if n < 0 {
                        Self { n: $priv::$neg_variant(n as $neg_ty) }
                    } else {
                        Self { n: $priv::$pos_variant(n as $pos_ty) }
                    }
                }
            }
        )*
    };
}

numeric_wrapper!(
    /// 64‑bit signed/unsigned wrapper
    pub struct Integer {
        enum IntPriv {
            PosInt(u64),
            NegInt(i64)
        }
        unsigned: [u8, u16, u32, u64, usize],
        signed:   [i8, i16, i32, i64, isize]
    }
);

impl Integer {
    #[inline]
    pub const fn is_i64(&self) -> bool {
        match self.n {
            IntPriv::PosInt(n) => n <= i64::MAX as u64,
            IntPriv::NegInt(_) => true,
        }
    }
    #[inline]
    pub const fn is_u64(&self) -> bool {
        matches!(self.n, IntPriv::PosInt(..))
    }
    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        match self.n {
            IntPriv::PosInt(n) => n.try_into().ok(),
            IntPriv::NegInt(n) => Some(n),
        }
    }
    #[inline]
    pub fn as_u64(&self) -> Option<u64> {
        match self.n {
            IntPriv::PosInt(n) => Some(n),
            IntPriv::NegInt(n) => n.try_into().ok(),
        }
    }
}

numeric_wrapper!(
    /// 128‑bit signed/unsigned wrapper
    pub struct Long {
        enum LongPriv {
            PosLong(u128),
            NegLong(i128)
        }
        unsigned: [u8, u16, u32, u64, u128, usize],
        signed:   [i8, i16, i32, i64, i128, isize]
    }
);

impl Long {
    #[inline]
    pub const fn is_i128(&self) -> bool {
        match self.n {
            LongPriv::PosLong(n) => n <= i128::MAX as u128,
            LongPriv::NegLong(_) => true,
        }
    }
    #[inline]
    pub const fn is_u128(&self) -> bool {
        matches!(self.n, LongPriv::PosLong(..))
    }
    #[inline]
    pub fn as_i128(&self) -> Option<i128> {
        match self.n {
            LongPriv::PosLong(n) => n.try_into().ok(),
            LongPriv::NegLong(n) => Some(n),
        }
    }
    #[inline]
    pub fn as_u128(&self) -> Option<u128> {
        match self.n {
            LongPriv::PosLong(n) => Some(n),
            LongPriv::NegLong(n) => n.try_into().ok(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum FloatPriv {
    F64(f64),
    F32(f32),
}

#[derive(Copy, Clone, PartialEq)]
pub struct Float {
    n: FloatPriv,
}

impl Float {
    pub const fn is_f32(&self) -> bool {
        matches!(self.n, FloatPriv::F32(_))
    }
    pub const fn is_f64(&self) -> bool {
        true
    }
    pub fn as_f64(&self) -> f64 {
        match self.n {
            FloatPriv::F64(v) => v,
            FloatPriv::F32(v) => v as f64,
        }
    }
    pub fn as_f32(&self) -> Option<f32> {
        match self.n {
            FloatPriv::F32(v) => Some(v),
            FloatPriv::F64(v) => {
                let v32 = v as f32;
                if (v32 as f64) == v { Some(v32) } else { None }
            }
        }
    }
}

impl Debug for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.n, f)
    }
}

impl Display for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.n {
            FloatPriv::F64(v) => Display::fmt(&v, f),
            FloatPriv::F32(v) => Display::fmt(&v, f),
        }
    }
}

impl From<f32> for Float {
    #[inline]
    fn from(n: f32) -> Self {
        Self { n: FloatPriv::F32(n) }
    }
}

impl From<f64> for Float {
    #[inline]
    fn from(n: f64) -> Self {
        Self { n: FloatPriv::F64(n) }
    }
}
