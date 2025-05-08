use std::fmt;
use std::ops::{Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign};

/// Unsigned 48-bit integer kept in the low 48 bits of a `u64`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct U48(pub u64);

const MASK: u64 = 0xFFFF_FFFF_FFFF;


impl From<u64> for U48 {
    #[inline(always)]
    fn from(value: u64) -> Self {
        U48(value & MASK)  // truncates the upper 16 bits
    }
}

impl From<usize> for U48 {
    #[inline(always)]
    fn from(value: usize) -> Self {
        U48(value as u64 & MASK)
    }
}

impl From<&[u8; 6]> for U48 {
    #[inline(always)]
    fn from(b: &[u8; 6]) -> Self {
        U48(
            (b[0] as u64)
                | (b[1] as u64) <<  8
                | (b[2] as u64) << 16
                | (b[3] as u64) << 24
                | (b[4] as u64) << 32
                | (b[5] as u64) << 40,
        )
    }
}

impl From<U48> for [u8; 6] {
    #[inline(always)]
    fn from(v: U48) -> Self {
        let n = v.0 & MASK;
        [
            n as u8,
            (n >>  8) as u8,
            (n >> 16) as u8,
            (n >> 24) as u8,
            (n >> 32) as u8,
            (n >> 40) as u8,
        ]
    }
}

impl From<U48> for u64 {
    #[inline(always)]
    fn from(v: U48) -> Self {
        v.0
    }
}

impl From<U48> for usize {
    #[inline(always)]
    fn from(v: U48) -> Self {
        v.0 as usize
    }
}

impl fmt::Display for U48 {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for U48 {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

macro_rules! impl_bin_op {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for U48 {
            type Output = Self;
            #[inline(always)]
            fn $method(self, rhs: Self) -> Self::Output {
                U48((self.0 $op rhs.0) & MASK)
            }
        }
        impl $trait<u64> for U48 {
            type Output = Self;
            #[inline(always)]
            fn $method(self, rhs: u64) -> Self::Output {
                U48((self.0 $op (rhs & MASK)) & MASK)
            }
        }
        impl $trait<U48> for u64 {
            type Output = U48;
            #[inline(always)]
            fn $method(self, rhs: U48) -> Self::Output {
                U48(((self & MASK) $op rhs.0) & MASK)
            }
        }
    };
}

macro_rules! impl_assign_op {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for U48 {
            #[inline(always)]
            fn $method(&mut self, rhs: Self) {
                self.0 = (self.0 $op rhs.0) & MASK;
            }
        }
        impl $trait<u64> for U48 {
            #[inline(always)]
            fn $method(&mut self, rhs: u64) {
                self.0 = (self.0 $op (rhs & MASK)) & MASK;
            }
        }
    };
}

impl_bin_op!(Add, add, +);
impl_bin_op!(Sub, sub, -);
impl_bin_op!(Mul, mul, *);
impl_bin_op!(Div, div, /);
impl_bin_op!(Rem, rem, %);

impl_assign_op!(AddAssign, add_assign, +);
impl_assign_op!(SubAssign, sub_assign, -);
impl_assign_op!(MulAssign, mul_assign, *);
impl_assign_op!(DivAssign, div_assign, /);
impl_assign_op!(RemAssign, rem_assign, %);

impl_bin_op!(BitAnd, bitand, &);
impl_bin_op!(BitOr,  bitor,  |);
impl_bin_op!(BitXor, bitxor, ^);
impl_bin_op!(Shl,    shl,   <<);
impl_bin_op!(Shr,    shr,   >>);

impl_assign_op!(BitAndAssign, bitand_assign, &);
impl_assign_op!(BitOrAssign,  bitor_assign,  |);
impl_assign_op!(BitXorAssign, bitxor_assign, ^);
impl_assign_op!(ShlAssign,    shl_assign,   <<);
impl_assign_op!(ShrAssign,    shr_assign,   >>);

impl Not for U48 {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self::Output {
        U48((!self.0) & MASK)
    }
}

// Variable length representations

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

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.n, f)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.n {
                    $priv::$pos_variant(v) => fmt::Display::fmt(&v, f),
                    $priv::$neg_variant(v) => fmt::Display::fmt(&v, f),
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

impl fmt::Debug for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.n, f)
    }
}

impl fmt::Display for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.n {
            FloatPriv::F64(v) => fmt::Display::fmt(&v, f),
            FloatPriv::F32(v) => fmt::Display::fmt(&v, f),
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
