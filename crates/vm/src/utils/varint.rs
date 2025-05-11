//! varint.rs  –  no allocation, no std needed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarUInt32(pub u32);

impl VarUInt32 {
    /// Encoded length in bytes (same logic as before, but const-fn safe).
    #[inline(always)]
    pub const fn encoded_len(self) -> usize {
        match self.0 {
            0..=0x7F => 1,
            0x80..=0x3FFF => 2,
            0x4000..=0x1F_FFFF => 3,
            0x20_0000..=0xFFF_FFFF => 4,
            _ => 5,
        }
    }

    /// Encode into a 5-byte buffer; returns (buffer, length_used).
    #[inline]
    pub fn encode(self) -> ([u8; 5], usize) {
        let mut buf = [0u8; 5];
        let mut v = self.0;
        let mut i = 0;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            buf[i] = if v == 0 { byte } else { byte | 0x80 };
            i += 1;
            if v == 0 {
                break;
            }
        }
        (buf, i)
    }

    /// Decode ULEB128 from `bytes`, returning the value and bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        let mut result = 0u32;
        let mut shift = 0;
        for (i, &b) in bytes.iter().enumerate() {
            result |= ((b & 0x7F) as u32) << shift;
            if (b & 0x80) == 0 {
                return Ok((VarUInt32(result), i + 1));
            }
            shift += 7;
            if shift >= 32 {
                return Err("ULEB128 overflow");
            }
        }
        Err("buffer too short")
    }
}

impl From<u32> for VarUInt32 {
    fn from(v: u32) -> Self {
        Self(v)
    }
}
impl From<VarUInt32> for u32 {
    fn from(v: VarUInt32) -> Self {
        v.0
    }
}

/// Signed two-complement LEB128 (not zig-zag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt32(pub i32);

impl VarInt32 {
    /// Encoded length in bytes.
    #[inline(always)]
    pub const fn encoded_len(self) -> usize {
        let mut value = self.0;
        let mut len = 0;
        loop {
            let byte = value & 0x7F;
            value >>= 7;
            len += 1;
            let done = (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0);
            if done {
                return len;
            }
        }
    }

    /// Encode into a 5-byte buffer.
    #[inline]
    pub fn encode(self) -> ([u8; 5], usize) {
        let mut buf = [0u8; 5];
        let mut v = self.0 as i64;
        let mut i = 0;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            let more = !((v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0));
            buf[i] = if more { byte | 0x80 } else { byte };
            i += 1;
            if !more {
                break;
            }
        }
        (buf, i)
    }

    /// Decode SLEB128.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        let mut result = 0i32;
        let mut shift = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let byte_read = b;
            result |= ((b & 0x7F) as i32) << shift;
            shift += 7;
            if (b & 0x80) == 0 {
                if shift < 32 && (byte_read & 0x40) != 0 {
                    result |= (!0) << shift; // sign-extend
                }
                return Ok((VarInt32(result), i + 1));
            }
            if shift >= 32 {
                return Err("SLEB128 overflow");
            }
        }
        Err("buffer too short")
    }
}

impl From<i32> for VarInt32 {
    fn from(v: i32) -> Self {
        Self(v)
    }
}
impl From<VarInt32> for i32 {
    fn from(v: VarInt32) -> Self {
        v.0
    }
}

#[cfg(test)]
mod tests {
    use super::{VarInt32, VarUInt32};

    // ---------- helpers ----------

    fn roundtrip_u(v: u32) {
        let var = VarUInt32(v);

        // encode
        let (buf, len) = var.encode();
        assert_eq!(len, var.encoded_len(), "encoded_len mismatch for {v}");

        // decode the exact slice
        let (decoded, used) = VarUInt32::decode(&buf[..len]).expect("decode failed");
        assert_eq!(used, len, "decode consumed unexpected length for {v}");
        assert_eq!(u32::from(decoded), v, "round-trip value mismatch");

        // decode from a longer buffer (should ignore the tail)
        let mut long = [0u8; 16];
        long[..len].copy_from_slice(&buf[..len]);
        long[len..].fill(0xAA);
        let (decoded2, used2) = VarUInt32::decode(&long).expect("decode (long) failed");
        assert_eq!(u32::from(decoded2), v);
        assert_eq!(used2, len);
    }

    fn roundtrip_i(v: i32) {
        let var = VarInt32(v);

        let (buf, len) = var.encode();
        assert_eq!(len, var.encoded_len(), "encoded_len mismatch for {v}");

        let (decoded, used) = VarInt32::decode(&buf[..len]).expect("decode failed");
        assert_eq!(used, len, "decode consumed unexpected length for {v}");
        assert_eq!(i32::from(decoded), v, "round-trip value mismatch");

        let mut long = [0u8; 16];
        long[..len].copy_from_slice(&buf[..len]);
        long[len..].fill(0x55);
        let (decoded2, used2) = VarInt32::decode(&long).expect("decode (long) failed");
        assert_eq!(i32::from(decoded2), v);
        assert_eq!(used2, len);
    }

    // ---------- ULEB128 ----------

    #[test]
    fn varuint32_roundtrip_edge_cases() {
        const CASES: &[u32] = &[
            0,
            1,
            127, // 1-byte upper bound
            128,
            16_383, // 2-byte upper bound
            16_384,
            0x1F_FFFF, // 3-byte upper bound
            0x20_0000,
            0x0FFF_FFFF, // 4-byte upper bound
            u32::MAX,    // 0xFFFF_FFFF -> 5 bytes
        ];
        for &v in CASES {
            roundtrip_u(v);
        }
    }

    // ---------- SLEB128 ----------

    #[test]
    fn varint32_roundtrip_edge_cases() {
        const CASES: &[i32] = &[
            0,
            1,
            -1,
            63,
            64, // sign-bit boundary
            -64,
            -65,
            i32::MAX,
            i32::MIN,
        ];
        for &v in CASES {
            roundtrip_i(v);
        }
    }

    // ---------- malformed / overflow ----------

    #[test]
    fn varuint32_overflow() {
        // 6 continuation bytes with payload-bits set -> shift >= 32
        let bad = [0xFFu8; 6];
        assert!(VarUInt32::decode(&bad).is_err());
    }

    #[test]
    fn varint32_overflow() {
        let bad = [0xFFu8; 6];
        assert!(VarInt32::decode(&bad).is_err());
    }
}
