//! Software emulation support for CLMUL hardware intrinsics.
//!
//! WARNING: Not constant time! Should be made constant-time or disabled by default.

// TODO(tarcieri): performance-oriented constant-time implementation
// See: <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c>

use super::Backend;
use crate::field::Block;
use core::{convert::TryInto, ops::Add};

/// 2 x `u64` values emulating an XMM register
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U64x2(u64, u64);

impl From<Block> for U64x2 {
    fn from(bytes: Block) -> U64x2 {
        U64x2(
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        )
    }
}

impl From<U64x2> for Block {
    fn from(u64x2: U64x2) -> Block {
        let x: u128 = u64x2.into();
        x.to_le_bytes()
    }
}

impl From<u128> for U64x2 {
    fn from(x: u128) -> U64x2 {
        let lo = (x & 0xFFFF_FFFFF) as u64;
        let hi = (x >> 64) as u64;
        U64x2(lo, hi)
    }
}

impl From<U64x2> for u128 {
    fn from(u64x2: U64x2) -> u128 {
        u128::from(u64x2.0) | (u128::from(u64x2.1) << 64)
    }
}

impl Add for U64x2 {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    fn add(self, rhs: Self) -> Self {
        U64x2(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Backend for U64x2 {
    fn clmul(self, other: Self, imm: u8) -> Self {
        let (a, b) = match imm.into() {
            0x00 => (self.0, other.0),
            0x01 => (self.1, other.0),
            0x10 => (self.0, other.1),
            0x11 => (self.1, other.1),
            _ => unreachable!(),
        };

        let mut result = U64x2(0, 0);

        for i in 0..64 {
            if b & (1 << i) != 0 {
                result.1 ^= a;
            }

            result.0 >>= 1;

            if result.1 & 1 != 0 {
                result.0 ^= 1 << 63;
            }

            result.1 >>= 1;
        }

        result
    }

    fn shuffle(self) -> Self {
        U64x2(self.1, self.0)
    }

    fn shl64(self) -> Self {
        U64x2(0, self.0)
    }

    fn shr64(self) -> Self {
        U64x2(self.1, 0)
    }
}
