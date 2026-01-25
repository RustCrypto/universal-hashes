//! Portable software implementation. Provides implementations for low power 32-bit devices as well
//! as a 64-bit implementation.

cpubits::cpubits! {
    16 | 32 => {
        #[path = "soft/soft32.rs"]
        mod soft_impl;
    }
    64 => {
        #[path = "soft/soft64.rs"]
        mod soft_impl;
    }
}

use crate::{Block, Key, Tag};
use core::{
    num::Wrapping,
    ops::{BitAnd, BitOr, BitXor, Mul},
};
use soft_impl::*;
use universal_hash::{
    KeyInit, Reset, UhfBackend, UhfClosure, UniversalHash,
    common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
    consts::{U1, U16},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
///
/// Parameterized on a constant that determines how many
/// blocks to process at once: higher numbers use more memory,
/// and require more time to re-key, but process data significantly
/// faster.
///
/// (This constant is not used when acceleration is not enabled.)
#[derive(Clone)]
pub struct Polyval<const N: usize = 1> {
    /// GF(2^128) field element input blocks are multiplied by
    h: FieldElement,

    /// Field element representing the computed universal hash
    s: FieldElement,
}

impl<const N: usize> Polyval<N> {
    /// Initialize POLYVAL with the given `H` field element and initial block
    pub fn new_with_init_block(h: &Key, init_block: u128) -> Self {
        Self {
            h: FieldElement::from_le_bytes(h),
            s: init_block.into(),
        }
    }
}

impl<const N: usize> KeySizeUser for Polyval<N> {
    type KeySize = U16;
}

impl<const N: usize> KeyInit for Polyval<N> {
    /// Initialize POLYVAL with the given `H` field element
    fn new(h: &Key) -> Self {
        Self::new_with_init_block(h, 0)
    }
}

impl<const N: usize> BlockSizeUser for Polyval<N> {
    type BlockSize = U16;
}

impl<const N: usize> ParBlocksSizeUser for Polyval<N> {
    type ParBlocksSize = U1;
}

impl<const N: usize> UhfBackend for Polyval<N> {
    fn proc_block(&mut self, x: &Block) {
        let x = FieldElement::from_le_bytes(x);
        self.s = (self.s + x) * self.h;
    }
}

impl<const N: usize> UniversalHash for Polyval<N> {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    fn finalize(self) -> Tag {
        self.s.to_le_bytes()
    }
}

impl<const N: usize> Reset for Polyval<N> {
    fn reset(&mut self) {
        self.s = FieldElement::default();
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> Drop for Polyval<N> {
    fn drop(&mut self) {
        self.h.zeroize();
        self.s.zeroize();
    }
}

/// Multiplication in GF(2)[X], truncated to the low 64-bits, with "holes" (sequences of zeroes) to
/// avoid carry spilling, as specified in the four masking operands (`m0`-`m4`).
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked out of the result.
#[inline]
fn bmul<T>(x: T, y: T, m0: T, m1: T, m2: T, m3: T) -> T
where
    T: BitAnd<Output = T> + BitOr<Output = T> + Copy,
    Wrapping<T>: BitXor<Output = Wrapping<T>> + Mul<Output = Wrapping<T>>,
{
    let x0 = Wrapping(x & m0);
    let x1 = Wrapping(x & m1);
    let x2 = Wrapping(x & m2);
    let x3 = Wrapping(x & m3);

    let y0 = Wrapping(y & m0);
    let y1 = Wrapping(y & m1);
    let y2 = Wrapping(y & m2);
    let y3 = Wrapping(y & m3);

    let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

    (z0.0 & m0) | (z1.0 & m1) | (z2.0 & m2) | (z3.0 & m3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const A: [u8; 16] = hex!("66e94bd4ef8a2c3b884cfa59ca342b2e");
    const B: [u8; 16] = hex!("ff000000000000000000000000000000");

    #[test]
    fn fe_add() {
        let a = FieldElement::from_le_bytes(&A.into());
        let b = FieldElement::from_le_bytes(&B.into());

        let expected =
            FieldElement::from_le_bytes(&hex!("99e94bd4ef8a2c3b884cfa59ca342b2e").into());
        assert_eq!(a + b, expected);
        assert_eq!(b + a, expected);
    }

    #[test]
    fn fe_mul() {
        let a = FieldElement::from_le_bytes(&A.into());
        let b = FieldElement::from_le_bytes(&B.into());

        let expected =
            FieldElement::from_le_bytes(&hex!("ebe563401e7e91ea3ad6426b8140c394").into());
        assert_eq!(a * b, expected);
        assert_eq!(b * a, expected);
    }
}
