//! Portable pure Rust implementation which can computes carryless POLYVAL multiplication over
//! GF (2^128) in constant time. Both 32-bit and 64-bit backends are available.
//!
//! Method described at: <https://www.bearssl.org/constanttime.html#ghash-for-gcm>
//!
//! POLYVAL multiplication is effectively the little endian equivalent of GHASH multiplication,
//! aside from one small detail described here:
//!
//! <https://crypto.stackexchange.com/questions/66448/how-does-bearssls-gcm-modular-reduction-work/66462#66462>
//!
//! > The product of two bit-reversed 128-bit polynomials yields the
//! > bit-reversed result over 255 bits, not 256. The BearSSL code ends up
//! > with a 256-bit result in zw[], and that value is shifted by one bit,
//! > because of that reversed convention issue. Thus, the code must
//! > include a shifting step to put it back where it should
//!
//! This shift is unnecessary for POLYVAL (it is in fact what distinguishes POLYVAL from GHASH) and
//! has been removed.

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

pub(super) use soft_impl::{karatsuba, mont_reduce};

use super::FieldElement;
use crate::{Block, Key, Tag};
use core::{
    num::Wrapping,
    ops::{BitAnd, BitOr, BitXor, Mul, Shl},
};
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
    y: FieldElement,
}

impl<const N: usize> Polyval<N> {
    /// Initialize POLYVAL with the given `H` field element and initial block
    pub fn new_with_init_block(h: &Key, init_block: u128) -> Self {
        Self {
            h: FieldElement::from(*h),
            y: init_block.into(),
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
        let x = FieldElement::from(x);
        self.y = (self.y + x) * self.h;
    }
}

impl<const N: usize> UniversalHash for Polyval<N> {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    fn finalize(self) -> Tag {
        self.y.into()
    }
}

impl<const N: usize> Reset for Polyval<N> {
    fn reset(&mut self) {
        self.y = FieldElement::default();
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> Drop for Polyval<N> {
    fn drop(&mut self) {
        self.h.zeroize();
        self.y.zeroize();
    }
}

/// Multiplication in GF(2)[X], implemented generically and wrapped as `bmul32` and `bmul64`.
///
/// Uses "holes" (sequences of zeroes) to avoid carry spilling, as specified in the mask operand
/// `m0` which should have a full-width value with the following bit pattern:
///
/// `0b100010001...0001` (e.g. `0x1111_1111u32`)
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked out of the result.
#[inline]
fn bmul<T>(x: T, y: T, m0: T) -> T
where
    T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Shl<u32, Output = T>,
    Wrapping<T>: BitXor<Output = Wrapping<T>> + Mul<Output = Wrapping<T>>,
{
    let m1 = m0 << 1;
    let m2 = m1 << 1;
    let m3 = m2 << 1;

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
