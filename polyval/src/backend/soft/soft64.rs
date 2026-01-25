//! Constant-time software implementation of POLYVAL for 64-bit architectures.
//! Adapted from BearSSL's `ghash_ctmul64.c`:
//!
//! <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c;hb=4b6046412>
//!
//! Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
//!
//! Note that this implementation doesn't use its generic argument,
//! since (experimentally) it gets no performance benefit from doing so.
//! `N` is present only so that we can provide a `GenericPolyval` that
//! is always generic.

use crate::Block;
use core::{
    num::Wrapping,
    ops::{Add, Mul},
};
use universal_hash::crypto_common::array::{Array, sizes::U8};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// POLYVAL field element implemented as 2 x `u64` values.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct FieldElement(u64, u64);

impl FieldElement {
    /// Decode field element from little endian bytestring representation.
    #[inline]
    pub(super) fn from_le_bytes(bytes: &Block) -> FieldElement {
        // TODO(tarcieri): use `[T]::as_chunks` when MSRV is 1.88
        let (chunks, remainder) = Array::<u8, U8>::slice_as_chunks(bytes);
        debug_assert!(remainder.is_empty());
        Self(
            u64::from_le_bytes(chunks[0].into()),
            u64::from_le_bytes(chunks[1].into()),
        )
    }

    /// Encode field element as little endian bytestring representation.
    #[inline]
    pub(super) fn to_le_bytes(self) -> Block {
        let mut block = Block::default();
        let (lo, hi) = block.split_at_mut(8);
        lo.copy_from_slice(&self.0.to_le_bytes());
        hi.copy_from_slice(&self.1.to_le_bytes());
        block
    }

    /// Compute the unreduced 256-bit carryless product of two 128-bit field elements.
    ///
    /// Uses a Karatsuba decomposition in which the 128x128 multiplication is reduced to three 64x64
    /// multiplications together with a bit-reversal trick to efficiently recover the high half.
    #[inline]
    fn karatsuba(self, rhs: FieldElement) -> (u64, u64, u64, u64) {
        // Karatsuba input decomposition for H
        let h0 = self.0;
        let h1 = self.1;
        let h0r = h0.reverse_bits();
        let h1r = h1.reverse_bits();
        let h2 = h0 ^ h1;
        let h2r = h0r ^ h1r;

        // Karatsuba input decomposition for Y
        let y0 = rhs.0;
        let y1 = rhs.1;
        let y0r = y0.reverse_bits();
        let y1r = y1.reverse_bits();
        let y2 = y0 ^ y1;
        let y2r = y0r ^ y1r;

        // Perform carryless multiplications
        let z0 = bmul64(y0, h0);
        let z1 = bmul64(y1, h1);
        let mut z2 = bmul64(y2, h2);
        let mut z0h = bmul64(y0r, h0r);
        let mut z1h = bmul64(y1r, h1r);
        let mut z2h = bmul64(y2r, h2r);

        // Karatsuba recombination
        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = z0h.reverse_bits() >> 1;
        z1h = z1h.reverse_bits() >> 1;
        z2h = z2h.reverse_bits() >> 1;

        // Assemble the final 256-bit product as 64x4
        let v0 = z0;
        let v1 = z0h ^ z2;
        let v2 = z1 ^ z2h;
        let v3 = z1h;
        (v0, v1, v2, v3)
    }
}

impl From<u128> for FieldElement {
    fn from(x: u128) -> Self {
        FieldElement((x >> 64) as u64, (x & 0xFFFF_FFFF_FFFF_FFFF) as u64)
    }
}

impl Add for FieldElement {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

/// Computes carryless POLYVAL multiplication over GF(2^128) in constant time.
///
/// Method described at: <https://www.bearssl.org/constanttime.html#ghash-for-gcm>
///
/// POLYVAL multiplication is effectively the little endian equivalent of
/// GHASH multiplication, aside from one small detail described here:
///
/// <https://crypto.stackexchange.com/questions/66448/how-does-bearssls-gcm-modular-reduction-work/66462#66462>
///
/// > The product of two bit-reversed 128-bit polynomials yields the
/// > bit-reversed result over 255 bits, not 256. The BearSSL code ends up
/// > with a 256-bit result in zw[], and that value is shifted by one bit,
/// > because of that reversed convention issue. Thus, the code must
/// > include a shifting step to put it back where it should
///
/// This shift is unnecessary for POLYVAL and has been removed.
impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let (v0, v1, v2, v3) = self.karatsuba(rhs);
        mont_reduce(v0, v1, v2, v3)
    }
}

/// Reduce the 256-bit carryless product of Karatsuba modulo the POLYVAL polynomial.
///
/// This performs constant-time folding using shifts and XORs corresponding to the irreducible
/// polynomial `x^128 + x^127 + x^126 + x^121 + 1`. This is closely related to GHASH reduction but
/// the polynomial's bit order is reversed in POLYVAL.
#[inline]
fn mont_reduce(v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> FieldElement {
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    FieldElement(v2, v3)
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
        self.1.zeroize();
    }
}

/// Multiplication in GF(2)[X], truncated to the low 64-bits, with "holes" (sequences of zeroes) to
/// avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked out of the result.
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;

    let x0 = Wrapping(x & M0);
    let x1 = Wrapping(x & M1);
    let x2 = Wrapping(x & M2);
    let x3 = Wrapping(x & M3);

    let y0 = Wrapping(y & M0);
    let y1 = Wrapping(y & M1);
    let y2 = Wrapping(y & M2);
    let y3 = Wrapping(y & M3);

    let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

    (z0.0 & M0) | (z1.0 & M1) | (z2.0 & M2) | (z3.0 & M3)
}
