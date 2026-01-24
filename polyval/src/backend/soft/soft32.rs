//! Constant-time software implementation of POLYVAL for 32-bit architectures
//! Adapted from BearSSL's `ghash_ctmul32.c`:
//!
//! <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul32.c;hb=4b6046412>
//!
//! Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
//!
//! This implementation uses 32-bit multiplications, and only the low
//! 32 bits for each multiplication result. This is meant primarily for
//! the ARM Cortex M0 and M0+, whose multiplication opcode does not yield
//! the upper 32 bits; but it might also be useful on architectures where
//! access to the upper 32 bits requires use of specific registers that
//! create contention (e.g. on i386, "mul" necessarily outputs the result
//! in edx:eax, while "imul" can use any registers but is limited to the
//! low 32 bits).
//!
//! The implementation trick that is used here is bit-reversing (bit 0
//! is swapped with bit 31, bit 1 with bit 30, and so on). In GF(2)[X],
//! for all values x and y, we have:
//!
//! ```text
//! x.reverse_bits() * y.reverse_bits() = (x * y).reverse_bits()
//! ```
//!
//! In other words, if we bit-reverse (over 32 bits) the operands, then we
//! bit-reverse (over 64 bits) the result.
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

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// POLYVAL field element implemented as 4 x `u32` values.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FieldElement(u32, u32, u32, u32);

impl FieldElement {
    /// Decode field element from little endian bytestring representation.
    #[inline]
    pub(crate) fn from_le_bytes(bytes: &Block) -> FieldElement {
        FieldElement(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            u32::from_le_bytes(bytes[12..].try_into().unwrap()),
        )
    }

    /// Encode field element as little endian bytestring representation.
    #[inline]
    pub(crate) fn to_le_bytes(self) -> Block {
        let mut block = Block::default();

        for (chunk, i) in block.chunks_mut(4).zip([self.0, self.1, self.2, self.3]) {
            chunk.copy_from_slice(&i.to_le_bytes());
        }

        block
    }
}

impl From<u128> for FieldElement {
    fn from(x: u128) -> Self {
        FieldElement(
            x as u32,
            (x >> 32) as u32,
            (x >> 64) as u32,
            (x >> 96) as u32,
        )
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for FieldElement {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Mul for FieldElement {
    type Output = Self;

    /// Computes carryless POLYVAL multiplication over GF(2^128) in constant time.
    ///
    /// Method described at:
    /// <https://www.bearssl.org/constanttime.html#ghash-for-gcm>
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
    fn mul(self, rhs: Self) -> Self {
        let hw = [self.0, self.1, self.2, self.3];
        let yw = [rhs.0, rhs.1, rhs.2, rhs.3];
        let hwr = [
            hw[0].reverse_bits(),
            hw[1].reverse_bits(),
            hw[2].reverse_bits(),
            hw[3].reverse_bits(),
        ];

        // We are using Karatsuba: the 128x128 multiplication is
        // reduced to three 64x64 multiplications, hence nine
        // 32x32 multiplications. With the bit-reversal trick,
        // we have to perform 18 32x32 multiplications.

        let mut a = [0u32; 18];

        a[0] = yw[0];
        a[1] = yw[1];
        a[2] = yw[2];
        a[3] = yw[3];
        a[4] = a[0] ^ a[1];
        a[5] = a[2] ^ a[3];
        a[6] = a[0] ^ a[2];
        a[7] = a[1] ^ a[3];
        a[8] = a[6] ^ a[7];
        a[9] = yw[0].reverse_bits();
        a[10] = yw[1].reverse_bits();
        a[11] = yw[2].reverse_bits();
        a[12] = yw[3].reverse_bits();
        a[13] = a[9] ^ a[10];
        a[14] = a[11] ^ a[12];
        a[15] = a[9] ^ a[11];
        a[16] = a[10] ^ a[12];
        a[17] = a[15] ^ a[16];

        let mut b = [0u32; 18];

        b[0] = hw[0];
        b[1] = hw[1];
        b[2] = hw[2];
        b[3] = hw[3];
        b[4] = b[0] ^ b[1];
        b[5] = b[2] ^ b[3];
        b[6] = b[0] ^ b[2];
        b[7] = b[1] ^ b[3];
        b[8] = b[6] ^ b[7];
        b[9] = hwr[0];
        b[10] = hwr[1];
        b[11] = hwr[2];
        b[12] = hwr[3];
        b[13] = b[9] ^ b[10];
        b[14] = b[11] ^ b[12];
        b[15] = b[9] ^ b[11];
        b[16] = b[10] ^ b[12];
        b[17] = b[15] ^ b[16];

        let mut c = [0u32; 18];

        for i in 0..18 {
            c[i] = bmul32(a[i], b[i]);
        }

        c[4] ^= c[0] ^ c[1];
        c[5] ^= c[2] ^ c[3];
        c[8] ^= c[6] ^ c[7];

        c[13] ^= c[9] ^ c[10];
        c[14] ^= c[11] ^ c[12];
        c[17] ^= c[15] ^ c[16];

        let mut zw = [0u32; 8];

        zw[0] = c[0];
        zw[1] = c[4] ^ c[9].reverse_bits() >> 1;
        zw[2] = c[1] ^ c[0] ^ c[2] ^ c[6] ^ c[13].reverse_bits() >> 1;
        zw[3] = c[4] ^ c[5] ^ c[8] ^ (c[10] ^ c[9] ^ c[11] ^ c[15]).reverse_bits() >> 1;
        zw[4] = c[2] ^ c[1] ^ c[3] ^ c[7] ^ (c[13] ^ c[14] ^ c[17]).reverse_bits() >> 1;
        zw[5] = c[5] ^ (c[11] ^ c[10] ^ c[12] ^ c[16]).reverse_bits() >> 1;
        zw[6] = c[3] ^ c[14].reverse_bits() >> 1;
        zw[7] = c[12].reverse_bits() >> 1;

        for i in 0..4 {
            let lw = zw[i];
            zw[i + 4] ^= lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7);
            zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
        }

        FieldElement(zw[4], zw[5], zw[6], zw[7])
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
        self.1.zeroize();
        self.2.zeroize();
        self.3.zeroize();
    }
}

/// Multiplication in GF(2)[X], truncated to the low 32-bits, with “holes”
/// (sequences of zeroes) to avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked
/// out of the result.
fn bmul32(x: u32, y: u32) -> u32 {
    let x0 = Wrapping(x & 0x1111_1111);
    let x1 = Wrapping(x & 0x2222_2222);
    let x2 = Wrapping(x & 0x4444_4444);
    let x3 = Wrapping(x & 0x8888_8888);
    let y0 = Wrapping(y & 0x1111_1111);
    let y1 = Wrapping(y & 0x2222_2222);
    let y2 = Wrapping(y & 0x4444_4444);
    let y3 = Wrapping(y & 0x8888_8888);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111;
    z1 &= 0x2222_2222;
    z2 &= 0x4444_4444;
    z3 &= 0x8888_8888;

    z0 | z1 | z2 | z3
}
