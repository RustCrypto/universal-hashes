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

use crate::Block;
use crate::field_element::FieldElement;
use core::{
    num::Wrapping,
    ops::{BitAnd, BitOr, BitXor, Mul, Shl},
};
use soft_impl::{karatsuba, mont_reduce};
use universal_hash::array::{Array, ArraySize};

/// Stub implementation which only makes `PolyvalGeneric::h` work.
// TODO(tarcieri): actually implement this optimization?
#[inline]
pub(super) fn powers_of_h<const N: usize>(h: FieldElement) -> [FieldElement; N] {
    let mut ret = [FieldElement::default(); N];
    ret[N - 1] = h;
    ret
}

/// Perform carryless multiplication of `y` by `h` and return the result.
#[inline]
pub(super) fn polymul(y: FieldElement, h: FieldElement) -> FieldElement {
    let v = karatsuba(y, h);
    mont_reduce(v)
}

/// Process an individual block.
// TODO(tarcieri): implement `proc_par_blocks` for soft backend?
#[inline]
pub(super) fn proc_block(h: FieldElement, y: FieldElement, x: &Block) -> FieldElement {
    let x = FieldElement::from(x);
    polymul(y + x, h)
}

/// Process multiple blocks.
// TODO(tarcieri): optimized implementation?
#[inline]
pub(super) fn proc_par_blocks<const N: usize, U: ArraySize>(
    powers_of_h: &[FieldElement; N],
    mut y: FieldElement,
    blocks: &Array<Block, U>,
) -> FieldElement {
    for block in blocks.iter() {
        y = proc_block(powers_of_h[N - 1], y, block);
    }
    y
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
