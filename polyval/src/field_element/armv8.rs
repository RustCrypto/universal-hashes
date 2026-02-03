//! ARMv8 `PMULL`-accelerated implementation of POLYVAL.
//!
//! Based on this C intrinsics implementation:
//! <https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c>
//!
//! Original C written and placed in public domain by Jeffrey Walton.
//! Based on code from ARM, and by Johannes Schneiders, Skip Hovsmith and
//! Barry O'Rourke for the mbedTLS project.
//!
//! Incorporates performance improvements from Eric Lagergren at
//! <https://github.com/ericlagergren/polyval-rs/>.
//!
//! For more information about PMULL, see:
//! - <https://developer.arm.com/documentation/100069/0608/A64-SIMD-Vector-Instructions/PMULL--PMULL2--vector->
//! - <https://eprint.iacr.org/2015/688.pdf>

#![allow(unsafe_op_in_unsafe_fn)]

use super::FieldElement;
use crate::Block;
use core::arch::aarch64::*;
use universal_hash::array::{Array, ArraySize};

/// 128-bit SIMD register type.
pub(super) type Simd128 = uint8x16_t;

/// Perform carryless multiplication of `y` by `h` and return the result.
///
/// # Safety
/// It is the caller's responsibility to ensure the host CPU is capable of PMULL and NEON
/// instructions.
// TODO(tarcieri): investigate ordering optimizations and fusions e.g.`fuse-crypto-eor`
#[inline]
#[target_feature(enable = "aes,neon")]
pub(super) unsafe fn polymul(y: Simd128, h: Simd128) -> Simd128 {
    let (h, m, l) = karatsuba1(h, y);
    let (h, l) = karatsuba2(h, m, l);
    mont_reduce(h, l)
}

/// Process an individual block.
///
/// # Safety
/// It is the caller's responsibility to ensure the host CPU is capable of PMULL and NEON
/// instructions.
#[inline]
#[target_feature(enable = "aes,neon")]
pub(super) unsafe fn proc_block(h: FieldElement, y: FieldElement, x: &Block) -> FieldElement {
    let y = veorq_u8(y.into(), vld1q_u8(x.as_ptr()));
    polymul(y, h.into()).into()
}

/// Process multiple blocks in parallel.
///
/// # Safety
/// It is the caller's responsibility to ensure the host CPU is capable of PMULL and NEON
/// instructions.
#[target_feature(enable = "aes,neon")]
pub(super) unsafe fn proc_par_blocks<const N: usize, U: ArraySize>(
    powers_of_h: &[FieldElement; N],
    y: FieldElement,
    blocks: &Array<Block, U>,
) -> FieldElement {
    unsafe {
        let mut h = vdupq_n_u8(0);
        let mut m = vdupq_n_u8(0);
        let mut l = vdupq_n_u8(0);

        // Note: Manually unrolling this loop did not help in benchmarks.
        for i in (0..N).rev() {
            let mut x = vld1q_u8(blocks[i].as_ptr());
            if i == 0 {
                x = veorq_u8(x, y.into());
            }
            let (hh, mm, ll) = karatsuba1(x, powers_of_h[i].into());
            h = veorq_u8(h, hh);
            m = veorq_u8(m, mm);
            l = veorq_u8(l, ll);
        }

        let (h, l) = karatsuba2(h, m, l);
        mont_reduce(h, l).into()
    }
}

impl From<FieldElement> for Simd128 {
    #[inline]
    fn from(fe: FieldElement) -> Simd128 {
        unsafe { vld1q_u8(fe.0.as_ptr()) }
    }
}

impl From<Simd128> for FieldElement {
    #[inline]
    fn from(fe: Simd128) -> FieldElement {
        let mut ret = FieldElement::default();
        unsafe { vst1q_u8(ret.0.as_mut_ptr(), fe) }
        ret
    }
}

/// Karatsuba decomposition for `x*y`.
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn karatsuba1(x: Simd128, y: Simd128) -> (Simd128, Simd128, Simd128) {
    // First Karatsuba step: decompose x and y.
    //
    // (x1*y0 + x0*y1) = (x1+x0) * (y1+y0) + (x1*y1) + (x0*y0)
    //        M                                 H         L
    //
    // m = x.hi^x.lo * y.hi^y.lo
    let m = pmull(
        veorq_u8(x, vextq_u8(x, x, 8)), // x.hi^x.lo
        veorq_u8(y, vextq_u8(y, y, 8)), // y.hi^y.lo
    );
    let h = pmull2(x, y); // h = x.hi * y.hi
    let l = pmull(x, y); // l = x.lo * y.lo
    (h, m, l)
}

/// Karatsuba combine.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn karatsuba2(h: Simd128, m: Simd128, l: Simd128) -> (Simd128, Simd128) {
    // Second Karatsuba step: combine into a 2n-bit product.
    //
    // m0 ^= l0 ^ h0 // = m0^(l0^h0)
    // m1 ^= l1 ^ h1 // = m1^(l1^h1)
    // l1 ^= m0      // = l1^(m0^l0^h0)
    // h0 ^= l0 ^ m1 // = h0^(l0^m1^l1^h1)
    // h1 ^= l1      // = h1^(l1^m0^l0^h0)
    let t = {
        //   {m0, m1} ^ {l1, h0}
        // = {m0^l1, m1^h0}
        let t0 = veorq_u8(m, vextq_u8(l, h, 8));

        //   {h0, h1} ^ {l0, l1}
        // = {h0^l0, h1^l1}
        let t1 = veorq_u8(h, l);

        //   {m0^l1, m1^h0} ^ {h0^l0, h1^l1}
        // = {m0^l1^h0^l0, m1^h0^h1^l1}
        veorq_u8(t0, t1)
    };

    // {m0^l1^h0^l0, l0}
    let x01 = vextq_u8(
        vextq_u8(l, l, 8), // {l1, l0}
        t,
        8,
    );

    // {h1, m1^h0^h1^l1}
    let x23 = vextq_u8(
        t,
        vextq_u8(h, h, 8), // {h1, h0}
        8,
    );

    (x23, x01)
}

/// POLYVAL reduction polynomial (`x^128 + x^127 + x^126 + x^121 + 1`) encoded in little-endian
/// GF(2)[x] form with reflected reduction terms arising from folding the upper 128-bits of the
/// product into the lower half during modular reduction.
const POLY: u128 = (1 << 127) | (1 << 126) | (1 << 121) | (1 << 63) | (1 << 62) | (1 << 57);

#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn mont_reduce(x23: Simd128, x01: Simd128) -> Simd128 {
    // Perform the Montgomery reduction over the 256-bit X.
    //    [A1:A0] = X0 • poly
    //    [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
    //    [C1:C0] = B0 • poly
    //    [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
    // Output: [D1 ⊕ X3 : D0 ⊕ X2]
    let poly = vreinterpretq_u8_p128(POLY);
    let a = pmull(x01, poly);
    let b = veorq_u8(x01, vextq_u8(a, a, 8));
    let c = pmull2(b, poly);
    veorq_u8(x23, veorq_u8(c, b))
}

/// Multiplies the low bits in `a` and `b`.
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn pmull(a: Simd128, b: Simd128) -> Simd128 {
    vreinterpretq_u8_p128(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), 0),
    ))
}

/// Multiplies the high bits in `a` and `b`.
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn pmull2(a: Simd128, b: Simd128) -> Simd128 {
    vreinterpretq_u8_p128(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), 1),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), 1),
    ))
}
