//! Intel `CLMUL`-accelerated implementation for modern x86/x86_64 CPUs
//! (i.e. Intel Sandy Bridge-compatible or newer)
//!
//! Based on implementation by Eric Lagergren at
//! <https://github.com/ericlagergren/polyval-rs/>.

#![allow(unsafe_op_in_unsafe_fn, unused_unsafe)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::FieldElement;
use crate::Block;
use core::ptr;
use universal_hash::array::{Array, ArraySize};

/// 128-bit SIMD register type.
pub(super) type Simd128 = __m128i;

/// Perform carryless multiplication of `y` by `h` and return the result.
///
/// # Safety
///
/// The SSE2 and pclmulqdq target features must be enabled.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) unsafe fn polymul(x: Simd128, y: Simd128) -> Simd128 {
    let (h, m, l) = unsafe { karatsuba1(x, y) };
    let (h, l) = unsafe { karatsuba2(h, m, l) };
    unsafe {
        mont_reduce(h, l) // d
    }
}

/// Perform carryless multiplication of `y` by `h` and return the result.
#[inline]
#[target_feature(enable = "pclmulqdq")]
pub(super) unsafe fn proc_block(h: FieldElement, y: FieldElement, x: &Block) -> FieldElement {
    let x = unsafe { _mm_loadu_si128(x.as_ptr().cast()) };
    unsafe { polymul(_mm_xor_si128(y.into(), x), h.into()).into() }
}

#[inline]
#[target_feature(enable = "pclmulqdq")]
pub(super) unsafe fn proc_par_blocks<const N: usize, U: ArraySize>(
    powers_of_h: &[FieldElement; N],
    y: FieldElement,
    blocks: &Array<Block, U>,
) -> FieldElement {
    unsafe {
        let mut h = _mm_setzero_si128();
        let mut m = _mm_setzero_si128();
        let mut l = _mm_setzero_si128();

        // Note: Manually unrolling this loop did not help in benchmarks.
        for i in (0..N).rev() {
            let mut x = _mm_loadu_si128(blocks[i].as_ptr().cast());
            if i == 0 {
                x = _mm_xor_si128(x, y.into());
            }
            let (hh, mm, ll) = karatsuba1(x, powers_of_h[i].into());
            h = _mm_xor_si128(h, hh);
            m = _mm_xor_si128(m, mm);
            l = _mm_xor_si128(l, ll);
        }

        let (h, l) = karatsuba2(h, m, l);
        mont_reduce(h, l).into()
    }
}

impl From<FieldElement> for Simd128 {
    #[inline]
    fn from(fe: FieldElement) -> Simd128 {
        unsafe { _mm_loadu_si128(fe.0.as_ptr().cast()) }
    }
}

impl From<Simd128> for FieldElement {
    #[inline]
    fn from(fe: Simd128) -> FieldElement {
        let mut ret = FieldElement::default();
        unsafe { _mm_store_si128(ret.0.as_mut_ptr().cast(), fe) }
        ret
    }
}

/// Karatsuba decomposition for `x*y`.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn karatsuba1(x: Simd128, y: Simd128) -> (Simd128, Simd128, Simd128) {
    // First Karatsuba step: decompose x and y.
    //
    // (x1*y0 + x0*y1) = (x1+x0) * (y1+x0) + (x1*y1) + (x0*y0)
    //        M                                 H         L
    //
    // m = x.hi^x.lo * y.hi^y.lo
    let m = unsafe {
        clmul(
            _mm_xor_si128(x, _mm_shuffle_epi32(x, 0xee)),
            _mm_xor_si128(y, _mm_shuffle_epi32(y, 0xee)),
        )
    };
    let h = unsafe { clmul2(y, x) }; // h = x.hi * y.hi
    let l = unsafe { clmul(y, x) }; // l = x.lo * y.lo
    (h, m, l)
}

/// Karatsuba combine.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn karatsuba2(h: Simd128, m: Simd128, l: Simd128) -> (Simd128, Simd128) {
    // Second Karatsuba step: combine into a 2n-bit product.
    //
    // m0 ^= l0 ^ h0 // = m0^(l0^h0)
    // m1 ^= l1 ^ h1 // = m1^(l1^h1)
    // l1 ^= m0      // = l1^(m0^l0^h0)
    // h0 ^= l0 ^ m1 // = h0^(l0^m1^l1^h1)
    // h1 ^= l1      // = h1^(l1^m0^l0^h0)
    let t = unsafe {
        //   {m0, m1} ^ {l1, h0}
        // = {m0^l1, m1^h0}
        let t0 = {
            _mm_xor_si128(
                m,
                _mm_castps_si128(_mm_shuffle_ps(
                    _mm_castsi128_ps(l),
                    _mm_castsi128_ps(h),
                    0x4e,
                )),
            )
        };

        //   {h0, h1} ^ {l0, l1}
        // = {h0^l0, h1^l1}
        let t1 = _mm_xor_si128(h, l);

        //   {m0^l1, m1^h0} ^ {h0^l0, h1^l1}
        // = {m0^l1^h0^l0, m1^h0^h1^l1}
        _mm_xor_si128(t0, t1)
    };

    // {m0^l1^h0^l0, l0}
    let x01 = unsafe { _mm_unpacklo_epi64(l, t) };
    // {h1, m1^h0^h1^l1}
    let x23 = unsafe { _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(h), _mm_castsi128_ps(t))) };

    (x23, x01)
}

/// Perform Montgomery reduction of the 256-bit product into 128-bits.
///
/// # Safety
/// It is the caller's responsibility to ensure the host CPU is capable of CLMUL and SSE2
/// instructions.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mont_reduce(x23: Simd128, x01: Simd128) -> Simd128 {
    // Perform the Montgomery reduction over the 256-bit X.
    //    [A1:A0] = X0 • poly
    //    [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
    //    [C1:C0] = B0 • poly
    //    [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
    // Output: [D1 ⊕ X3 : D0 ⊕ X2]
    static POLY: u128 = (1 << 127) | (1 << 126) | (1 << 121) | (1 << 63) | (1 << 62) | (1 << 57);
    let poly = unsafe { _mm_loadu_si128(ptr::addr_of!(POLY).cast()) };
    let a = unsafe { clmul(x01, poly) };
    let b = unsafe { _mm_xor_si128(x01, _mm_shuffle_epi32(a, 0x4e)) };
    let c = unsafe { clmul2(b, poly) };
    unsafe { _mm_xor_si128(x23, _mm_xor_si128(c, b)) }
}

/// Multiplies the low bits in `a` and `b`.
///
/// # Safety
/// It is the caller's responsibility to ensure the host CPU is capable of CLMUL and SSE2
/// instructions.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul(a: Simd128, b: Simd128) -> Simd128 {
    // SAFETY: This requires the `sse2` and `pclmulqdq` features
    // which we have.
    unsafe { _mm_clmulepi64_si128(a, b, 0x00) }
}

/// Multiplies the high bits in `a` and `b`.
///
/// # Safety
/// It is the caller's responsibility to ensure the host CPU is capable of CLMUL and SSE2
/// instructions.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul2(a: Simd128, b: Simd128) -> Simd128 {
    // SAFETY: This requires the `sse2` and `pclmulqdq` features
    // which we have.
    unsafe { _mm_clmulepi64_si128(a, b, 0x11) }
}
