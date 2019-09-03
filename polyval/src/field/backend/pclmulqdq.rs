//! Support for the PCLMULQDQ CPU intrinsic on `x86` and `x86_64` target
//! architectures.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::Backend;
use crate::field::Block;
use core::ops::{Add, Mul};

/// Wrapper for `__m128i` - a 128-bit XMM register (SSE2)
#[repr(align(16))]
#[derive(Copy, Clone)]
pub struct M128i(__m128i);

impl Backend for M128i {}

impl From<Block> for M128i {
    // `_mm_loadu_si128` performs an unaligned load
    #[allow(clippy::cast_ptr_alignment)]
    fn from(bytes: Block) -> M128i {
        M128i(unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) })
    }
}

impl From<M128i> for Block {
    // `_mm_storeu_si128` performs an unaligned store
    #[allow(clippy::cast_ptr_alignment)]
    fn from(xmm: M128i) -> Block {
        let mut result = Block::default();

        unsafe {
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, xmm.0);
        }

        result
    }
}

impl Add for M128i {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    fn add(self, rhs: Self) -> Self {
        M128i(unsafe { xor(self.0, rhs.0) })
    }
}

impl Mul for M128i {
    type Output = Self;

    /// Computes carryless POLYVAL multiplication over GF(2^128).
    fn mul(self, rhs: Self) -> Self {
        unsafe {
            let t1 = pclmulqdq(self.0, rhs.0, 0x00);
            let t2 = pclmulqdq(self.0, rhs.0, 0x01);
            let t3 = pclmulqdq(self.0, rhs.0, 0x10);
            let t4 = pclmulqdq(self.0, rhs.0, 0x11);
            let t5 = xor(t2, t3);
            let t6 = xor(t4, psrldq8(t5));
            let t7 = xor(t1, pslldq8(t5));
            M128i(xor(t6, reduce(t7)))
        }
    }
}

/// Mask value used when performing Montgomery fast reduction.
/// This corresponds to POLYVAL's polynomial with the highest bit unset.
const MASK: u128 = 1 << 127 | 1 << 126 | 1 << 121 | 1;

/// Fast reduction modulo x^128 + x^127 + x^126 +x^121 + 1 (Gueron 2012)
/// Algorithm 4: "Montgomery reduction"
///
/// See: <https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf>
unsafe fn reduce(x: __m128i) -> __m128i {
    // `_mm_loadu_si128` performs an unaligned load
    // (`u128` is not necessarily aligned to 16-bytes)
    #[allow(clippy::cast_ptr_alignment)]
    let mask = _mm_loadu_si128(&MASK as *const u128 as *const __m128i);
    let a = pclmulqdq(mask, x, 0x01);
    let b = xor(shufpd1(x), a);
    let c = pclmulqdq(mask, b, 0x01);
    xor(shufpd1(b), c)
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn xor(a: __m128i, b: __m128i) -> __m128i {
    _mm_xor_si128(a, b)
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn shufpd1(a: __m128i) -> __m128i {
    let a = _mm_castsi128_pd(a);
    _mm_castpd_si128(_mm_shuffle_pd(a, a, 1))
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn pslldq8(a: __m128i) -> __m128i {
    _mm_bslli_si128(a, 8)
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn psrldq8(a: __m128i) -> __m128i {
    _mm_bsrli_si128(a, 8)
}

// TODO(tarcieri): _mm256_clmulepi64_epi128 (vpclmulqdq)
#[target_feature(enable = "pclmulqdq", enable = "sse2", enable = "sse4.1")]
unsafe fn pclmulqdq(a: __m128i, b: __m128i, imm: u8) -> __m128i {
    // The `imm` value passed to `_mm_clmulepi64_si128` needs to be a literal
    // value since it ends up being encoded into the CPU instruction.
    match imm {
        // Low-Low: `clmul(a[0..8], b[0..8])` (PCLMULLQLQDQ)
        0x00 => _mm_clmulepi64_si128(a, b, 0x00),

        // High-Low: `clmul(a[8..16], b[0..8])` (PCLMULHQLQDQ)
        0x01 => _mm_clmulepi64_si128(a, b, 0x01),

        // Low-High: `clmul(a[0..8], b[8..16])` (PCLMULLQHQDQ)
        0x10 => _mm_clmulepi64_si128(a, b, 0x10),

        // High-High: `clmul(a[8..16], b[8..16])` (PCLMULHQHQDQ)
        0x11 => _mm_clmulepi64_si128(a, b, 0x11),

        _ => unreachable!(),
    }
}
