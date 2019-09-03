//! Support for the PCLMULQDQ CPU intrinsic on `x86` and `x86_64` target
//! architectures.

// The code below uses `loadu`/`storeu` to support unaligned loads/stores
#![allow(clippy::cast_ptr_alignment)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::Backend;
use crate::field::Block;
use core::ops::Add;

/// Wrapper for `__m128i` - a 128-bit XMM register (SSE2)
#[repr(align(16))]
#[derive(Copy, Clone)]
pub struct M128i(__m128i);

impl From<Block> for M128i {
    fn from(bytes: Block) -> M128i {
        M128i(unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) })
    }
}

impl From<M128i> for Block {
    fn from(xmm: M128i) -> Block {
        let mut result = Block::default();

        unsafe {
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, xmm.0);
        }

        result
    }
}

impl From<u128> for M128i {
    fn from(x: u128) -> M128i {
        M128i(unsafe { _mm_loadu_si128(&x as *const u128 as *const __m128i) })
    }
}

impl Add for M128i {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    fn add(self, rhs: Self) -> Self {
        M128i(unsafe { xor(self.0, rhs.0) })
    }
}

impl Backend for M128i {
    /// Wrapper for PCLMULQDQ
    fn clmul(self, rhs: Self, imm: u8) -> Self {
        M128i(unsafe { pclmulqdq(self.0, rhs.0, imm) })
    }

    fn shuffle(self) -> Self {
        M128i(unsafe { shufpd1(self.0) })
    }

    fn shl64(self) -> Self {
        M128i(unsafe { pslldq8(self.0) })
    }

    fn shr64(self) -> Self {
        M128i(unsafe { psrldq8(self.0) })
    }
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
