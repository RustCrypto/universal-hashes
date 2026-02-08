//! AVX2 + PCLMULQDQ optimized POLYVAL implementation using R/F Algorithm
//! Adapted from the implementation in the Apache 2.0+MIT-licensed HPCrypt library
//! Copyright (c) 2024 HPCrypt Contributors
//!
//! Uses the R/F algorithm from "Efficient GHASH Implementation Using CLMUL":
//! - 4 CLMULs per block for multiplication (R and F terms)
//! - 1 CLMUL for reduction (Lemma 3)
//! - 4-block aggregated processing with single reduction
//!
//! Key equations:
//! - D = swap(H) ⊕ (H0 × P1)
//! - R = M0×D1 ⊕ M1×H1
//! - F = M0×D0 ⊕ M1×H0
//! - Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
//!
//! POLYVAL operates in GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1
//! Unlike GHASH, POLYVAL uses little-endian byte ordering (no byte swap needed).
//!
//! <https://eprint.iacr.org/2025/2171.pdf>

#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::ParBlocks;

/// P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
const P1: u64 = 0xC200000000000000;

cpufeatures::new!(clmul, "pclmulqdq");
pub(crate) use clmul::InitToken;

/// POLYVAL state using AVX2 + PCLMULQDQ with R/F algorithm
#[derive(Clone, Copy)]
pub(super) struct State {
    key: ExpandedKey,
    /// Current accumulator
    acc: __m128i,
}

impl State {
    /// Create a new POLYVAL instance
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub(super) unsafe fn new(h: &[u8; 16]) -> Self {
        Self {
            key: ExpandedKey::new(h),
            acc: _mm_setzero_si128(),
        }
    }

    /// Update with a single block (5 CLMULs)
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    #[inline]
    pub(super) unsafe fn update_block(&mut self, block: &[u8; 16]) {
        let data = _mm_loadu_si128(block.as_ptr().cast());

        // XOR with accumulator
        self.acc = _mm_xor_si128(self.acc, data);

        // Multiply by H using R/F algorithm
        self.acc = gf128_mul_rf(self.acc, self.key.h1, self.key.d1);
    }

    /// Process 4 blocks with R/F algorithm and aggregated reduction
    ///
    /// Uses 16 CLMULs for multiplication (4 per block) + 1 CLMUL for reduction = 17 CLMULs total
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    #[inline]
    pub(super) unsafe fn proc_par_blocks(&mut self, par_blocks: &ParBlocks) {
        // Load all 4 blocks (no byte swap for POLYVAL)
        let m0 = _mm_loadu_si128(par_blocks[0].as_ptr().cast());
        let m1 = _mm_loadu_si128(par_blocks[1].as_ptr().cast());
        let m2 = _mm_loadu_si128(par_blocks[2].as_ptr().cast());
        let m3 = _mm_loadu_si128(par_blocks[3].as_ptr().cast());

        // XOR first block with accumulator
        let y0 = _mm_xor_si128(self.acc, m0);

        // R/F multiply all 4 blocks (16 CLMULs)
        let (r0, f0) = rf_mul_unreduced(y0, self.key.h4, self.key.d4);
        let (r1, f1) = rf_mul_unreduced(m1, self.key.h3, self.key.d3);
        let (r2, f2) = rf_mul_unreduced(m2, self.key.h2, self.key.d2);
        let (r3, f3) = rf_mul_unreduced(m3, self.key.h1, self.key.d1);

        // Aggregate R and F values
        let r = _mm_xor_si128(_mm_xor_si128(r0, r1), _mm_xor_si128(r2, r3));
        let f = _mm_xor_si128(_mm_xor_si128(f0, f1), _mm_xor_si128(f2, f3));

        // Single reduction (1 CLMUL)
        self.acc = reduce_rf(r, f);
    }

    /// Finalize and return the POLYVAL tag
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub(super) unsafe fn finalize(self) -> [u8; 16] {
        // Output directly (POLYVAL uses little-endian, no byte swap)
        let mut output = [0u8; 16];
        _mm_storeu_si128(output.as_mut_ptr().cast(), self.acc);
        output
    }

    /// Reset for reuse with the same key
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub(super) unsafe fn reset(&mut self) {
        self.acc = _mm_setzero_si128();
    }

    /// Zeroize the internal state.
    #[cfg(feature = "zeroize")]
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub(super) unsafe fn zeroize(&mut self) {
        // TODO(tarcieri): zeroize
    }
}

/// Precomputed key material for POLYVAL using R/F algorithm
///
/// Stores H and D values for each power, where D = swap(H) ⊕ (H0 × P1)
#[derive(Clone, Copy)]
pub(super) struct ExpandedKey {
    /// H^1 packed as [h1_hi : h1_lo]
    h1: __m128i,
    /// D^1 = computed from H^1
    d1: __m128i,
    /// H^2
    h2: __m128i,
    /// D^2
    d2: __m128i,
    /// H^3
    h3: __m128i,
    /// D^3
    d3: __m128i,
    /// H^4
    h4: __m128i,
    /// D^4
    d4: __m128i,
}

impl ExpandedKey {
    /// Create a new POLYVAL key with R/F algorithm
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub(super) unsafe fn new(h: &[u8; 16]) -> Self {
        // Load H directly (POLYVAL uses little-endian, no byte swap needed)
        let h1 = _mm_loadu_si128(h.as_ptr().cast());
        let d1 = compute_d(h1);

        // Compute powers using R/F multiplication
        let h2 = gf128_mul_rf(h1, h1, d1);
        let d2 = compute_d(h2);

        let h3 = gf128_mul_rf(h2, h1, d1);
        let d3 = compute_d(h3);

        let h4 = gf128_mul_rf(h2, h2, d2);
        let d4 = compute_d(h4);

        Self {
            h1,
            d1,
            h2,
            d2,
            h3,
            d3,
            h4,
            d4,
        }
    }
}

/// Compute D from H using the R/F algorithm
///
/// D = swap(H) ⊕ (H0 × P1)
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn compute_d(h: __m128i) -> __m128i {
    // TODO(tarcieri): P1.cast_signed() when MSRV 1.87+
    #[allow(clippy::cast_possible_wrap)]
    let p = _mm_set_epi64x(P1 as i64, 0);

    // Swap halves: [H1 : H0] -> [H0 : H1]
    let h_swap = _mm_shuffle_epi32(h, 0x4e);

    // T = H0 × P1
    let t = _mm_clmulepi64_si128(h, p, 0x10);

    // D = swap(H) ⊕ T
    _mm_xor_si128(h_swap, t)
}

/// R/F multiplication using 4 CLMULs per block
///
/// Given M = [M1 : M0] and precomputed H = [H1 : H0], D = [D1 : D0]:
/// - R = M0×D1 ⊕ M1×H1 (2 CLMULs)
/// - F = M0×D0 ⊕ M1×H0 (2 CLMULs)
///
/// Returns (R, F) for later reduction
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn rf_mul_unreduced(m: __m128i, h: __m128i, d: __m128i) -> (__m128i, __m128i) {
    // R = M0×D1 ⊕ M1×H1
    let r0 = _mm_clmulepi64_si128(m, d, 0x10); // M0 × D1
    let r1 = _mm_clmulepi64_si128(m, h, 0x11); // M1 × H1
    let r = _mm_xor_si128(r0, r1);

    // F = M0×D0 ⊕ M1×H0
    let f0 = _mm_clmulepi64_si128(m, d, 0x00); // M0 × D0
    let f1 = _mm_clmulepi64_si128(m, h, 0x01); // M1 × H0
    let f = _mm_xor_si128(f0, f1);

    (r, f)
}

/// Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
///
/// Uses 1 CLMUL for reduction
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn reduce_rf(r: __m128i, f: __m128i) -> __m128i {
    // TODO(tarcieri): P1.cast_signed() when MSRV 1.87+
    #[allow(clippy::cast_possible_wrap)]
    let p1 = _mm_set_epi64x(0, P1 as i64);

    // F1 in low position
    let f1 = _mm_srli_si128(f, 8);

    // x^64×F0 (shift F0 to high position)
    let f0_shifted = _mm_slli_si128(f, 8);

    // P1×F0
    let p1_f0 = _mm_clmulepi64_si128(f, p1, 0x00);

    // Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
    let result = _mm_xor_si128(r, f1);
    let result = _mm_xor_si128(result, f0_shifted);
    _mm_xor_si128(result, p1_f0)
}

/// Complete R/F multiplication with reduction (5 CLMULs total)
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn gf128_mul_rf(m: __m128i, h: __m128i, d: __m128i) -> __m128i {
    let (r, f) = rf_mul_unreduced(m, h, d);
    reduce_rf(r, f)
}
