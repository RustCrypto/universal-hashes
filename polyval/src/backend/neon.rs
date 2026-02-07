//! ARM NEON + PMULL optimized POLYVAL implementation using R/F Algorithm
//! Adapted from the implementation in the Apache 2.0+MIT-licensed HPCrypt library
//! Copyright (c) 2024 HPCrypt Contributors
//!
//! This implementation uses the R/F (Reduction/Field) algorithm:
//! - 4 PMULL per block for R and F terms
//! - PMULL-based reduction (1 PMULL) instead of scalar shifts
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

use crate::ParBlocks;
use core::arch::aarch64::*;

/// P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
const P1: u64 = 0xC200000000000000;

// `aes` implies PMULL
cpufeatures::new!(pmull, "aes");
pub(crate) use pmull::InitToken;

/// POLYVAL state using ARM NEON + PMULL with R/F algorithm
#[derive(Clone, Copy)]
pub(super) struct State {
    key: ExpandedKey,
    /// Current accumulator
    acc: uint64x2_t,
}

impl State {
    /// Create a new POLYVAL instance
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub(super) unsafe fn new(h: &[u8; 16]) -> Self {
        Self {
            key: ExpandedKey::new(h),
            acc: vdupq_n_u64(0),
        }
    }

    /// Update with a single block (5 PMULLs)
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    #[inline]
    pub(super) unsafe fn update_block(&mut self, block: &[u8; 16]) {
        // Load directly (POLYVAL uses little-endian, no byte swap)
        let data = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr()));

        // XOR with accumulator
        self.acc = veorq_u64(self.acc, data);

        // Multiply by H using R/F algorithm
        self.acc = gf128_mul_rf(self.acc, self.key.h1, self.key.d1);
    }

    /// Process 4 blocks with R/F algorithm and aggregated reduction
    ///
    /// Uses 16 PMULLs for multiplication (4 per block) + 1 PMULL for reduction = 17 PMULLs total
    #[target_feature(enable = "neon", enable = "aes")]
    #[inline]
    pub(super) unsafe fn proc_par_blocks(&mut self, par_blocks: &ParBlocks) {
        // Load all 4 blocks (no byte swap for POLYVAL)
        let m0 = vreinterpretq_u64_u8(vld1q_u8(par_blocks[0].as_ptr()));
        let m1 = vreinterpretq_u64_u8(vld1q_u8(par_blocks[1].as_ptr()));
        let m2 = vreinterpretq_u64_u8(vld1q_u8(par_blocks[2].as_ptr()));
        let m3 = vreinterpretq_u64_u8(vld1q_u8(par_blocks[3].as_ptr()));

        // XOR first block with accumulator
        let y0 = veorq_u64(self.acc, m0);

        // R/F multiply all 4 blocks (16 PMULLs)
        let (r0, f0) = rf_mul_unreduced(y0, self.key.h4, self.key.d4);
        let (r1, f1) = rf_mul_unreduced(m1, self.key.h3, self.key.d3);
        let (r2, f2) = rf_mul_unreduced(m2, self.key.h2, self.key.d2);
        let (r3, f3) = rf_mul_unreduced(m3, self.key.h1, self.key.d1);

        // Aggregate R and F values
        let r = veorq_u64(veorq_u64(r0, r1), veorq_u64(r2, r3));
        let f = veorq_u64(veorq_u64(f0, f1), veorq_u64(f2, f3));

        // Single reduction (1 PMULL)
        self.acc = reduce_rf(r, f);
    }

    /// Finalize and return the POLYVAL tag
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub(super) unsafe fn finalize(self) -> [u8; 16] {
        // Output directly (POLYVAL uses little-endian, no byte swap)
        let mut output = [0u8; 16];
        vst1q_u8(output.as_mut_ptr(), vreinterpretq_u8_u64(self.acc));
        output
    }

    /// Reset for reuse with the same key
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub(super) unsafe fn reset(&mut self) {
        self.acc = vdupq_n_u64(0);
    }

    /// Zeroize the internal state.
    #[cfg(feature = "zeroize")]
    #[target_feature(enable = "neon", enable = "aes")]
    pub(crate) unsafe fn zeroize(&mut self) {
        // TODO(tarcieri): zeroize
    }
}

/// Precomputed key material for POLYVAL using R/F algorithm
///
/// Stores H and D values for each power, where D = swap(H) ⊕ (H0 × P1)
#[derive(Clone, Copy)]
pub(super) struct ExpandedKey {
    /// H^1 packed as [h1_hi : h1_lo]
    h1: uint64x2_t,
    /// D^1 = computed from H^1
    d1: uint64x2_t,
    /// H^2
    h2: uint64x2_t,
    /// D^2
    d2: uint64x2_t,
    /// H^3
    h3: uint64x2_t,
    /// D^3
    d3: uint64x2_t,
    /// H^4
    h4: uint64x2_t,
    /// D^4
    d4: uint64x2_t,
}

impl ExpandedKey {
    /// Create a new POLYVAL key with R/F algorithm
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub(super) unsafe fn new(h: &[u8; 16]) -> Self {
        let h1 = vreinterpretq_u64_u8(vld1q_u8(h.as_ptr()));
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

/// Compute D from H using R/F algorithm
///
/// D = swap(H) ⊕ (H0 × P1)
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn compute_d(h: uint64x2_t) -> uint64x2_t {
    // Swap halves: [H1 : H0] -> [H0 : H1]
    let h_swap = vextq_u64(h, h, 1);

    // T = H0 × P1 (polynomial multiply)
    let h0 = vgetq_lane_u64(h, 0);
    let t = vreinterpretq_u64_p128(vmull_p64(h0, P1));

    // D = swap(H) ⊕ T
    veorq_u64(h_swap, t)
}

/// R/F multiplication: compute R and F terms (4 PMULLs)
///
/// R = M0×D1 ⊕ M1×H1
/// F = M0×D0 ⊕ M1×H0
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn rf_mul_unreduced(
    m: uint64x2_t,
    h: uint64x2_t,
    d: uint64x2_t,
) -> (uint64x2_t, uint64x2_t) {
    let m0 = vgetq_lane_u64(m, 0);
    let m1 = vgetq_lane_u64(m, 1);
    let h0 = vgetq_lane_u64(h, 0);
    let h1 = vgetq_lane_u64(h, 1);
    let d0 = vgetq_lane_u64(d, 0);
    let d1 = vgetq_lane_u64(d, 1);

    // R = M0×D1 ⊕ M1×H1
    let r0 = vmull_p64(m0, d1);
    let r1 = vmull_p64(m1, h1);
    let r = veorq_u64(vreinterpretq_u64_p128(r0), vreinterpretq_u64_p128(r1));

    // F = M0×D0 ⊕ M1×H0
    let f0 = vmull_p64(m0, d0);
    let f1 = vmull_p64(m1, h0);
    let f = veorq_u64(vreinterpretq_u64_p128(f0), vreinterpretq_u64_p128(f1));

    (r, f)
}

/// Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
///
/// Uses 1 PMULL for reduction
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn reduce_rf(r: uint64x2_t, f: uint64x2_t) -> uint64x2_t {
    // F1 (high 64 bits of f)
    let f1 = vgetq_lane_u64(f, 1);
    let f1_vec = vcombine_u64(vcreate_u64(f1), vcreate_u64(0));

    // x^64×F0 (shift F0 to high position)
    let f0 = vgetq_lane_u64(f, 0);
    let f0_shifted = vcombine_u64(vcreate_u64(0), vcreate_u64(f0));

    // P1×F0
    let p1_f0: u128 = vmull_p64(f0, P1);

    // Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
    let result = veorq_u64(r, f1_vec);
    let result = veorq_u64(result, f0_shifted);
    veorq_u64(result, vreinterpretq_u64_p128(p1_f0))
}

/// Complete R/F multiplication with reduction (5 PMULLs total)
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn gf128_mul_rf(m: uint64x2_t, h: uint64x2_t, d: uint64x2_t) -> uint64x2_t {
    let (r, f) = rf_mul_unreduced(m, h, d);
    reduce_rf(r, f)
}
