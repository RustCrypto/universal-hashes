//! NEON implementation of Poly1305 using 26-bit limbs.
//!
//! Uses the same structure as the AVX2 implementation, but with `vmull_u32`/`vmull_high_u32` to
//! perform a widening 128x128 -> 256-bit multiply.

use super::simd::{AdditionKey, Aligned130, PrecomputedMultiplier};
use crate::Key;
use core::arch::aarch64::*;

pub(super) type U32x8 = (uint32x4_t, uint32x4_t);
pub(super) type U64x4 = (uint64x2_t, uint64x2_t);

/// Derives the Poly1305 addition and polynomial keys.
#[target_feature(enable = "neon")]
pub(super) unsafe fn prepare_keys(key: &Key) -> (AdditionKey, PrecomputedMultiplier) {
    // Load the two 128-bit halves of the key.
    let key_lo = vreinterpretq_u32_u8(vld1q_u8(key.as_ptr()));
    let key_hi = vreinterpretq_u32_u8(vld1q_u8(key.as_ptr().add(16)));

    // Prepare addition key: interleave the four `u32` words of `k` with zeros to produce
    // `[0, k7, 0, k6]` and `[0, k5, 0, k4]` as a `uint64x2_t` pair.
    let zeros = vdupq_n_u32(0);
    let k_lo = vreinterpretq_u64_u32(vzip1q_u32(key_hi, zeros));
    let k_hi = vreinterpretq_u64_u32(vzip2q_u32(key_hi, zeros));
    let k = AdditionKey((k_lo, k_hi));

    // Prepare polynomial key R = k & 0xffffffc0ffffffc0ffffffc0fffffff:
    let r = Aligned130::new(vandq_u32(
        key_lo,
        vld1q_u32([0x0fffffff_u32, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc].as_ptr()),
    ));

    (k, PrecomputedMultiplier::new(r))
}

impl Aligned130 {
    /// Splits a 130-bit integer into five 26-bit limbs.
    #[target_feature(enable = "neon")]
    unsafe fn new(x: uint32x4_t) -> Self {
        let mask26 = vdupq_n_u32(0x3ffffff);
        let xl = unsafe { vshlq_u32(x, vld1q_s32([0, 6, 12, 18].as_ptr())) };
        let xh = vextq_u32(
            vshlq_u32(x, vld1q_s32([-26, -20, -14, -8].as_ptr())),
            vdupq_n_u32(0),
            1,
        );

        let limbs3 = vandq_u32(vorrq_u32(xl, xh), mask26);
        let limb4 = vshrq_n_u32(vextq_u32(vdupq_n_u32(0), x, 1), 24);
        Aligned130((limbs3, limb4))
    }
}

impl PrecomputedMultiplier {
    #[target_feature(enable = "neon")]
    unsafe fn new(r: Aligned130) -> Self {
        let r_lo = r.0.0;
        let r_hi = r.0.1;

        let r5_lo = vaddq_u32(r_lo, vshlq_n_u32(r_lo, 2));
        let r5_hi = vaddq_u32(r_hi, vshlq_n_u32(r_hi, 2));

        let a_hi = vld1q_u32(
            [
                vgetq_lane_u32(r_hi, 0),
                vgetq_lane_u32(r5_lo, 2),
                vgetq_lane_u32(r5_lo, 3),
                vgetq_lane_u32(r5_hi, 0),
            ]
            .as_ptr(),
        );

        let a_5 = vdupq_n_u32(vgetq_lane_u32(r5_lo, 1));

        PrecomputedMultiplier {
            a: (r_lo, a_hi),
            a_5: (a_5, a_5),
        }
    }
}
