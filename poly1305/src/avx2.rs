//! The Poly1305 universal hash function (AVX2 optimized).
//!
//! Adapted from: "Improved SIMD Implementation of Poly1305" which is based
//! on the SIMD Poly1305 developed by Shay Gueron and Martin Goll.
//! Copyright (c) 2019, Sreyosi Bhattacharyya, Palash Sarkar
//! <https://eprint.iacr.org/2019/842.pdf>

#![allow(non_camel_case_types, unused_parens, unused_variables, unused_assignments, non_snake_case)]

use super::Tag;
use core::{mem, ptr};
use universal_hash::{
    generic_array::{
        typenum::{U16, U32},
        GenericArray,
    },
    UniversalHash,
};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

type vec128 = __m128i;
type vec256 = __m256i;

#[derive(Copy, Clone)]
struct vec256x2 {
    v0: vec256,
    v1: vec256,
}

#[derive(Clone)]
struct vec256x3 {
    v0: vec256,
    v1: vec256,
    v2: vec256,
}

#[derive(Clone)]
struct vec256x5 {
    v0: vec256,
    v1: vec256,
    v2: vec256,
    v3: vec256,
    v4: vec256,
}

//enum Buffer {
//    B([u8; 64]),
//    V(vec256x2),
//    VA([vec128; 4]),
//}

/// Size of the internal buffer
const BUFFER_SIZE: usize = 64;

/// Internal buffer
type Buffer = [u8; 64];

/// The Poly1305 universal hash function (AVX2 optimized)
#[derive(Clone)]
pub struct Poly1305 {
    k: vec256,
    r1: vec256,
    r2: vec256,
    r4: vec256,
    r15: vec256,
    r25: vec256,
    r45: vec256,
    m: vec256x2,
    p: vec256x3,
    buffer: Buffer,
    p_init: u32,
    leftover: u32,
}

impl UniversalHash for Poly1305 {
    type KeySize = U32;
    type BlockSize = U16;

    /// Initialize Poly1305 with the given key
    fn new(key: &GenericArray<u8, U32>) -> Poly1305 {
        let mut state: Poly1305 = unsafe { mem::zeroed() };
        unsafe {
            init(&mut state, key);
        }
        state
    }

    /// Input data into the Poly1305 universal hash function
    fn update_block(&mut self, block: &GenericArray<u8, U16>) {
        self.update(block.as_slice());
    }

    /// Reset internal state
    fn reset(&mut self) {
        // TODO(tarcieri): call `init` again but without key
        unimplemented!();
    }

    /// Get the hashed output
    fn result(mut self) -> Tag {
        let mut tag = GenericArray::default();
        unsafe {
            finish(&mut self, tag.as_mut_slice());
        }
        Tag::new(tag)
    }
}

impl Poly1305 {
    /// Input data into the Poly1305 universal hash function
    pub fn update(&mut self, data: &[u8]) {
        unsafe { process(self, data); }
    }

    /// Process input messages in a chained manner
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }
}

#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn init(state: &mut Poly1305, key: &GenericArray<u8, U32>) {
    let k = _mm256_loadu_si256(key.as_ptr() as *const __m256i);
    state.k = _mm256_and_si256(
        (_mm256_permutevar8x32_epi32((k), (_mm256_set_epi32(3, 7, 2, 6, 1, 5, 0, 4)))),
        (_mm256_set_epi32(0, -1, 0, -1, 0, -1, 0, -1)),
    );

    let mut r1 = _mm256_and_si256(
        (_mm256_or_si256(
            (_mm256_sllv_epi32(
                (_mm256_and_si256(
                    (k),
                    (_mm256_set_epi32(0, 0, 0, 0, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc, 0x0fffffff)),
                )),
                (_mm256_set_epi32(32, 32, 32, 24, 18, 12, 6, 0)),
            )),
            (_mm256_permutevar8x32_epi32(
                (_mm256_srlv_epi32(
                    (_mm256_and_si256(
                        (k),
                        (_mm256_set_epi32(
                            0, 0, 0, 0, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc, 0x0fffffff,
                        )),
                    )),
                    (_mm256_set_epi32(32, 32, 32, 2, 8, 14, 20, 26)),
                )),
                (_mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7)),
            )),
        )),
        (_mm256_set_epi32(
            0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
        )),
    );
    let mut r15 = _mm256_permutevar8x32_epi32(
        (_mm256_add_epi32((r1), (_mm256_slli_epi32((r1), (2))))),
        (_mm256_set_epi32(4, 3, 2, 1, 1, 1, 1, 1)),
    );
    r1 = _mm256_blend_epi32((r1), (r15), (0xE0));
    r15 = _mm256_permute2x128_si256((r15), (r15), (0));

    let mut r2 = red5x64(mul130(r1, r1, r15));
    let mut r25 = _mm256_permutevar8x32_epi32(
        (_mm256_add_epi32((r2), (_mm256_slli_epi32((r2), (2))))),
        (_mm256_set_epi32(4, 3, 2, 1, 1, 1, 1, 1)),
    );
    r2 = _mm256_blend_epi32((r2), (r25), (0xE0));
    r25 = _mm256_permute2x128_si256((r25), (r25), (0));

    state.r1 = r1;
    state.r2 = r2;
    state.r15 = r15;
    state.r25 = r25;
    state.p_init = 0;
    state.leftover = 0;
}

#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn process(state: &mut Poly1305, input: &[u8]) {
    let mut in_len = input.len();
    let mut ip: *const u32 = input.as_ptr() as *const u32;
    let mut p: vec256x3;

    let r1 = state.r1;
    let r15 = state.r15;
    let r2 = state.r2;
    let r25 = state.r25;
    let r3 = red5x64(mul130(r2, r1, r15));
    let r4 = red5x64(mul130(r2, r2, r25));

    state.m.v0 = _mm256_blend_epi32(
        r3,
        _mm256_permutevar8x32_epi32(r2, _mm256_set_epi32(4, 3, 1, 0, 0, 0, 0, 0)),
        0xE0,
    );

    state.m.v1 = _mm256_blend_epi32(
        r4,
        _mm256_permutevar8x32_epi32(r2, _mm256_set_epi32(4, 2, 0, 0, 0, 0, 0, 0)),
        0xE0,
    );

    let r45 = _mm256_permutevar8x32_epi32(
        _mm256_add_epi32(r4, _mm256_slli_epi32(r4, 2)),
        _mm256_set_epi32(4, 3, 2, 1, 1, 1, 1, 1),
    );
    state.r4 = _mm256_blend_epi32(r4, r45, 0xE0);
    state.r45 = _mm256_permute2x128_si256(r45, r45, 0);
    p = align4x128(load4x128(ip));
    in_len -= 64;
    ip = ip.add(16);

    state.p_init = 1;

    if in_len >= 768 {
        let mut r8 = red5x64(mul130(state.r4, state.r4, state.r45));
        let mut r12 = red5x64(mul130(r8, state.r4, state.r45));
        let mut r85 = _mm256_permutevar8x32_epi32(
            (_mm256_add_epi32((r8), (_mm256_slli_epi32((r8), (2))))),
            (_mm256_set_epi32(4, 3, 2, 1, 1, 1, 1, 1)),
        );
        let mut r125 = _mm256_permutevar8x32_epi32(
            (_mm256_add_epi32((r12), (_mm256_slli_epi32((r12), (2))))),
            (_mm256_set_epi32(4, 3, 2, 1, 1, 1, 1, 1)),
        );
        r8 = _mm256_blend_epi32((r8), (r85), (0xE0));
        r12 = _mm256_blend_epi32((r12), (r125), (0xE0));
        r85 = _mm256_permute2x128_si256((r85), (r85), (0));
        r125 = _mm256_permute2x128_si256((r125), (r125), (0));

        loop {
            p = add4x130(
                red4x130(muladd4x130P(
                    muladd4x130P(mul4x130P(p, r12, r125), align4x128(load4x128(ip)), r8, r85),
                    align4x128(load4x128(ip.add(16))),
                    state.r4,
                    state.r45,
                )),
                align4x128(load4x128(ip.add(32))),
            );
            in_len -= 192;
            ip = ip.add(48);
            if in_len < 192 {
                break;
            }
        }

        if in_len >= 128 {
            p = add4x130(
                red4x130(muladd4x130P(
                    mul4x130P(p, r8, r85),
                    align4x128(load4x128(ip)),
                    state.r4,
                    state.r45,
                )),
                align4x128(load4x128(ip.add(16))),
            );
            in_len -= 128;
            ip = ip.add(32);
        } else if in_len >= 64 {
            p = add4x130(
                red4x130(mul4x130P(p, state.r4, state.r45)),
                align4x128(load4x128(ip)),
            );
            in_len -= 64;
            ip = ip.add(16);
        }
    } else if in_len >= 64 {
        loop {
            p = add4x130(
                red4x130(mul4x130R(p, state.r4, state.r45)),
                align4x128(load4x128(ip)),
            );
            in_len -= 64;
            ip = ip.add(16);
            if in_len < 64 {
                break;
            }
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn finish(state: &mut Poly1305, output: &mut [u8]) {
    let mut p_init: u32 = state.p_init;
    let mut p = _mm256_set_epi64x(0, 0, 0, 0);
    let mut buf_len = state.leftover;
    let mut idx = 0;

    if buf_len >= 32 {
        let c = vec256x2 {
            v0: _mm256_and_si256(
                _mm256_or_si256(
                    _mm256_sllv_epi32(
                        _mm256_or_si256(
                            _mm256_castsi128_si256(state.buffer.va()[0]),
                            _mm256_set_epi64x(0, 1, 0, 0),
                        ),
                        _mm256_set_epi32(32, 32, 32, 24, 18, 12, 6, 0),
                    ),
                    _mm256_permutevar8x32_epi32(
                        _mm256_srlv_epi32(
                            _mm256_or_si256(
                                _mm256_castsi128_si256(state.buffer.va()[0]),
                                _mm256_set_epi64x(0, 1, 0, 0),
                            ),
                            _mm256_set_epi32(32, 32, 32, 2, 8, 14, 20, 26),
                        ),
                        _mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7),
                    ),
                ),
                _mm256_set_epi32(
                    0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
                ),
            ),
            v1: _mm256_and_si256(
                _mm256_or_si256(
                    _mm256_sllv_epi32(
                        _mm256_or_si256(
                            _mm256_castsi128_si256(state.buffer.va()[1]),
                            _mm256_set_epi64x(0, 1, 0, 0),
                        ),
                        _mm256_set_epi32(32, 32, 32, 24, 18, 12, 6, 0),
                    ),
                    _mm256_permutevar8x32_epi32(
                        _mm256_srlv_epi32(
                            _mm256_or_si256(
                                _mm256_castsi128_si256(state.buffer.va()[1]),
                                _mm256_set_epi64x(0, 1, 0, 0),
                            ),
                            _mm256_set_epi32(32, 32, 32, 2, 8, 14, 20, 26),
                        ),
                        _mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7),
                    ),
                ),
                _mm256_set_epi32(
                    0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
                ),
            ),
        };

        let p = red5x64(mul2x130(c, state.r1, state.r2, state.r15, state.r25));
        idx += 2;
        buf_len -= 32;
        p_init += 1;
    }

    if buf_len >= 16 {
        let mut c: vec256 = _mm256_and_si256(
            _mm256_or_si256(
                _mm256_sllv_epi32(
                    _mm256_or_si256(
                        _mm256_castsi128_si256(state.buffer.va()[idx]),
                        _mm256_set_epi64x(0, 1, 0, 0),
                    ),
                    _mm256_set_epi32(32, 32, 32, 24, 18, 12, 6, 0),
                ),
                _mm256_permutevar8x32_epi32(
                    _mm256_srlv_epi32(
                        _mm256_or_si256(
                            _mm256_castsi128_si256(state.buffer.va()[idx]),
                            _mm256_set_epi64x(0, 1, 0, 0),
                        ),
                        _mm256_set_epi32(32, 32, 32, 2, 8, 14, 20, 26),
                    ),
                    _mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7),
                ),
            ),
            _mm256_set_epi32(
                0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
            ),
        );

        if p_init != 0 {
            c = _mm256_add_epi32(p, c);
        }

        let p = red5x64(mul130(c, state.r1, state.r15));
        idx += 1;
        buf_len -= 16;
        p_init += 1;
    }

    if buf_len != 0 {
        state.buffer.b()[state.leftover as usize] = 1;
        if buf_len < 15 {
            memzero15(
                state
                    .buffer
                    .b()
                    .as_mut_ptr()
                    .add(state.leftover.checked_add(1).unwrap() as usize),
                15 - buf_len as usize,
            );
        }

        let mut c = _mm256_and_si256(
            _mm256_or_si256(
                _mm256_sllv_epi32(
                    _mm256_castsi128_si256(state.buffer.va()[idx]),
                    _mm256_set_epi32(32, 32, 32, 24, 18, 12, 6, 0),
                ),
                _mm256_permutevar8x32_epi32(
                    _mm256_srlv_epi32(
                        _mm256_castsi128_si256(state.buffer.va()[idx]),
                        _mm256_set_epi32(32, 32, 32, 2, 8, 14, 20, 26),
                    ),
                    _mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7),
                ),
            ),
            _mm256_set_epi32(
                0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
            ),
        );

        if p_init != 0 {
            c = _mm256_add_epi32(p, c);
        }

        p = red5x64(mul130(c, state.r1, state.r15));
        p_init += 1;
    }

    if p_init != 0 {
        _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, addkey(p, state.k));
    } else {
        _mm_storeu_si128(
            output.as_mut_ptr() as *mut __m128i,
            _mm256_castsi256_si128(_mm256_permutevar8x32_epi32(
                state.k,
                _mm256_set_epi32(0, 0, 0, 0, 6, 4, 2, 0),
            )),
        );
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn addkey(mut x: vec256, k: vec256) -> vec128 {
    let t = _mm256_permutevar8x32_epi32(
        (_mm256_srli_epi32((x), (26))),
        (_mm256_set_epi32(7, 7, 7, 3, 2, 1, 0, 4)),
    );
    x = _mm256_add_epi32(
        (_mm256_add_epi32(
            (_mm256_and_si256(
                (x),
                (_mm256_set_epi32(
                    0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
                )),
            )),
            (t),
        )),
        (_mm256_permutevar8x32_epi32(
            (_mm256_slli_epi32((t), (2))),
            (_mm256_set_epi32(7, 7, 7, 7, 7, 7, 7, 0)),
        )),
    );
    x = _mm256_or_si256(
        (_mm256_srlv_epi32((x), (_mm256_set_epi32(32, 32, 32, 32, 18, 12, 6, 0)))),
        (_mm256_permutevar8x32_epi32(
            (_mm256_sllv_epi32((x), (_mm256_set_epi32(32, 32, 32, 8, 14, 20, 26, 32)))),
            (_mm256_set_epi32(7, 7, 7, 7, 4, 3, 2, 1)),
        )),
    );
    x = _mm256_add_epi64(
        (_mm256_permutevar8x32_epi32((x), (_mm256_set_epi32(7, 3, 7, 2, 7, 1, 7, 0)))),
        (k),
    );
    x = _mm256_add_epi64(
        (_mm256_permutevar8x32_epi32((x), (_mm256_set_epi32(7, 7, 7, 7, 6, 4, 2, 0)))),
        (_mm256_permutevar8x32_epi32(
            (_mm256_srli_epi64((x), (32))),
            (_mm256_set_epi32(7, 7, 7, 7, 4, 2, 0, 7)),
        )),
    );
    _mm256_castsi256_si128((x))
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul2x130(x: vec256x2, r1: vec256, r2: vec256, r15: vec256, r25: vec256) -> vec256x2 {
    let mut ret: vec256x2 = mem::zeroed();
    ret.v0 = _mm256_mul_epu32(
        (_mm256_permutevar8x32_epi32((x.v0), (_mm256_set_epi64x(4, 3, 2, 1)))),
        (_mm256_permutevar8x32_epi32((r2), (_mm256_set_epi64x(7, 7, 7, 7)))),
    );
    ret.v1 = _mm256_mul_epu32(
        (_mm256_permutevar8x32_epi32((x.v1), (_mm256_set_epi64x(4, 3, 2, 1)))),
        (_mm256_permutevar8x32_epi32((r1), (_mm256_set_epi64x(7, 7, 7, 7)))),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permute4x64_epi64((x.v0), (((0) << 6) | ((2) << 4) | ((2) << 2) | (1)))),
            (_mm256_permutevar8x32_epi32((r2), (_mm256_set_epi64x(3, 6, 5, 6)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (_mm256_permute4x64_epi64((x.v1), (((0) << 6) | ((2) << 4) | ((2) << 2) | (1)))),
            (_mm256_permutevar8x32_epi32((r1), (_mm256_set_epi64x(3, 6, 5, 6)))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permutevar8x32_epi32((x.v0), (_mm256_set_epi64x(1, 1, 3, 3)))),
            (_mm256_permutevar8x32_epi32((r2), (_mm256_set_epi64x(2, 1, 6, 5)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (_mm256_permutevar8x32_epi32((x.v1), (_mm256_set_epi64x(1, 1, 3, 3)))),
            (_mm256_permutevar8x32_epi32((r1), (_mm256_set_epi64x(2, 1, 6, 5)))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permutevar8x32_epi32((x.v0), (_mm256_set_epi64x(3, 2, 1, 0)))),
            (_mm256_broadcastd_epi32((_mm256_castsi256_si128((r2))))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (_mm256_permutevar8x32_epi32((x.v1), (_mm256_set_epi64x(3, 2, 1, 0)))),
            (_mm256_broadcastd_epi32((_mm256_castsi256_si128((r1))))),
        )),
    );

    let mut t0 = _mm256_permute4x64_epi64((x.v0), (((1) << 6) | ((0) << 4) | ((0) << 2) | (2)));
    let mut t1 = _mm256_permute4x64_epi64((x.v1), (((1) << 6) | ((0) << 4) | ((0) << 2) | (2)));

    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (t0),
            (_mm256_blend_epi32(
                (_mm256_permutevar8x32_epi32((r2), (_mm256_set_epi64x(1, 2, 1, 1)))),
                (r25),
                (0x03),
            )),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (t1),
            (_mm256_blend_epi32(
                (_mm256_permutevar8x32_epi32((r1), (_mm256_set_epi64x(1, 2, 1, 1)))),
                (r15),
                (0x03),
            )),
        )),
    );
    ret.v0 = _mm256_add_epi64((ret.v0), (ret.v1));
    t0 = _mm256_mul_epu32((t0), (r2));
    t1 = _mm256_mul_epu32((t1), (r1));
    ret.v1 = _mm256_add_epi64((t0), (t1));
    t0 = _mm256_mul_epu32(
        (_mm256_permutevar8x32_epi32((x.v0), (_mm256_set_epi64x(3, 2, 1, 0)))),
        (_mm256_permutevar8x32_epi32((r2), (_mm256_set_epi64x(1, 2, 3, 4)))),
    );
    t1 = _mm256_mul_epu32(
        (_mm256_permutevar8x32_epi32((x.v1), (_mm256_set_epi64x(3, 2, 1, 0)))),
        (_mm256_permutevar8x32_epi32((r1), (_mm256_set_epi64x(1, 2, 3, 4)))),
    );
    t0 = _mm256_add_epi64((t0), (t1));
    t0 = _mm256_add_epi64(
        (t0),
        (_mm256_permute4x64_epi64((t0), (((1) << 6) | ((0) << 4) | ((3) << 2) | (2)))),
    );
    t0 = _mm256_add_epi64(
        (t0),
        (_mm256_permute4x64_epi64((t0), (((2) << 6) | ((3) << 4) | ((0) << 2) | (1)))),
    );
    ret.v1 = _mm256_add_epi64((ret.v1), (t0));
    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn red5x64(mut x: vec256x2) -> vec256 {
    x.v0 = _mm256_add_epi64(
        (_mm256_and_si256(
            (x.v0),
            (_mm256_set_epi64x(-1, 0x3ffffff, 0x3ffffff, 0x3ffffff)),
        )),
        (_mm256_permute4x64_epi64(
            (_mm256_srlv_epi64((x.v0), (_mm256_set_epi64x(64, 26, 26, 26)))),
            (((2) << 6) | ((1) << 4) | ((0) << 2) | (3)),
        )),
    );
    x.v1 = _mm256_add_epi64(
        (x.v1),
        (_mm256_permute4x64_epi64(
            (_mm256_srli_epi64((x.v0), (26))),
            (((2) << 6) | ((1) << 4) | ((0) << 2) | (3)),
        )),
    );
    x.v0 = _mm256_and_si256((x.v0), (_mm256_set_epi64x(0x3ffffff, -1, -1, -1)));

    let t = _mm256_srlv_epi64((x.v1), (_mm256_set_epi64x(64, 64, 64, 26)));
    x.v0 = _mm256_add_epi64(
        (_mm256_add_epi64((x.v0), (t))),
        (_mm256_slli_epi32((t), (2))),
    );
    x.v1 = _mm256_and_si256((x.v1), (_mm256_set_epi64x(0, 0, 0, 0x3ffffff)));
    x.v0 = _mm256_add_epi64(
        (_mm256_and_si256(
            (x.v0),
            (_mm256_set_epi64x(-1, 0x3ffffff, 0x3ffffff, 0x3ffffff)),
        )),
        (_mm256_permute4x64_epi64(
            (_mm256_srlv_epi64((x.v0), (_mm256_set_epi64x(64, 26, 26, 26)))),
            (((2) << 6) | ((1) << 4) | ((0) << 2) | (3)),
        )),
    );
    x.v1 = _mm256_add_epi64(
        (x.v1),
        (_mm256_permute4x64_epi64(
            (_mm256_srli_epi64((x.v0), (26))),
            (((2) << 6) | ((1) << 4) | ((0) << 2) | (3)),
        )),
    );
    x.v0 = _mm256_and_si256((x.v0), (_mm256_set_epi64x(0x3ffffff, -1, -1, -1)));

    _mm256_blend_epi32(
        (_mm256_permutevar8x32_epi32((x.v0), (_mm256_set_epi32(0, 6, 4, 0, 6, 4, 2, 0)))),
        (_mm256_permutevar8x32_epi32((x.v1), (_mm256_set_epi32(0, 6, 4, 0, 6, 4, 2, 0)))),
        (0x90),
    )
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul130(x: vec256, y: vec256, z: vec256) -> vec256x2 {
    let mut ret: vec256x2 = mem::zeroed();

    ret.v0 = _mm256_mul_epu32(
        (_mm256_permutevar8x32_epi32((x), (_mm256_set_epi64x(4, 3, 2, 1)))),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permutevar8x32_epi32((x), (_mm256_set_epi64x(3, 2, 1, 0)))),
            (_mm256_broadcastd_epi32((_mm256_castsi256_si128((y))))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permutevar8x32_epi32((x), (_mm256_set_epi64x(1, 1, 3, 3)))),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 1, 6, 5)))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permute4x64_epi64((x), (((1) << 6) | ((0) << 4) | ((0) << 2) | (2)))),
            (_mm256_blend_epi32(
                (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 2, 1, 1)))),
                (z),
                (0x03),
            )),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (_mm256_permute4x64_epi64((x), (((0) << 6) | ((2) << 4) | ((2) << 2) | (1)))),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(3, 6, 5, 6)))),
        )),
    );

    ret.v1 = _mm256_mul_epu32(
        (_mm256_permutevar8x32_epi32((x), (_mm256_set_epi64x(3, 2, 1, 0)))),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 2, 3, 4)))),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_permute4x64_epi64((ret.v1), (((1) << 6) | ((0) << 4) | ((3) << 2) | (2)))),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_permute4x64_epi64((ret.v1), (((0) << 6) | ((0) << 4) | ((0) << 2) | (1)))),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (_mm256_permute4x64_epi64((x), (((0) << 6) | ((0) << 4) | ((0) << 2) | (2)))),
            (y),
        )),
    );

    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn align4x128(mut x: vec256x2) -> vec256x3 {
    let msk: vec256 = _mm256_setr_epi32(
        0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
    );
    let pad: vec256 = _mm256_setr_epi32(
        1 << 24,
        1 << 24,
        1 << 24,
        1 << 24,
        1 << 24,
        1 << 24,
        1 << 24,
        1 << 24,
    );

    let mut ret: vec256x3 = mem::zeroed();
    ret.v0 = _mm256_permute4x64_epi64(
        (_mm256_unpackhi_epi64((x.v0), (x.v1))),
        (((3) << 6) | ((1) << 4) | ((2) << 2) | (0)),
    );
    x.v0 = _mm256_permute4x64_epi64(
        (_mm256_unpacklo_epi64((x.v0), (x.v1))),
        (((3) << 6) | ((1) << 4) | ((2) << 2) | (0)),
    );
    ret.v2 = _mm256_or_si256((_mm256_srli_epi64((ret.v0), (40))), (pad));
    x.v1 = _mm256_or_si256(
        (_mm256_srli_epi64((x.v0), (46))),
        (_mm256_slli_epi64((ret.v0), (18))),
    );
    ret.v1 = _mm256_and_si256(
        (_mm256_blend_epi32((_mm256_srli_epi64((x.v0), (26))), (x.v1), (0xAA))),
        (msk),
    );
    ret.v0 = _mm256_and_si256(
        (_mm256_blend_epi32((x.v0), (_mm256_slli_epi64((x.v1), (26))), (0xAA))),
        (msk),
    );
    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn load4x128(ip: *const u32) -> vec256x2 {
    vec256x2 {
        v0: _mm256_loadu_si256(ip as *const __m256i),
        v1: _mm256_loadu_si256(ip.add(8) as *const __m256i),
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn add4x130(x: vec256x3, y: vec256x3) -> vec256x3 {
    vec256x3 {
        v0: _mm256_add_epi32((x.v0), (y.v0)),
        v1: _mm256_add_epi32((x.v1), (y.v1)),
        v2: _mm256_add_epi32((x.v2), (y.v2)),
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn hadd4x130(x: vec256x5) -> vec256x2 {
    let mut ret: vec256x2 = mem::zeroed();
    ret.v0 = _mm256_add_epi64(
        (_mm256_unpackhi_epi64((x.v0), (x.v1))),
        (_mm256_unpacklo_epi64((x.v0), (x.v1))),
    );
    ret.v1 = _mm256_add_epi64(
        (_mm256_unpackhi_epi64((x.v2), (x.v3))),
        (_mm256_unpacklo_epi64((x.v2), (x.v3))),
    );
    ret.v0 = _mm256_add_epi64(
        (_mm256_inserti128_si256((ret.v0), (_mm256_castsi256_si128((ret.v1))), (1))),
        (_mm256_inserti128_si256((ret.v1), (_mm256_extractf128_si256((ret.v0), (1))), (0))),
    );
    ret.v1 = _mm256_add_epi64(
        (x.v4),
        (_mm256_permute4x64_epi64((x.v4), (((1) << 6) | ((0) << 4) | ((3) << 2) | (2)))),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_permute4x64_epi64((ret.v1), (((0) << 6) | ((0) << 4) | ((0) << 2) | (1)))),
    );
    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn red4x130(mut x: vec256x5) -> vec256x3 {
    let msk: vec256 = _mm256_setr_epi32(0x3ffffff, 0, 0x3ffffff, 0, 0x3ffffff, 0, 0x3ffffff, 0);

    x.v1 = _mm256_add_epi64((x.v1), (_mm256_srli_epi64((x.v0), (26))));
    x.v0 = _mm256_and_si256((x.v0), (msk));
    x.v4 = _mm256_add_epi64((x.v4), (_mm256_srli_epi64((x.v3), (26))));
    x.v3 = _mm256_and_si256((x.v3), (msk));
    x.v2 = _mm256_add_epi64((x.v2), (_mm256_srli_epi64((x.v1), (26))));
    x.v1 = _mm256_and_si256((x.v1), (msk));
    x.v0 = _mm256_add_epi64(
        (x.v0),
        (_mm256_mul_epu32(
            (_mm256_srli_epi64((x.v4), (26))),
            _mm256_setr_epi32(5, 0, 5, 0, 5, 0, 5, 0),
        )),
    );
    x.v4 = _mm256_and_si256((x.v4), (msk));
    x.v3 = _mm256_add_epi64((x.v3), (_mm256_srli_epi64((x.v2), (26))));
    x.v2 = _mm256_and_si256((x.v2), (msk));
    x.v1 = _mm256_add_epi64((x.v1), (_mm256_srli_epi64((x.v0), (26))));
    x.v0 = _mm256_and_si256((x.v0), (msk));
    x.v4 = _mm256_add_epi64((x.v4), (_mm256_srli_epi64((x.v3), (26))));
    x.v3 = _mm256_and_si256((x.v3), (msk));
    x.v0 = _mm256_blend_epi32((x.v0), (_mm256_slli_epi64((x.v2), (32))), (0xAA));
    x.v1 = _mm256_blend_epi32((x.v1), (_mm256_slli_epi64((x.v3), (32))), (0xAA));

    vec256x3 {
        v0: x.v0,
        v1: x.v1,
        v2: x.v4,
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul4x130M(mut x: vec256x3, mut m: vec256x2, r1: vec256) -> vec256x5 {
    let mut ret: vec256x5 = mem::zeroed();

    ret.v0 = _mm256_unpacklo_epi32((m.v0), (m.v1));
    ret.v1 = _mm256_unpackhi_epi32((m.v0), (m.v1));

    let mut t: vec256x3 = mem::zeroed();

    let mut ord = _mm256_set_epi32(1, 0, 6, 7, 2, 0, 3, 1);
    t.v0 = _mm256_blend_epi32(
        (_mm256_permutevar8x32_epi32((r1), (ord))),
        (_mm256_permutevar8x32_epi32((ret.v0), (ord))),
        (0x3F),
    );

    ord = _mm256_set_epi32(3, 2, 4, 5, 2, 0, 3, 1);
    t.v1 = _mm256_blend_epi32(
        (_mm256_permutevar8x32_epi32((r1), (ord))),
        (_mm256_permutevar8x32_epi32((ret.v1), (ord))),
        (0x3F),
    );

    ord = _mm256_set_epi32(1, 4, 6, 6, 2, 4, 3, 5);
    t.v2 = _mm256_blend_epi32(
        (_mm256_blend_epi32(
            (_mm256_permutevar8x32_epi32((r1), (ord))),
            (_mm256_permutevar8x32_epi32((ret.v1), (ord))),
            (0x10),
        )),
        (_mm256_permutevar8x32_epi32((ret.v0), (ord))),
        (0x2F),
    );
    ret.v0 = _mm256_mul_epu32((x.v0), (t.v0));
    ret.v1 = _mm256_mul_epu32((x.v1), (t.v0));
    ret.v2 = _mm256_mul_epu32((x.v0), (t.v1));
    ret.v3 = _mm256_mul_epu32((x.v1), (t.v1));
    ret.v4 = _mm256_mul_epu32((x.v0), (t.v2));
    ord = _mm256_set_epi32(6, 7, 4, 5, 2, 3, 0, 1);
    m.v0 = _mm256_permutevar8x32_epi32((t.v0), (ord));
    m.v1 = _mm256_permutevar8x32_epi32((t.v1), (ord));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v2), (t.v0))));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v1), (m.v1))));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v0), (m.v0))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v0), (m.v1))));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v1), (m.v0))));
    x.v0 = _mm256_permutevar8x32_epi32((x.v0), (ord));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v0), (t.v0))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v0), (m.v0))));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v0), (t.v1))));
    t.v1 = _mm256_add_epi32((t.v2), (_mm256_slli_epi32((t.v2), (2))));
    m.v1 = _mm256_add_epi32((m.v1), (_mm256_slli_epi32((m.v1), (2))));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v0), (m.v1))));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v1), (t.v1))));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v0), (t.v1))));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v2), (m.v1))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v2), (t.v1))));
    x.v1 = _mm256_permutevar8x32_epi32((x.v1), (ord));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v1), (m.v1))));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v1), (t.v1))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v1), (t.v0))));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v1), (m.v0))));
    m.v1 = _mm256_permutevar8x32_epi32((m.v1), (ord));
    t.v1 = _mm256_permutevar8x32_epi32((t.v1), (ord));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v1), (m.v1))));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v2), (t.v1))));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v2), (m.v1))));

    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul4x130R(mut x: vec256x3, y: vec256, z: vec256) -> vec256x5 {
    let mut ret: vec256x5 = mem::zeroed();
    let ord = _mm256_set_epi32(6, 7, 4, 5, 2, 3, 0, 1);
    let mut t0 = _mm256_permute4x64_epi64((y), (((0) << 6) | ((0) << 4) | ((0) << 2) | (0)));
    let mut t1 = _mm256_permute4x64_epi64((y), (((1) << 6) | ((1) << 4) | ((1) << 2) | (1)));
    ret.v0 = _mm256_mul_epu32((x.v0), (t0));
    ret.v1 = _mm256_mul_epu32((x.v1), (t0));
    ret.v4 = _mm256_mul_epu32((x.v2), (t0));
    ret.v2 = _mm256_mul_epu32((x.v0), (t1));
    ret.v3 = _mm256_mul_epu32((x.v1), (t1));
    t0 = _mm256_permutevar8x32_epi32((t0), (ord));
    t1 = _mm256_permutevar8x32_epi32((t1), (ord));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v0), (t0))));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v1), (t0))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v0), (t1))));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v1), (t1))));
    let mut t2 = _mm256_permute4x64_epi64((y), (((2) << 6) | ((2) << 4) | ((2) << 2) | (2)));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v0), (t2))));
    x.v0 = _mm256_permutevar8x32_epi32((x.v0), (ord));
    x.v1 = _mm256_permutevar8x32_epi32((x.v1), (ord));
    t2 = _mm256_permutevar8x32_epi32((t2), (ord));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v1), (t2))));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v2), (t2))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v0), (t0))));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v1), (t0))));
    t0 = _mm256_permutevar8x32_epi32((t0), (ord));
    t1 = _mm256_permutevar8x32_epi32((t1), (ord));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v0), (t0))));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v1), (t0))));
    ret.v4 = _mm256_add_epi64((ret.v4), (_mm256_mul_epu32((x.v0), (t1))));
    t0 = _mm256_permute4x64_epi64((y), (((3) << 6) | ((3) << 4) | ((3) << 2) | (3)));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v0), (t0))));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v1), (t0))));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v2), (t0))));
    t0 = _mm256_permutevar8x32_epi32((t0), (ord));
    ret.v3 = _mm256_add_epi64((ret.v3), (_mm256_mul_epu32((x.v2), (t0))));
    ret.v1 = _mm256_add_epi64((ret.v1), (_mm256_mul_epu32((x.v0), (t0))));
    ret.v2 = _mm256_add_epi64((ret.v2), (_mm256_mul_epu32((x.v1), (t0))));
    x.v1 = _mm256_permutevar8x32_epi32((x.v1), (ord));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v1), (t0))));
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v2), (z))));
    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul4x130P(mut x: vec256x3, y: vec256, z: vec256) -> vec256x5 {
    let mut ret: vec256x5 = mem::zeroed();
    let ord = _mm256_set_epi32(6, 7, 4, 5, 2, 3, 0, 1);
    ret.v0 = _mm256_mul_epu32(
        (x.v0),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
    );
    ret.v1 = _mm256_mul_epu32(
        (x.v0),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
    );
    ret.v2 = _mm256_mul_epu32(
        (x.v0),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 2, 2, 2)))),
    );
    ret.v3 = _mm256_mul_epu32(
        (x.v0),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(3, 3, 3, 3)))),
    );
    ret.v4 = _mm256_mul_epu32(
        (x.v0),
        (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(4, 4, 4, 4)))),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 2, 2, 2)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(3, 3, 3, 3)))),
        )),
    );
    x.v0 = _mm256_permutevar8x32_epi32((x.v0), (ord));
    x.v1 = _mm256_permutevar8x32_epi32((x.v1), (ord));
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(6, 6, 6, 6)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 2, 2, 2)))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(5, 5, 5, 5)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(6, 6, 6, 6)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v2), (z))));
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(5, 5, 5, 5)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(6, 6, 6, 6)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    return ret;
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn muladd4x130P(mut ret: vec256x5, mut x: vec256x3, y: vec256, z: vec256) -> vec256x5 {
    let ord = _mm256_set_epi32(6, 7, 4, 5, 2, 3, 0, 1);
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 2, 2, 2)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(3, 3, 3, 3)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(4, 4, 4, 4)))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 2, 2, 2)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(3, 3, 3, 3)))),
        )),
    );
    x.v0 = _mm256_permutevar8x32_epi32((x.v0), (ord));
    x.v1 = _mm256_permutevar8x32_epi32((x.v1), (ord));
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(6, 6, 6, 6)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v0),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(2, 2, 2, 2)))),
        )),
    );
    ret.v0 = _mm256_add_epi64(
        (ret.v0),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(5, 5, 5, 5)))),
        )),
    );
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(6, 6, 6, 6)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v1),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(1, 1, 1, 1)))),
        )),
    );
    ret.v0 = _mm256_add_epi64((ret.v0), (_mm256_mul_epu32((x.v2), (z))));
    ret.v1 = _mm256_add_epi64(
        (ret.v1),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(5, 5, 5, 5)))),
        )),
    );
    ret.v2 = _mm256_add_epi64(
        (ret.v2),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(6, 6, 6, 6)))),
        )),
    );
    ret.v3 = _mm256_add_epi64(
        (ret.v3),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(7, 7, 7, 7)))),
        )),
    );
    ret.v4 = _mm256_add_epi64(
        (ret.v4),
        (_mm256_mul_epu32(
            (x.v2),
            (_mm256_permutevar8x32_epi32((y), (_mm256_set_epi64x(0, 0, 0, 0)))),
        )),
    );
    ret
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn memcpy63(dst: *mut u8, src: *const u8, count: usize) {
    ptr::copy(src, dst, count);
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn memzero15(dst: *mut u8, count: usize) {
    ptr::write_bytes(dst, 0, count);
}
