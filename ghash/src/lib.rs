//! **GHASH**: universal hash over GF(2^128) used by AES-GCM.
//!
//! ## Implementation Notes
//!
//! The implementation of GHASH found in this crate internally uses the
//! [`polyval`] crate, which provides a similar universal hash function used by
//! AES-GCM-SIV (RFC 8452).
//!
//! By implementing GHASH in terms of POLYVAL, the two universal hash functions
//! can share a common core, meaning any optimization work (e.g. CPU-specific
//! SIMD implementations) which happens upstream in the `polyval` crate
//! benefits GHASH as well.
//!
//! From RFC 8452 Appendix A:
//! <https://tools.ietf.org/html/rfc8452#appendix-A>
//!
//! > GHASH and POLYVAL both operate in GF(2^128), although with different
//! > irreducible polynomials: POLYVAL works modulo x^128 + x^127 + x^126 +
//! > x^121 + 1 and GHASH works modulo x^128 + x^7 + x^2 + x + 1.  Note
//! > that these irreducible polynomials are the "reverse" of each other.
//!
//! [`polyval`]: https://github.com/RustCrypto/universal-hashes/tree/master/polyval
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub use universal_hash;
use universal_hash::{consts::U16, NewUniversalHash, UniversalHash};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use core::arch::x86_64::*;

/// GHASH keys (16-bytes)
pub type Key = universal_hash::Key<GHash>;

/// GHASH blocks (16-bytes)
pub type Block = universal_hash::Block<GHash>;

/// GHASH tags (16-bytes)
pub type Tag = universal_hash::Output<GHash>;

/// **GHASH**: universal hash over GF(2^128) used by AES-GCM.
///
/// GHASH is a universal hash function used for message authentication in
/// the AES-GCM authenticated encryption cipher.
#[derive(Clone)]
#[repr(align(16))]
pub struct GHash {
    h: __m128i,
    y: __m128i,
}

const BS_MASK1: i64 = 0x00010203_04050607;
const BS_MASK2: i64 = 0x08090A0B_0C0D0E0F;

impl NewUniversalHash for GHash {
    type KeySize = U16;

    /// Initialize GHASH with the given `H` field element
    fn new(h: &Key) -> Self {
        unsafe {
            let bs_mask = _mm_set_epi64x(BS_MASK1, BS_MASK2);
            let h = _mm_loadu_si128(h.as_ptr() as *const _);
            let h = _mm_shuffle_epi8(h, bs_mask);
            let y = _mm_setzero_si128();
            Self { h, y }
        }
    }
}

impl UniversalHash for GHash {
    type BlockSize = U16;

    #[inline]
    fn update(&mut self, x: &Block) {
        unsafe {
            let bs_mask = _mm_set_epi64x(BS_MASK1, BS_MASK2);

            let h = self.h;
            let x = _mm_loadu_si128(x.as_ptr() as *const _);
            let x = _mm_shuffle_epi8(x, bs_mask);
            let y = _mm_xor_si128(self.y, x);

            let h0 = h;
            let h1 = _mm_shuffle_epi32(h, 0x0E);
            let h2 = _mm_xor_si128(h0, h1);
            let y0 = y;
            let y1 = _mm_shuffle_epi32(y, 0x0E);
            let y2 = _mm_xor_si128(y0, y1);
            let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
            let t1 = _mm_clmulepi64_si128(y, h, 0x11);
            let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
            let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
            let v0 = t0;
            let v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
            let v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
            let v3 = _mm_shuffle_epi32(t1, 0x0E);

            let v3 = _mm_or_si128(_mm_slli_epi64(v3, 1), _mm_srli_epi64(v2, 63));
            let v2 = _mm_or_si128(_mm_slli_epi64(v2, 1), _mm_srli_epi64(v1, 63));
            let v1 = _mm_or_si128(_mm_slli_epi64(v1, 1), _mm_srli_epi64(v0, 63));
            let v0 = _mm_slli_epi64(v0, 1);

            let v2 = _mm_xor_si128(
                v2,
                _mm_xor_si128(
                    _mm_xor_si128(v0, _mm_srli_epi64(v0, 1)),
                    _mm_xor_si128(_mm_srli_epi64(v0, 2), _mm_srli_epi64(v0, 7)),
                ),
            );
            let v1 = _mm_xor_si128(
                _mm_xor_si128(v1, _mm_slli_epi64(v0, 63)),
                _mm_xor_si128(_mm_slli_epi64(v0, 62), _mm_slli_epi64(v0, 57)),
            );
            let v3 = _mm_xor_si128(
                v3,
                _mm_xor_si128(
                    _mm_xor_si128(v1, _mm_srli_epi64(v1, 1)),
                    _mm_xor_si128(_mm_srli_epi64(v1, 2), _mm_srli_epi64(v1, 7)),
                ),
            );
            let v2 = _mm_xor_si128(
                _mm_xor_si128(v2, _mm_slli_epi64(v1, 63)),
                _mm_xor_si128(_mm_slli_epi64(v1, 62), _mm_slli_epi64(v1, 57)),
            );

            self.y = _mm_unpacklo_epi64(v2, v3);
        }
    }

    /// Reset internal state
    fn reset(&mut self) {
        unsafe {
            self.y = _mm_setzero_si128();
        }
    }

    /// Get GHASH output
    fn finalize(self) -> Tag {
        unsafe {
            let bs_mask = _mm_set_epi64x(BS_MASK1, BS_MASK2);
            core::mem::transmute(_mm_shuffle_epi8(self.y, bs_mask))
        }
    }
}

