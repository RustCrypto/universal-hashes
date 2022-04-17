//! **GHASH**: universal hash over GF(2^128) used by AES-GCM for message
//! authentication (i.e. GMAC).
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

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/ghash/0.4.3"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use polyval::universal_hash;

use polyval::Polyval;
use universal_hash::{
    consts::U16,
    crypto_common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
    KeyInit, UhfBackend, UniversalHash,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// GHASH keys (16-bytes)
pub type Key = universal_hash::Key<GHash>;

/// GHASH blocks (16-bytes)
pub type Block = universal_hash::Block<GHash>;

/// GHASH tags (16-bytes)
pub type Tag = universal_hash::Block<GHash>;

/// **GHASH**: universal hash over GF(2^128) used by AES-GCM.
///
/// GHASH is a universal hash function used for message authentication in
/// the AES-GCM authenticated encryption cipher.
#[derive(Clone)]
pub struct GHash(Polyval);

impl KeySizeUser for GHash {
    type KeySize = U16;
}

impl KeyInit for GHash {
    /// Initialize GHASH with the given `H` field element
    #[inline]
    fn new(h: &Key) -> Self {
        let mut h = *h;
        h.reverse();

        #[allow(unused_mut)]
        let mut h_polyval = polyval::mulx(&h);

        #[cfg(feature = "zeroize")]
        h.zeroize();

        #[allow(clippy::let_and_return)]
        let result = GHash(Polyval::new(&h_polyval));

        #[cfg(feature = "zeroize")]
        h_polyval.zeroize();

        result
    }
}

impl BlockSizeUser for GHash {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for GHash {
    type ParBlocksSize = U16;
}

impl UhfBackend for GHash {
    fn proc_block(&mut self, x: &Block) {
        let mut x = *x;
        x.reverse();
        self.0.proc_block(&x);
    }
}

impl UniversalHash for GHash {
    fn update_with_backend(
        &mut self,
        f: impl universal_hash::UhfClosure<BlockSize = Self::BlockSize>,
    ) {
        f.call(self);
    }

    /// Get GHASH output
    #[inline]
    fn finalize(self) -> Tag {
        let mut output = self.0.finalize();
        output.reverse();
        output.into()
    }
}

opaque_debug::implement!(GHash);
