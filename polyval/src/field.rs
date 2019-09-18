//! Implementation of POLYVAL's finite field.
//!
//! From [RFC 8452 Section 3] which defines POLYVAL for use in AES-GCM_SIV:
//!
//! > "POLYVAL, like GHASH (the authenticator in AES-GCM; ...), operates in a
//! > binary field of size 2^128.  The field is defined by the irreducible
//! > polynomial x^128 + x^127 + x^126 + x^121 + 1."
//!
//! This implementation provides multiplication over GF(2^128) optimized using
//! Shay Gueron's PCLMULQDQ-based techniques.
//!
//! For more information on how these techniques work, see:
//! <https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html>
//!
//! [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod pclmulqdq;
mod soft;

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
use self::pclmulqdq::M128i;
use self::soft::U64x2;

/// Size of GF(2^128) in bytes (16-bytes).
pub const FIELD_SIZE: usize = 16;

/// POLYVAL field element bytestrings (16-bytes)
pub type Block = [u8; FIELD_SIZE];

/// POLYVAL field element.
#[derive(Copy, Clone)]
pub enum Element {
    #[cfg(all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    /// (P)CLMUL(QDQ)-accelerated backend on supported x86 architectures
    Clmul(M128i),

    /// Portable software fallback
    Soft(U64x2),
}

impl Element {
    /// Load a `FieldElement` from its bytestring representation.
    #[cfg(all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    pub fn from_bytes(bytes: Block) -> Self {
        if cfg!(feature = "std") {
            if is_x86_feature_detected!("pclmulqdq") {
                Element::Clmul(bytes.into())
            } else {
                Element::Soft(bytes.into())
            }
        } else {
            Element::Clmul(bytes.into())
        }
    }

    /// Load a `FieldElement` from its bytestring representation.
    #[cfg(not(all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    )))]
    pub fn from_bytes(bytes: Block) -> Self {
        Element::Soft(bytes.into())
    }

    /// Serialize this `FieldElement` as a bytestring.
    pub fn to_bytes(self) -> Block {
        match self {
            #[cfg(all(
                target_feature = "pclmulqdq",
                target_feature = "sse2",
                target_feature = "sse4.1",
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            Element::Clmul(m128i) => m128i.into(),
            Element::Soft(u64x2) => u64x2.into(),
        }
    }

    /// Adds two POLYVAL field elements.
    ///
    /// From [RFC 8452 Section 3]:
    ///
    /// > "The sum of any two elements in the field is the result of XORing them."
    ///
    /// [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Block) -> Self {
        match self {
            #[cfg(all(
                target_feature = "pclmulqdq",
                target_feature = "sse2",
                target_feature = "sse4.1",
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            Element::Clmul(m128i) => Element::Clmul(m128i + M128i::from(other)),
            Element::Soft(u64x2) => Element::Soft(u64x2 + U64x2::from(other)),
        }
    }

    /// Computes carryless POLYVAL multiplication over GF(2^128).
    ///
    /// From [RFC 8452 Section 3]:
    ///
    /// > "The product of any two elements is calculated using standard
    /// > (binary) polynomial multiplication followed by reduction modulo the
    /// > irreducible polynomial."
    ///
    /// [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
    pub fn clmul(self, other: Block) -> Self {
        match self {
            #[cfg(all(
                target_feature = "pclmulqdq",
                target_feature = "sse2",
                target_feature = "sse4.1",
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            Element::Clmul(m128i) => Element::Clmul(m128i * M128i::from(other)),
            Element::Soft(u64x2) => Element::Soft(u64x2 * U64x2::from(other)),
        }
    }
}

impl Default for Element {
    fn default() -> Self {
        Self::from_bytes(Block::default())
    }
}
