//! GHASH field element implementation.
//!
//! This module implements GHASH's field in terms of POLYVAL's, which is its little endian
//! equivalent. Elements are stored in POLYVAL's representation, i.e. as
//! `mulX_POLYVAL(ByteReverse(a))` as described in [RFC 8452 Appendix A], the inverse conversion
//! being `ByteReverse(divX_POLYVAL(a))`.
//!
//! This representation preserves both addition and multiplication (the latter because POLYVAL's
//! multiplication includes a Montgomery factor of `x^-128`, which cancels out the `x^127`
//! introduced by the byte reversal), so the arithmetic is a direct delegation to
//! [`polyval::hazmat::FieldElement`].
//!
//! [RFC 8452 Appendix A]: https://tools.ietf.org/html/rfc8452#appendix-A

use crate::Block;
use core::{
    fmt::{self, Debug},
    ops::{Add, Mul, MulAssign},
};
use polyval::{BLOCK_SIZE, hazmat::FieldElement as PolyvalElement};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// An element in GHASH's field.
///
/// This type represents an element of the binary field GF(2^128) modulo the irreducible polynomial
/// `x^128 + x^7 + x^2 + x + 1` as described in [NIST SP 800-38D §6.3].
///
/// Arithmetic in GHASH's field has the following properties:
/// - All arithmetic operations are performed modulo the polynomial above.
/// - Addition is equivalent to the XOR operation applied to the two field elements
/// - Multiplication is carryless
///
/// Note that elements are stored internally in POLYVAL's field (see the module-level
/// documentation), and thus converting to and from a byte representation is not free.
///
/// [NIST SP 800-38D §6.3]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
#[derive(Clone, Copy, Default)]
pub struct FieldElement(PolyvalElement);

impl FieldElement {
    /// Convert this field element back into GHASH's representation.
    #[inline]
    fn to_bytes(self) -> [u8; BLOCK_SIZE] {
        self.0.divx().reverse().into()
    }
}

impl Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(")?;
        for byte in self.to_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl From<[u8; BLOCK_SIZE]> for FieldElement {
    /// Convert a GHASH field element into POLYVAL's representation.
    #[inline]
    fn from(bytes: [u8; BLOCK_SIZE]) -> Self {
        Self(PolyvalElement::from(bytes).reverse().mulx())
    }
}

impl From<FieldElement> for [u8; BLOCK_SIZE] {
    #[inline]
    fn from(fe: FieldElement) -> Self {
        fe.to_bytes()
    }
}

impl From<Block> for FieldElement {
    #[inline]
    fn from(block: Block) -> Self {
        Self::from(<[u8; BLOCK_SIZE]>::from(block))
    }
}

impl From<FieldElement> for Block {
    #[inline]
    fn from(fe: FieldElement) -> Self {
        fe.to_bytes().into()
    }
}

impl Add for FieldElement {
    type Output = Self;

    /// Adds two GHASH field elements.
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    /// Perform carryless multiplication within GHASH's field modulo its polynomial.
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl MulAssign for FieldElement {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use hex_literal::hex;

    // Test vectors for GHASH from RFC 8452 Appendix A
    // https://tools.ietf.org/html/rfc8452#appendix-A

    const H: [u8; 16] = hex!("25629347589242761d31f826ba4b757b");
    const X_1: [u8; 16] = hex!("4f4f95668c83dfb6401762bb2d01a262");
    const X_2: [u8; 16] = hex!("d1a24ddd2721d006bbe45f20d3c9f362");

    /// GHASH(H, X_1, X_2)
    const GHASH_RESULT: [u8; 16] = hex!("bd9b3997046731fb96251b91f9c99d7a");

    /// Converting to POLYVAL's field and back is the identity.
    #[test]
    fn roundtrip() {
        assert_eq!(FieldElement::from(H).to_bytes(), H);
    }

    /// Addition is the XOR of the GHASH representations.
    #[test]
    fn fe_add() {
        let expected = FieldElement::from(hex!("9eedd8bbaba20fb0fbf33d9bfec85100"));
        assert_eq!(FieldElement::from(X_1) + FieldElement::from(X_2), expected);
    }

    /// GHASH is `((X_1 * H) + X_2) * H`.
    #[test]
    fn fe_mul() {
        let h = FieldElement::from(H);
        let y = (FieldElement::from(X_1) * h + FieldElement::from(X_2)) * h;
        assert_eq!(y.to_bytes(), GHASH_RESULT);
    }
}
