//! POLYVAL backends

mod soft;

use crate::{BLOCK_SIZE, Block};
use core::fmt;
use core::fmt::Debug;
use core::ops::{Add, Mul};
use cpubits::cfg_if;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", not(polyval_backend = "soft")))] {
        mod autodetect;
        mod pmull;
        mod common;
        pub use crate::backend::autodetect::Polyval as PolyvalGeneric;
    } else if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(polyval_backend = "soft")
    ))] {
        mod autodetect;
        mod clmul;
        mod common;
        pub use crate::backend::autodetect::Polyval as PolyvalGeneric;
    } else {
        pub use crate::backend::soft::Polyval as PolyvalGeneric;
    }
}

/// An element in POLYVAL's field.
///
/// This type represents an element of the binary field GF(2^128) modulo the irreducible polynomial
/// `x^128 + x^127 + x^126 + x^121 + 1` as described in [RFC8452 §3].
///
/// # Representation
///
/// The element is represented as 16-bytes in little-endian order.
///
/// Arithmetic in POLYVAL's field has the following properties:
/// - All arithmetic operations are performed modulo the polynomial above.
/// - Addition is equivalent to the XOR operation applied to the two field elements
/// - Multiplication is carryless
///
/// [RFC8452 §3]: https://tools.ietf.org/html/rfc8452#section-3
#[derive(Clone, Copy, Default, Eq, PartialEq)] // TODO(tarcieri): constant-time `*Eq`?
#[repr(C, align(16))] // Make ABI and alignment compatible with SIMD registers
pub(crate) struct FieldElement([u8; BLOCK_SIZE]);

impl Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(")?;
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl From<Block> for FieldElement {
    #[inline]
    fn from(block: Block) -> Self {
        Self(block.into())
    }
}

impl From<&Block> for FieldElement {
    #[inline]
    fn from(block: &Block) -> Self {
        Self::from(*block)
    }
}

impl From<FieldElement> for Block {
    #[inline]
    fn from(fe: FieldElement) -> Self {
        fe.0.into()
    }
}

impl From<&FieldElement> for Block {
    #[inline]
    fn from(fe: &FieldElement) -> Self {
        Self::from(*fe)
    }
}

impl From<[u8; BLOCK_SIZE]> for FieldElement {
    #[inline]
    fn from(bytes: [u8; BLOCK_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<u128> for FieldElement {
    #[inline]
    fn from(x: u128) -> Self {
        Self(x.to_le_bytes())
    }
}

impl From<FieldElement> for u128 {
    #[inline]
    fn from(fe: FieldElement) -> Self {
        u128::from_le_bytes(fe.0)
    }
}

impl Add for FieldElement {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    ///
    /// In POLYVAL's field, addition is the equivalent operation to XOR.
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        (u128::from(self) ^ u128::from(rhs)).into()
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let v = soft::karatsuba(self.into(), rhs.into());
        soft::mont_reduce(v).into()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const A: [u8; 16] = hex!("66e94bd4ef8a2c3b884cfa59ca342b2e");
    const B: [u8; 16] = hex!("ff000000000000000000000000000000");

    #[test]
    fn fe_add() {
        let a = FieldElement::from(A);
        let b = FieldElement::from(B);

        let expected = FieldElement::from(hex!("99e94bd4ef8a2c3b884cfa59ca342b2e"));
        assert_eq!(a + b, expected);
        assert_eq!(b + a, expected);
    }

    #[test]
    fn fe_mul() {
        let a = FieldElement::from(A);
        let b = FieldElement::from(B);

        let expected = FieldElement::from(hex!("ebe563401e7e91ea3ad6426b8140c394"));
        assert_eq!(a * b, expected);
        assert_eq!(b * a, expected);
    }
}
