//! POLYVAL field element implementation.

mod soft;

use crate::{BLOCK_SIZE, Block};
use core::{
    fmt::{self, Debug},
    ops::{Add, Mul, MulAssign},
};
use cpubits::cfg_if;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// An element in POLYVAL's field.
///
/// This type represents an element of the binary field GF(2^128) modulo the irreducible polynomial
/// `x^128 + x^127 + x^126 + x^121 + 1` as described in [RFC8452 §3].
///
/// # Representation
///
/// The element is represented as 16-bytes in little-endian order, using a `repr(C)` ABI and
/// 16-byte alignment enforced with `align(16)`.
///
/// Arithmetic in POLYVAL's field has the following properties:
/// - All arithmetic operations are performed modulo the polynomial above.
/// - Addition is equivalent to the XOR operation applied to the two field elements
/// - Multiplication is carryless
///
/// [RFC8452 §3]: https://tools.ietf.org/html/rfc8452#section-3
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[repr(C, align(16))] // Make ABI and alignment compatible with SIMD registers
pub struct FieldElement([u8; BLOCK_SIZE]);

impl FieldElement {
    /// Reverse this field element at a byte-level of granularity.
    ///
    /// This is useful when implementing GHASH in terms of POLYVAL.
    pub fn reverse(&mut self) {
        self.0.reverse();
    }
}

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", not(polyval_backend = "soft")))] {
        // aarch64
        mod autodetect;
        mod armv8;
        pub(crate) use autodetect::{InitToken, init_intrinsics};
    } else if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(polyval_backend = "soft")
    ))] {
        // x86/x86-64
        mod autodetect;
        mod x86;
        pub(crate) use autodetect::{InitToken, init_intrinsics};
    } else {
        // "soft" fallback implementation for other targets written in pure Rust
        use universal_hash::array::{Array, ArraySize};

        // Stub intrinsics "detection"
        pub(crate) type InitToken = ();
        pub(crate) fn init_intrinsics() {}

        impl FieldElement {
            /// Default degree of parallelism, i.e. how many powers of `H` to compute.
            pub const DEFAULT_PARALLELISM: usize = 8;

            /// Stub implementation that works with `Polyval::h` even though we don't support
            /// `proc_par_blocks`.
            #[inline]
            pub(crate) fn powers_of_h<const N: usize>(
                self,
                _has_intrinsics: InitToken
            ) -> [Self; N] {
                soft::powers_of_h(self)
            }

            /// Process an individual block.
            pub(crate) fn proc_block(
                h: FieldElement,
                y: FieldElement,
                x: &Block,
                _has_intrinsics: InitToken
            ) -> FieldElement {
                soft::proc_block(h, y, x)
            }

            /// Process multiple blocks in parallel.
            // TODO(tarcieri): currently just calls `proc_block` for each block on `soft`-only
            pub(crate) fn proc_par_blocks<const N: usize, U: ArraySize>(
                powers_of_h: &[FieldElement; N],
                y: FieldElement,
                blocks: &Array<Block, U>,
                _has_intrinsics: InitToken
            ) -> FieldElement {
                soft::proc_par_blocks(powers_of_h, y, blocks)
            }
        }
    }
}

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

    /// Perform carryless multiplication within POLYVAL's field modulo its polynomial.
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        soft::polymul(self, rhs)
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
