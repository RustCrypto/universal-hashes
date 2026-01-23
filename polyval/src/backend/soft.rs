//! Portable software implementation. Provides implementations for low power 32-bit devices as well
//! as a 64-bit implementation.

cpubits::cpubits! {
    16 | 32 => {
        #[path = "soft/soft32.rs"]
        mod soft_impl;
    }
    64 => {
        #[path = "soft/soft64.rs"]
        mod soft_impl;
    }
}

use crate::{Block, Key, Tag};
use soft_impl::*;
use universal_hash::{
    KeyInit, Reset, UhfBackend, UhfClosure, UniversalHash,
    consts::{U1, U16},
    crypto_common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
///
/// Parameterized on a constant that determines how many
/// blocks to process at once: higher numbers use more memory,
/// and require more time to re-key, but process data significantly
/// faster.
///
/// (This constant is not used when acceleration is not enabled.)
#[derive(Clone)]
pub struct Polyval<const N: usize = 1> {
    /// GF(2^128) field element input blocks are multiplied by
    h: FieldElement,

    /// Field element representing the computed universal hash
    s: FieldElement,
}

impl<const N: usize> Polyval<N> {
    /// Initialize POLYVAL with the given `H` field element and initial block
    pub fn new_with_init_block(h: &Key, init_block: u128) -> Self {
        Self {
            h: FieldElement::from_le_bytes(h),
            s: init_block.into(),
        }
    }
}

impl<const N: usize> KeySizeUser for Polyval<N> {
    type KeySize = U16;
}

impl<const N: usize> KeyInit for Polyval<N> {
    /// Initialize POLYVAL with the given `H` field element
    fn new(h: &Key) -> Self {
        Self::new_with_init_block(h, 0)
    }
}

impl<const N: usize> BlockSizeUser for Polyval<N> {
    type BlockSize = U16;
}

impl<const N: usize> ParBlocksSizeUser for Polyval<N> {
    type ParBlocksSize = U1;
}

impl<const N: usize> UhfBackend for Polyval<N> {
    fn proc_block(&mut self, x: &Block) {
        let x = FieldElement::from_le_bytes(x);
        self.s = (self.s + x) * self.h;
    }
}

impl<const N: usize> UniversalHash for Polyval<N> {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    fn finalize(self) -> Tag {
        self.s.to_le_bytes()
    }
}

impl<const N: usize> Reset for Polyval<N> {
    fn reset(&mut self) {
        self.s = FieldElement::default();
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> Drop for Polyval<N> {
    fn drop(&mut self) {
        self.h.zeroize();
        self.s.zeroize();
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
        let a = FieldElement::from_le_bytes(&A.into());
        let b = FieldElement::from_le_bytes(&B.into());

        let expected =
            FieldElement::from_le_bytes(&hex!("99e94bd4ef8a2c3b884cfa59ca342b2e").into());
        assert_eq!(a + b, expected);
        assert_eq!(b + a, expected);
    }

    #[test]
    fn fe_mul() {
        let a = FieldElement::from_le_bytes(&A.into());
        let b = FieldElement::from_le_bytes(&B.into());

        let expected =
            FieldElement::from_le_bytes(&hex!("ebe563401e7e91ea3ad6426b8140c394").into());
        assert_eq!(a * b, expected);
        assert_eq!(b * a, expected);
    }
}
