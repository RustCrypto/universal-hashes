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

pub(crate) use soft_impl::FieldElement;

use crate::{Block, Key, PolyvalGeneric as Polyval, Tag};
use universal_hash::{
    Reset, UhfBackend, UhfClosure, UniversalHash,
    array::ArraySize,
    crypto_common::typenum::{Const, ToUInt, U},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Default number of blocks to use for powers-of-h.
pub const DEFAULT_N_BLOCKS: usize = 1;

impl<const N: usize> Polyval<N> {
    pub(crate) fn compute_powers_of_h_soft(h: &Key, has_intrinsics: bool) -> [FieldElement; N] {
        debug_assert!(!has_intrinsics);

        // TODO(tarcieri): actually compute powers of h. This only uses the first element.
        let mut h_array = [FieldElement::default(); N];
        h_array[0] = FieldElement::from_le_bytes(h);
        h_array
    }
}

impl<const N: usize> UhfBackend for Polyval<N>
where
    U<N>: ArraySize,
    Const<N>: ToUInt,
{
    fn proc_block(&mut self, x: &Block) {
        let x = FieldElement::from_le_bytes(x);
        self.y = (self.y + x) * self.h[0];
    }
}

impl<const N: usize> UniversalHash for Polyval<N>
where
    U<N>: ArraySize,
    Const<N>: ToUInt,
{
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    fn finalize(self) -> Tag {
        self.y.to_le_bytes()
    }
}

impl<const N: usize> Reset for Polyval<N> {
    fn reset(&mut self) {
        self.y = FieldElement::default();
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> Drop for Polyval<N> {
    fn drop(&mut self) {
        self.h.zeroize();
        self.y.zeroize();
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
