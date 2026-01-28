//! Property-based tests.

#![cfg(all(any(unix, windows), feature = "hazmat"))]

use polyval::{BLOCK_SIZE, Block, KEY_SIZE, hazmat::FieldElement, universal_hash::UniversalHash};
use proptest::prelude::*;

/// Number of blocks to compute in parallel
const PARALLEL_BLOCKS: usize = 8;

/// Ensure we're always parallel
type ParallelPolyval = polyval::PolyvalGeneric<PARALLEL_BLOCKS>;

proptest! {
    /// Test explicitly parallel implementation for equivalence to the `soft` backend (which is what
    /// powers `Add`/`Mul` trait impls on `FieldElement`.
    #[test]
    fn par_soft_equivalence(
        key in any::<[u8; KEY_SIZE]>(),
        data in any::<[u8; BLOCK_SIZE * PARALLEL_BLOCKS]>()
    ) {
        let mut polyval = ParallelPolyval::new(&key.into());
        polyval.update_padded(&data);
        let actual = polyval.finalize();

        let h = FieldElement::from(key);
        let mut y = FieldElement::default();
        for block in Block::slice_as_chunks(&data).0 {
            y = (y + block.into()) * h;
        }

        prop_assert_eq!(actual, Block::from(y));
    }
}
