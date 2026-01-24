#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(missing_docs)]

mod backend;
mod mulx;

pub use crate::{backend::DEFAULT_N_BLOCKS, mulx::mulx};
pub use universal_hash;

use backend::{FieldElement, InitToken};
use core::fmt;
use universal_hash::{
    KeyInit,
    consts::U16,
    crypto_common::{
        BlockSizeUser, KeySizeUser, ParBlocksSizeUser,
        array::ArraySize,
        typenum::{Const, ToUInt, U},
    },
};

/// Size of a POLYVAL block in bytes
pub const BLOCK_SIZE: usize = 16;

/// Size of a POLYVAL key in bytes
pub const KEY_SIZE: usize = 16;

/// POLYVAL keys (16-bytes)
pub type Key = universal_hash::Key<Polyval>;

/// POLYVAL blocks (16-bytes)
pub type Block = universal_hash::Block<Polyval>;

/// POLYVAL tags (16-bytes)
pub type Tag = universal_hash::Block<Polyval>;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
///
/// This type alias automatically uses the default recommended level of parallelism.
pub type Polyval = PolyvalGeneric<DEFAULT_N_BLOCKS>;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
///
/// Parameterized on a constant that determines how many
/// blocks to process at once: higher numbers use more memory,
/// and require more time to re-key, but process data significantly
/// faster.
///
/// (This constant is not used when acceleration is not enabled.)
#[derive(Clone)]
pub struct PolyvalGeneric<const N: usize = DEFAULT_N_BLOCKS> {
    /// Powers of H in descending order.
    ///
    /// (H^N, H^(N-1)...H)
    h: [FieldElement; N],

    /// Accumulator for the universal hash computation.
    y: FieldElement,

    /// Initialization token for CPU feature autodetection.
    // TODO(tarcieri): compile this out in `soft` backend-only scenarios
    #[allow(dead_code)]
    init_token: InitToken,
}

impl<const N: usize> PolyvalGeneric<N> {
    /// Initialize POLYVAL with the given `H` field element and initial block
    pub fn new_with_init_block(h: &Key, init_block: u128) -> Self {
        const { assert!(N > 0, "N must be at least 1") }
        let (init_token, has_intrinsics) = backend::detect_intrinsics();
        Self {
            h: Self::compute_powers_of_h(h, has_intrinsics),
            y: init_block.into(),
            init_token,
        }
    }
}

impl<const N: usize> KeyInit for PolyvalGeneric<N> {
    /// Initialize POLYVAL with the given `H` field element.
    fn new(h: &Key) -> Self {
        Self::new_with_init_block(h, 0)
    }
}

impl<const N: usize> KeySizeUser for PolyvalGeneric<N> {
    type KeySize = U16;
}

impl<const N: usize> BlockSizeUser for PolyvalGeneric<N> {
    type BlockSize = U16;
}

impl<const N: usize> ParBlocksSizeUser for PolyvalGeneric<N>
where
    U<N>: ArraySize,
    Const<N>: ToUInt,
{
    type ParBlocksSize = U<N>;
}

impl fmt::Debug for Polyval {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Polyval").finish_non_exhaustive()
    }
}
