#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

mod field_element;
mod mulx;

pub use crate::mulx::mulx;
pub use universal_hash;

use core::fmt::{self, Debug};
use field_element::{FieldElement, InitToken, detect_intrinsics};
use universal_hash::{
    KeyInit, ParBlocks, Reset, UhfBackend, UhfClosure, UniversalHash,
    array::{Array, ArraySize},
    common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
    consts::U16,
    typenum::{Const, ToUInt, U},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Size of a POLYVAL block in bytes
pub const BLOCK_SIZE: usize = 16;

/// Size of a POLYVAL key in bytes
pub const KEY_SIZE: usize = 16;

/// POLYVAL keys (16-bytes)
pub type Key = Array<u8, U16>;

/// POLYVAL blocks (16-bytes)
pub type Block = Array<u8, U16>;

/// POLYVAL tags (16-bytes)
pub type Tag = Array<u8, U16>;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
///
/// This type alias uses the default amount of parallelism for the target (`8` for `aarch64`/`x86`,
/// `1` for other targets using a pure Rust fallback implementation).
pub type Polyval = PolyvalGeneric<{ FieldElement::DEFAULT_PARALLELISM }>;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
///
/// Parameterized on a constant that determines how many blocks to process at once: higher numbers
/// use more memory, and require more time to re-key, but process data significantly faster.
///
/// (This constant is not used when acceleration is not enabled.)
#[derive(Clone)]
pub struct PolyvalGeneric<const N: usize = { FieldElement::DEFAULT_PARALLELISM }> {
    /// Powers of H in descending order.
    ///
    /// (H^N, H^(N-1)...H)
    powers_of_h: [FieldElement; N],

    /// Accumulator for POLYVAL computation.
    y: FieldElement,

    /// Token for accessing CPU feature detection results.
    has_intrinsics: InitToken,
}

impl<const N: usize> PolyvalGeneric<N> {
    /// Initialize POLYVAL with the given `H` field element.
    #[must_use]
    pub fn new(h: &Key) -> Self {
        Self::new_with_init_block(h, 0)
    }

    /// Initialize POLYVAL with the given `H` field element and initial block.
    #[must_use]
    pub fn new_with_init_block(h: &Key, init_block: u128) -> Self {
        let (token, _has_intrinsics) = detect_intrinsics();
        Self {
            powers_of_h: FieldElement::from(h).powers_of_h(),
            y: init_block.into(),
            has_intrinsics: token,
        }
    }

    /// Get `h` from the powers-of-`H`.
    #[inline]
    pub(crate) fn h(&self) -> FieldElement {
        self.powers_of_h[N - 1]
    }
}

impl<const N: usize> KeyInit for PolyvalGeneric<N> {
    fn new(h: &Key) -> Self {
        Self::new(h)
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

impl<const N: usize> UniversalHash for PolyvalGeneric<N>
where
    U<N>: ArraySize,
    Const<N>: ToUInt,
{
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    fn finalize(self) -> Tag {
        self.y.into()
    }
}

#[allow(clippy::unit_arg)]
impl<const N: usize> UhfBackend for PolyvalGeneric<N>
where
    U<N>: ArraySize,
    Const<N>: ToUInt,
{
    fn proc_block(&mut self, block: &Block) {
        self.y = FieldElement::proc_block(self.h(), self.y, block, self.has_intrinsics);
    }

    fn proc_par_blocks(&mut self, blocks: &ParBlocks<Self>) {
        self.y =
            FieldElement::proc_par_blocks(&self.powers_of_h, self.y, blocks, self.has_intrinsics);
    }
}

impl<const N: usize> Reset for PolyvalGeneric<N> {
    fn reset(&mut self) {
        self.y = FieldElement::default();
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> Drop for PolyvalGeneric<N> {
    fn drop(&mut self) {
        self.powers_of_h.zeroize();
        self.y.zeroize();
    }
}

impl<const N: usize> Debug for PolyvalGeneric<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "PolyvalGeneric<{}> {{ ... }}", N)
    }
}
