//! SIMD implementation of Poly1305 using 26-bit limbs.

// The `State` struct and its logic was originally derived from Goll and Gueron's AVX2 C code:
//     [Vectorization of Poly1305 message authentication code](https://ieeexplore.ieee.org/document/7113463)
//
// which was sourced from Bhattacharyya and Sarkar's modified variant:
//     [Improved SIMD Implementation of Poly1305](https://eprint.iacr.org/2019/842)
//     https://github.com/Sreyosi/Improved-SIMD-Implementation-of-Poly1305
//
// The logic has been extensively rewritten and documented, and several bugs in the
// original C code were fixed.
//
// Note that State only implements the original Goll-Gueron algorithm, not the
// optimisations provided by Bhattacharyya and Sarkar. The latter require the message
// length to be known, which is incompatible with the streaming API of UniversalHash.

use crate::{Block, Key, Tag};
use core::fmt;
use universal_hash::{
    UhfBackend,
    array::Array,
    common::{BlockSizeUser, ParBlocksSizeUser},
    consts::{U4, U16},
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::avx2::{U32x8, U64x4, prepare_keys};
#[cfg(target_arch = "aarch64")]
use super::neon::{U32x8, U64x4, prepare_keys};

/// Four Poly1305 blocks (64-bytes)
type ParBlocks = universal_hash::ParBlocks<State>;

#[derive(Clone)]
pub(crate) struct State {
    k: AdditionKey,
    r1: PrecomputedMultiplier,
    r2: PrecomputedMultiplier,
    initialized: Option<Initialized>,
    cached_blocks: [Block; 4],
    num_cached_blocks: usize,
    partial_block: Option<Block>,
}

#[derive(Copy, Clone)]
struct Initialized {
    p: Aligned4x130,
    m: SpacedMultiplier4x130,
    r4: PrecomputedMultiplier,
}

impl State {
    /// Initialize Poly1305 [`State`] with the given key
    pub(crate) fn new(key: &Key) -> Self {
        // Prepare addition key and polynomial key.
        let (k, r1) = unsafe { prepare_keys(key) };

        // Precompute R^2.
        let r2 = (r1 * r1).reduce();

        State {
            k,
            r1,
            r2: r2.into(),
            initialized: None,
            cached_blocks: [Block::default(); 4],
            num_cached_blocks: 0,
            partial_block: None,
        }
    }

    /// Process four Poly1305 blocks at once.
    #[cfg_attr(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature(enable = "avx2")
    )]
    pub(crate) unsafe fn compute_par_blocks(&mut self, blocks: &ParBlocks) {
        assert!(self.partial_block.is_none());
        assert_eq!(self.num_cached_blocks, 0);

        self.process_blocks(Aligned4x130::from_par_blocks(blocks));
    }

    /// Compute a Poly1305 block.
    #[cfg_attr(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature(enable = "avx2")
    )]
    pub(crate) unsafe fn compute_block(&mut self, block: &Block, partial: bool) {
        // We can cache a single partial block.
        if partial {
            assert!(self.partial_block.is_none());
            self.partial_block = Some(*block);
            return;
        }

        self.cached_blocks[self.num_cached_blocks].copy_from_slice(block);
        if self.num_cached_blocks < 3 {
            self.num_cached_blocks += 1;
            return;
        } else {
            self.num_cached_blocks = 0;
        }

        self.process_blocks(Aligned4x130::from_blocks(&self.cached_blocks));
    }

    /// Compute a Poly1305 block.
    #[cfg_attr(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature(enable = "avx2")
    )]
    unsafe fn process_blocks(&mut self, blocks: Aligned4x130) {
        if let Some(inner) = &mut self.initialized {
            // P <-- R^4 * P + blocks
            inner.p = (&inner.p * inner.r4).reduce() + blocks;
        } else {
            // Initialize the polynomial.
            let p = blocks;

            // Initialize the multiplier (used to merge down the polynomial during
            // finalization).
            let (m, r4) = SpacedMultiplier4x130::new(self.r1, self.r2);

            self.initialized = Some(Initialized { p, m, r4 });
        }
    }

    /// Finalize output producing a [`Tag`].
    #[cfg_attr(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature(enable = "avx2")
    )]
    pub(crate) unsafe fn finalize(&mut self) -> Tag {
        assert!(self.num_cached_blocks < 4);
        let mut data = &self.cached_blocks[..];

        // T ← R◦T
        // P = T_0 + T_1 + T_2 + T_3
        let mut p = self
            .initialized
            .take()
            .map(|inner| (inner.p * inner.m).sum().reduce());

        if self.num_cached_blocks >= 2 {
            // Compute 32 byte block (remaining data < 64 bytes)
            let mut c = Aligned2x130::from_blocks(data[..2].try_into().unwrap());
            if let Some(p) = p {
                c = c + p;
            }
            p = Some(c.mul_and_sum(self.r1, self.r2).reduce());
            data = &data[2..];
            self.num_cached_blocks -= 2;
        }

        if self.num_cached_blocks == 1 {
            // Compute 16 byte block (remaining data < 32 bytes)
            let mut c = Aligned130::from_block(&data[0]);
            if let Some(p) = p {
                c = c + p;
            }
            p = Some((c * self.r1).reduce());
            self.num_cached_blocks -= 1;
        }

        if let Some(block) = &self.partial_block {
            // Compute last block (remaining data < 16 bytes)
            let mut c = Aligned130::from_partial_block(block);
            if let Some(p) = p {
                c = c + p;
            }
            p = Some((c * self.r1).reduce());
        }

        // Compute tag: p + k mod 2^128
        let mut tag = Array::<u8, _>::default();
        let tag_int = if let Some(p) = p {
            self.k + p
        } else {
            self.k.into()
        };
        tag_int.write(tag.as_mut_slice());

        tag
    }
}

impl BlockSizeUser for State {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for State {
    type ParBlocksSize = U4;
}

impl UhfBackend for State {
    fn proc_block(&mut self, block: &Block) {
        unsafe { self.compute_block(block, false) };
    }

    fn proc_par_blocks(&mut self, blocks: &ParBlocks) {
        if self.num_cached_blocks == 0 {
            // Fast path.
            unsafe { self.compute_par_blocks(blocks) };
        } else {
            // We are unaligned; use the slow fallback.
            for block in blocks {
                self.proc_block(block);
            }
        }
    }

    fn blocks_needed_to_align(&self) -> usize {
        if self.num_cached_blocks == 0 {
            // There are no cached blocks; fast path is available.
            0
        } else {
            // There are cached blocks; report how many more we need.
            self.cached_blocks.len() - self.num_cached_blocks
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct AdditionKey(pub(super) U64x4);

/// A 130-bit integer aligned across five 26-bit limbs.
///
/// The top three 32-bit words of the underlying 256-bit vector are ignored.
#[derive(Clone, Copy, Debug)]
pub(super) struct Aligned130(pub(super) U32x8);

/// A pair of `Aligned130`s.
#[derive(Clone, Debug)]
pub(super) struct Aligned2x130 {
    pub(super) v0: Aligned130,
    pub(super) v1: Aligned130,
}

impl fmt::Display for Aligned2x130 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Aligned2x130([")?;
        writeln!(f, "    {},", self.v0)?;
        writeln!(f, "    {},", self.v1)?;
        write!(f, "])")
    }
}

impl Aligned2x130 {
    /// Aligns two 16-byte Poly1305 blocks at 26-bit boundaries within 32-bit words, and
    /// sets the high bit for each block.
    #[cfg_attr(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature(enable = "avx2")
    )]
    pub(super) unsafe fn from_blocks(src: &[Block; 2]) -> Self {
        Aligned2x130 {
            v0: Aligned130::from_block(&src[0]),
            v1: Aligned130::from_block(&src[1]),
        }
    }
}

/// Four 130-bit integers aligned across five 26-bit limbs each.
///
/// Unlike `Aligned2x130` which wraps two `Aligned130`s, this struct represents the four integers as
/// 20 limbs spread across three 256-bit vectors.
#[derive(Copy, Clone, Debug)]
pub(super) struct Aligned4x130 {
    pub(super) v0: U32x8,
    pub(super) v1: U32x8,
    pub(super) v2: U32x8,
}

/// A pre-computed multiplier.
#[derive(Clone, Copy, Debug)]
pub(super) struct PrecomputedMultiplier {
    pub(super) a: U32x8,
    pub(super) a_5: U32x8,
}

/// A multiplier that takes 130-bit integers `(x3, x2, x1, x0)` and computes
/// `(x3·R^4, x2·R^3, x1·R^2, x0·R) mod 2^130 - 5`.
#[derive(Copy, Clone, Debug)]
pub(super) struct SpacedMultiplier4x130 {
    v0: U32x8,
    v1: U32x8,
    r1: PrecomputedMultiplier,
}

/// The unreduced output of an `Aligned130` multiplication.
///
/// Represented internally with 64-bit limbs.
#[derive(Copy, Clone, Debug)]
pub(super) struct Unreduced130 {
    pub(super) v0: U64x4,
    pub(super) v1: U64x4,
}

/// The unreduced output of an `Aligned4x130` multiplication.
#[derive(Clone, Debug)]
pub(super) struct Unreduced4x130 {
    pub(super) v0: U64x4,
    pub(super) v1: U64x4,
    pub(super) v2: U64x4,
    pub(super) v3: U64x4,
    pub(super) v4: U64x4,
}
