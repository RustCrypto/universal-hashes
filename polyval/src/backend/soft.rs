//! Portable software implementation written in terms of [`FieldElement`].

use crate::{Block, FieldElement, ParBlocks, Tag};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[derive(Clone, Copy)]
pub(crate) struct State {
    /// Hash key: fixed element of GF(2^128) that parameterizes the POLYVAL universal hash function.
    ///
    /// This is the multiplier that advances POLYVAL's state. Each message block is XORed into the
    /// accumulator and then multiplied by `H`.
    h: FieldElement,

    /// Accumulator for POLYVAL computation.
    y: FieldElement,
}

impl State {
    pub(crate) fn new(h: FieldElement, _has_intrinsics: InitToken) -> Self {
        let y = FieldElement::default();
        Self { h, y }
    }

    pub(crate) fn proc_block(&mut self, block: &Block, _has_intrinsics: InitToken) {
        self.y = (self.y + block.into()) * self.h;
    }

    pub(crate) fn proc_par_blocks(&mut self, par_blocks: &ParBlocks, has_intrinsics: InitToken) {
        // Just process them in sequence since we don't support anything fancy
        for block in par_blocks {
            self.proc_block(block, has_intrinsics);
        }
    }

    pub(crate) fn finalize(&self, _has_intrinsics: InitToken) -> Tag {
        self.y.into()
    }

    pub(crate) fn reset(&mut self, _has_intrinsics: InitToken) {
        self.y = FieldElement::default();
    }

    #[allow(dead_code)]
    pub(crate) fn clone_with_intrinsics(&self, _has_intrinsics: InitToken) -> Self {
        *self
    }

    #[cfg(feature = "zeroize")]
    pub(crate) fn zeroize(&mut self, _has_intrinsics: InitToken) {
        self.h.zeroize();
        self.y.zeroize();
    }
}

/// Stub initialization token for software-only scenarios.
#[derive(Clone, Copy)]
pub(crate) struct InitToken(());

impl InitToken {
    /// Stub initialize function for compatibility with real CPU feature detection.
    #[inline]
    pub(crate) fn init() -> Self {
        Self(())
    }
}
