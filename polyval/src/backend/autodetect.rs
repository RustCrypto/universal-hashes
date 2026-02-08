//! Support for CPU feature autodetection with a portable pure Rust fallback.

use super::{InitToken, soft};
use crate::{Block, FieldElement, ParBlocks, Tag};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use super::avx2 as intrinsics;
#[cfg(target_arch = "aarch64")]
use super::neon as intrinsics;

pub(crate) union State {
    intrinsics: intrinsics::State,
    soft: soft::State,
}

impl State {
    pub(crate) fn new(h: FieldElement, has_intrinsics: InitToken) -> Self {
        if has_intrinsics.get() {
            Self {
                intrinsics: unsafe { intrinsics::State::new(&h.into()) },
            }
        } else {
            Self {
                soft: soft::State::new(h, soft::InitToken::init()),
            }
        }
    }

    pub(crate) fn proc_block(&mut self, block: &Block, has_intrinsics: InitToken) {
        if has_intrinsics.get() {
            unsafe { self.intrinsics.update_block(&block.0) }
        } else {
            unsafe { self.soft.proc_block(block, soft::InitToken::init()) }
        }
    }

    pub(crate) fn proc_par_blocks(&mut self, par_blocks: &ParBlocks, has_intrinsics: InitToken) {
        if has_intrinsics.get() {
            unsafe { self.intrinsics.proc_par_blocks(par_blocks) }
        } else {
            unsafe {
                self.soft
                    .proc_par_blocks(par_blocks, soft::InitToken::init());
            }
        }
    }

    pub(crate) fn finalize(&self, has_intrinsics: InitToken) -> Tag {
        if has_intrinsics.get() {
            unsafe { self.intrinsics.finalize().into() }
        } else {
            unsafe { self.soft.finalize(soft::InitToken::init()) }
        }
    }

    pub(crate) fn reset(&mut self, has_intrinsics: InitToken) {
        if has_intrinsics.get() {
            unsafe { self.intrinsics.reset() }
        } else {
            unsafe { self.soft.reset(soft::InitToken::init()) }
        }
    }

    pub(crate) fn clone_with_intrinsics(&self, has_intrinsics: InitToken) -> Self {
        if has_intrinsics.get() {
            Self {
                intrinsics: unsafe { self.intrinsics },
            }
        } else {
            Self {
                soft: unsafe { self.soft },
            }
        }
    }

    #[cfg(feature = "zeroize")]
    pub(crate) fn zeroize(&mut self, has_intrinsics: InitToken) {
        if has_intrinsics.get() {
            unsafe {
                self.intrinsics.zeroize();
            }
        } else {
            unsafe {
                self.soft.zeroize(soft::InitToken::init());
            }
        }
    }
}
