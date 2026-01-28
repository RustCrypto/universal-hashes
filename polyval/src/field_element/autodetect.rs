//! Autodetection for CPU intrinsics, with fallback to the "soft" backend when
//! they are unavailable.

#[cfg(target_arch = "aarch64")]
use super::armv8 as intrinsics;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use super::x86 as intrinsics;

use super::{FieldElement, common, soft};
use crate::Block;
use core::ops::Mul;
use universal_hash::array::{Array, ArraySize};

#[cfg(target_arch = "aarch64")]
cpufeatures::new!(detect_intrinsics, "aes"); // `aes` implies PMULL
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
cpufeatures::new!(detect_intrinsics, "pclmulqdq");

pub(crate) use detect_intrinsics::{InitToken, init as init_intrinsics};

impl FieldElement {
    /// Default degree of parallelism, i.e. how many powers of `H` to compute.
    pub const DEFAULT_PARALLELISM: usize = 8;

    /// Compute the first N powers of h, in reverse order.
    #[inline]
    pub(crate) fn powers_of_h<const N: usize>(self, has_intrinsics: InitToken) -> [Self; N] {
        if has_intrinsics.get() {
            // SAFETY: we only need to ensure we have intrinsics, which we just did
            common::powers_of_h(self, |a, b| unsafe {
                intrinsics::polymul(a.into(), b.into()).into()
            })
        } else {
            common::powers_of_h(self, Mul::mul)
        }
    }

    /// Process an individual block.
    pub(crate) fn proc_block(
        h: FieldElement,
        y: FieldElement,
        block: &Block,
        has_intrinsics: InitToken,
    ) -> FieldElement {
        if has_intrinsics.get() {
            // SAFETY: we have checked the CPU has the necessary intrinsics above
            unsafe { intrinsics::proc_block(h, y, block) }
        } else {
            soft::proc_block(h, y, block)
        }
    }

    /// Process multiple blocks in parallel.
    pub(crate) fn proc_par_blocks<const N: usize, U: ArraySize>(
        powers_of_h: &[FieldElement; N],
        y: FieldElement,
        blocks: &Array<Block, U>,
        has_intrinsics: InitToken,
    ) -> FieldElement {
        if has_intrinsics.get() {
            // SAFETY: we have checked the CPU has the necessary intrinsics above
            unsafe { intrinsics::proc_par_blocks(powers_of_h, y, blocks) }
        } else {
            soft::proc_par_blocks(powers_of_h, y, blocks)
        }
    }
}
