//! Autodetection for (P)CLMUL(QDQ) CPU intrinsics on x86 CPUs, with fallback
//! to the "soft" backend when it's unavailable.

use crate::{backend, Block, Key};
use core::mem::ManuallyDrop;
use universal_hash::{consts::U16, NewUniversalHash, Output, UniversalHash};

cpuid_bool::new!(clmul_cpuid, "pclmulqdq", "sse4.1");

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
pub struct Polyval {
    inner: Inner,
    token: clmul_cpuid::InitToken,
}

union Inner {
    clmul: ManuallyDrop<backend::clmul::Polyval>,
    soft: ManuallyDrop<backend::soft::Polyval>,
}

impl NewUniversalHash for Polyval {
    type KeySize = U16;

    /// Initialize POLYVAL with the given `H` field element
    fn new(h: &Key) -> Self {
        let (token, clmul_present) = clmul_cpuid::init_get();

        let inner = if clmul_present {
            Inner {
                clmul: ManuallyDrop::new(backend::clmul::Polyval::new(h)),
            }
        } else {
            Inner {
                soft: ManuallyDrop::new(backend::soft::Polyval::new(h)),
            }
        };

        Self { inner, token }
    }
}

impl UniversalHash for Polyval {
    type BlockSize = U16;

    /// Input a field element `X` to be authenticated
    #[inline]
    fn update(&mut self, x: &Block) {
        if self.token.get() {
            unsafe { (*self.inner.clmul).update(x) }
        } else {
            unsafe { (*self.inner.soft).update(x) }
        }
    }

    /// Reset internal state
    fn reset(&mut self) {
        if self.token.get() {
            unsafe { (*self.inner.clmul).reset() }
        } else {
            unsafe { (*self.inner.soft).reset() }
        }
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    fn finalize(self) -> Output<Self> {
        let output_bytes = if self.token.get() {
            unsafe {
                ManuallyDrop::into_inner(self.inner.clmul)
                    .finalize()
                    .into_bytes()
            }
        } else {
            unsafe {
                ManuallyDrop::into_inner(self.inner.soft)
                    .finalize()
                    .into_bytes()
            }
        };

        Output::new(output_bytes)
    }
}

impl Clone for Polyval {
    fn clone(&self) -> Self {
        let inner = if self.token.get() {
            Inner {
                clmul: ManuallyDrop::new(unsafe { (*self.inner.clmul).clone() }),
            }
        } else {
            Inner {
                soft: ManuallyDrop::new(unsafe { (*self.inner.soft).clone() }),
            }
        };

        Self {
            inner,
            token: self.token,
        }
    }
}
