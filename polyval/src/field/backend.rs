//! Field arithmetic backends

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod pclmulqdq;

#[cfg(feature = "insecure-soft")]
pub mod soft;

use super::Block;
use core::ops::Add;

#[cfg(not(any(
    all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    ),
    feature = "insecure-soft"
)))]
compile_error!(
    "no backends available! On x86/x86-64 platforms, enable intrinsics with \
     RUSTFLAGS=\"-Ctarget-cpu=sandybridge -Ctarget-feature=+sse2,+sse4.1\" or \
     enable **INSECURE** portable emulation with the `insecure-soft` feature"
);

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub(crate) use self::pclmulqdq::M128i;

#[cfg(all(
    not(all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    )),
    feature = "insecure-soft"
))]
pub(crate) use self::soft::U64x2 as M128i;

/// Field arithmetic backend
pub trait Backend: Add<Output = Self> + Copy + From<Block> + Into<Block> + From<u128> {
    /// Fast reduction modulo x^128 + x^127 + x^126 +x^121 + 1 (Gueron 2012)
    /// Algorithm 4: "Montgomery reduction"
    ///
    /// See: <https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf>
    fn reduce(self) -> Self {
        // Mask value used when performing Montgomery fast reduction.
        // This corresponds to POLYVAL's polynomial with the highest bit unset.
        let mask = Self::from(1 << 127 | 1 << 126 | 1 << 121 | 1);
        let a = mask.clmul(self, 0x01);
        let b = self.shuffle() + a;
        let c = mask.clmul(b, 0x01);
        b.shuffle() + c
    }

    /// Carryless multiplication
    fn clmul(self, rhs: Self, imm: u8) -> Self;

    /// Swap the hi and low 64-bit halves of the register
    fn shuffle(self) -> Self;

    /// Shift the contents of the register left by 64-bits
    fn shl64(self) -> Self;

    /// Shift the contents of the register right by 64-bits
    fn shr64(self) -> Self;
}
