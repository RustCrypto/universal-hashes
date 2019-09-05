//! Field arithmetic backends

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod pclmulqdq;
mod soft;

use super::Block;
use core::ops::{Add, Mul};

// TODO(tarcieri): runtime selection of PCLMULQDQ based on CPU features

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub(crate) use self::pclmulqdq::M128i;

#[allow(unused_imports)]
pub(crate) use self::soft::U64x2;

#[cfg(not(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
pub(crate) type M128i = U64x2;

/// Field arithmetic backend
pub trait Backend:
    Copy + Add<Output = Self> + Mul<Output = Self> + From<Block> + Into<Block>
{
}
