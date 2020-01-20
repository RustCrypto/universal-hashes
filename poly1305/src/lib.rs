//! The Poly1305 universal hash function and message authentication code

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
)))]
mod soft;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
))]
mod avx2;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
)))]
pub use self::soft::Poly1305;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
))]
pub use self::avx2::Poly1305;

pub use universal_hash;

use universal_hash::{generic_array::typenum::U16, Output};

/// Size of a Poly1305 key
pub const KEY_SIZE: usize = 32;

/// Poly1305 keys (32-bytes)
pub type Key = [u8; KEY_SIZE];

/// Size of the blocks Poly1305 acts upon
pub const BLOCK_SIZE: usize = 16;

/// Poly1305 blocks (16-bytes)
pub type Block = [u8; BLOCK_SIZE];

/// Poly1305 tags (16-bytes)
pub type Tag = Output<U16>;
