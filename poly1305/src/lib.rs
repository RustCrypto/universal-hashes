//! The Poly1305 universal hash function and message authentication code

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use universal_hash;

use universal_hash::{
    consts::{U16, U32},
    generic_array::GenericArray,
    NewUniversalHash, UniversalHash,
};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
))]
mod avx2;
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
))]
use avx2::State;

#[cfg(any(
    not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    )),
    any(fuzzing, test)
))]
mod soft;
#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2"
)))]
use soft::State;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
    any(fuzzing, test)
))]
mod fuzz;

/// Size of a Poly1305 key
pub const KEY_SIZE: usize = 32;

/// Size of the blocks Poly1305 acts upon
pub const BLOCK_SIZE: usize = 16;

/// Poly1305 keys (32-bytes)
pub type Key = universal_hash::Key<Poly1305>;

/// Poly1305 blocks (16-bytes)
pub type Block = universal_hash::Block<Poly1305>;

/// Poly1305 tags (16-bytes)
pub type Tag = universal_hash::Output<Poly1305>;

/// The Poly1305 universal hash function.
///
/// Note that Poly1305 is not a traditional MAC and is single-use only
/// (a.k.a. "one-time authenticator").
///
/// For this reason it doesn't impl the `crypto_mac::Mac` trait.
#[derive(Clone)]
pub struct Poly1305 {
    state: State,
}

impl NewUniversalHash for Poly1305 {
    type KeySize = U32;

    /// Initialize Poly1305 with the given key
    fn new(key: &Key) -> Poly1305 {
        Poly1305 {
            state: State::new(key),
        }
    }
}

impl UniversalHash for Poly1305 {
    type BlockSize = U16;

    /// Input data into the Poly1305 universal hash function
    fn update(&mut self, block: &Block) {
        self.state.compute_block(block, false);
    }

    /// Reset internal state
    fn reset(&mut self) {
        self.state.reset();
    }

    /// Get the hashed output
    fn finalize(mut self) -> Tag {
        self.state.finalize()
    }
}

impl Poly1305 {
    /// Compute unpadded Poly1305 for the given input data.
    ///
    /// The main use case for this is XSalsa20Poly1305.
    pub fn compute_unpadded(mut self, data: &[u8]) -> Tag {
        for chunk in data.chunks(BLOCK_SIZE) {
            if chunk.len() == BLOCK_SIZE {
                let block = GenericArray::from_slice(chunk);
                self.state.compute_block(block, false);
            } else {
                let mut block = Block::default();
                block[..chunk.len()].copy_from_slice(chunk);
                block[chunk.len()] = 1;
                self.state.compute_block(&block, true)
            }
        }

        self.state.finalize()
    }
}

/// Helper function for fuzzing the AVX2 backend.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
    any(fuzzing, test)
))]
pub fn fuzz_avx2(key: &Key, data: &[u8]) {
    let mut avx2 = avx2::State::new(key);
    let mut soft = soft::State::new(key);

    for (_i, chunk) in data.chunks(BLOCK_SIZE).enumerate() {
        if chunk.len() == BLOCK_SIZE {
            let block = GenericArray::from_slice(chunk);
            avx2.compute_block(block, false);
            soft.compute_block(block, false);
        } else {
            let mut block = Block::default();
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1;
            avx2.compute_block(&block, true);
            soft.compute_block(&block, true);
        }

        // Check that the same tag would be derived after each chunk.
        // We add the chunk number to the assertion for debugging.
        // When fuzzing, we skip this check, and just look at the end.
        #[cfg(test)]
        assert_eq!(
            (_i + 1, avx2.clone().finalize().into_bytes()),
            (_i + 1, soft.clone().finalize().into_bytes()),
        );
    }

    assert_eq!(avx2.finalize().into_bytes(), soft.finalize().into_bytes());
}
