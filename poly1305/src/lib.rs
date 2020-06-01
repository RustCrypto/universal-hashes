//! The Poly1305 universal hash function and message authentication code

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub use universal_hash;

use universal_hash::{
    consts::{U16, U32},
    generic_array::GenericArray,
    NewUniversalHash, UniversalHash,
};

mod soft;

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
    state: soft::State,
}

impl NewUniversalHash for Poly1305 {
    type KeySize = U32;

    /// Initialize Poly1305 with the given key
    fn new(key: &Key) -> Poly1305 {
        Poly1305 {
            state: soft::State::new(key),
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
    fn result(mut self) -> Tag {
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
