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

use core::cmp::min;
use universal_hash::generic_array::{
    typenum::{U16, U32},
    GenericArray,
};
use universal_hash::{Output, UniversalHash};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

mod soft;

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

/// The Poly1305 universal hash function.
///
/// Note that Poly1305 is not a traditional MAC and is single-use only
/// (a.k.a. "one-time authenticator").
///
/// For this reason it doesn't impl the `crypto_mac::Mac` trait.
#[derive(Clone)]
pub struct Poly1305 {
    state: soft::Poly1305State,
    buffer: Block,
    filled: usize,
}

impl UniversalHash for Poly1305 {
    type KeySize = U32;
    type BlockSize = U16;

    /// Initialize Poly1305 with the given key
    fn new(key: &GenericArray<u8, U32>) -> Poly1305 {
        Poly1305 {
            state: soft::Poly1305State::new(key),
            buffer: Block::default(),
            filled: 0,
        }
    }

    /// Input data into the Poly1305 universal hash function
    fn update_block(&mut self, block: &GenericArray<u8, U16>) {
        if self.filled > 0 {
            // We have a partial block that needs processing.
            self.update(block.as_slice());
        } else {
            // Pass this block directly to `Poly1305State::compute_block`.
            self.state.compute_block(block.as_slice());
        }
    }

    /// Reset internal state
    fn reset(&mut self) {
        self.state.reset();
        self.buffer = Default::default();
        self.filled = 0;
    }

    /// Get the hashed output
    fn result(mut self) -> Tag {
        self.state.finalize(&self.buffer[..self.filled])
    }
}

impl Poly1305 {
    /// Input data into the Poly1305 universal hash function
    pub fn update(&mut self, mut data: &[u8]) {
        // Handle partially-filled buffer from a previous update
        if self.filled > 0 {
            let want = min(BLOCK_SIZE - self.filled, data.len());

            self.buffer[self.filled..self.filled + want].copy_from_slice(&data[..want]);
            data = &data[want..];
            self.filled += want;

            if self.filled < BLOCK_SIZE {
                return;
            }

            self.state.compute_block(&self.buffer);
            self.filled = 0;
        }

        while data.len() >= BLOCK_SIZE {
            self.state.compute_block(&data[..BLOCK_SIZE]);
            data = &data[BLOCK_SIZE..];
        }

        self.buffer[..data.len()].copy_from_slice(data);
        self.filled = data.len();
    }

    /// Process input messages in a chained manner
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}
