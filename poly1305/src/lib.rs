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
    leftover: usize,
    buffer: Block,
}

impl UniversalHash for Poly1305 {
    type KeySize = U32;
    type BlockSize = U16;

    /// Initialize Poly1305 with the given key
    fn new(key: &GenericArray<u8, U32>) -> Poly1305 {
        Poly1305 {
            state: soft::Poly1305State::new(key),
            leftover: 0,
            buffer: Block::default(),
        }
    }

    /// Input data into the Poly1305 universal hash function
    fn update_block(&mut self, block: &GenericArray<u8, U16>) {
        // TODO(tarcieri): pass block directly to `Poly1305State::compute_block`
        self.update(block.as_slice());
    }

    /// Reset internal state
    fn reset(&mut self) {
        self.state.reset();
        self.buffer = Default::default();
        self.leftover = 0;
    }

    /// Get the hashed output
    fn result(self) -> Tag {
        self.state.finalize(&self.buffer[..self.leftover])
    }
}

impl Poly1305 {
    /// Input data into the Poly1305 universal hash function
    pub fn update(&mut self, data: &[u8]) {
        let mut m = data;

        if self.leftover > 0 {
            let want = min(16 - self.leftover, m.len());

            self.buffer[self.leftover..self.leftover + want].copy_from_slice(&m[..want]);
            m = &m[want..];
            self.leftover += want;

            if self.leftover < BLOCK_SIZE {
                return;
            }

            self.state.compute_block(&self.buffer, false);
            self.leftover = 0;
        }

        while m.len() >= BLOCK_SIZE {
            self.state.compute_block(&m[..BLOCK_SIZE], false);
            m = &m[BLOCK_SIZE..];
        }

        self.buffer[..m.len()].copy_from_slice(m);
        self.leftover = m.len();
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
