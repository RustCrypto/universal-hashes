# RustCrypto: Universal Hash Functions ![Rust Version][rustc-image] [![dependency status][deps-image]][deps-link]

Collection of [Universal Hash Functions][1] written in pure Rust.

## Crates

| Name         | Crates.io | Documentation | Build Status |
|--------------|-----------|---------------|--------------|
| [`ghash`]    | [![crates.io](https://img.shields.io/crates/v/ghash.svg)](https://crates.io/crates/ghash) | [![Documentation](https://docs.rs/ghash/badge.svg)](https://docs.rs/ghash) | ![build](https://github.com/RustCrypto/universal-hashes/workflows/ghash/badge.svg?branch=master&event=push) |
| [`poly1305`] | [![crates.io](https://img.shields.io/crates/v/poly1305.svg)](https://crates.io/crates/poly1305) | [![Documentation](https://docs.rs/poly1305/badge.svg)](https://docs.rs/poly1305) | ![build](https://github.com/RustCrypto/universal-hashes/workflows/poly1305/badge.svg?branch=master&event=push) |
| [`polyval`]  | [![crates.io](https://img.shields.io/crates/v/polyval.svg)](https://crates.io/crates/polyval) | [![Documentation](https://docs.rs/polyval/badge.svg)](https://docs.rs/polyval) | ![build](https://github.com/RustCrypto/universal-hashes/workflows/polyval/badge.svg?branch=master&event=push) |

### Minimum Supported Rust Version

All crates in this repository support **Rust 1.49** or higher.

In the future, we reserve the right to change the Minimum Supported Rust
Version, but it will be done with the minor version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the [`universal-hash`][2]
crate.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[rustc-image]: https://img.shields.io/badge/rustc-1.49+-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/universal-hashes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/universal-hashes

[//]: # (crates)

[`ghash`]: https://github.com/RustCrypto/universal-hashes/tree/master/ghash
[`poly1305`]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
[`polyval`]: https://github.com/RustCrypto/universal-hashes/tree/master/polyval

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Universal_hashing
[2]: https://docs.rs/universal-hash
