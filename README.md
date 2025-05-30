# RustCrypto: Universal Hash Functions

[![Project Chat][chat-image]][chat-link]
![Apache2/MIT licensed][license-image]
[![dependency status][deps-image]][deps-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Collection of [Universal Hash Functions] written in pure Rust.

## Crates

| Name         | Crates.io | Documentation | MSRV |
|--------------|:---------:|:-------------:|:----:|
| [`ghash`]    | [![crates.io](https://img.shields.io/crates/v/ghash.svg)](https://crates.io/crates/ghash) | [![Documentation](https://docs.rs/ghash/badge.svg)](https://docs.rs/ghash) | ![MSRV 1.85][msrv-1.85] |
| [`poly1305`] | [![crates.io](https://img.shields.io/crates/v/poly1305.svg)](https://crates.io/crates/poly1305) | [![Documentation](https://docs.rs/poly1305/badge.svg)](https://docs.rs/poly1305) | ![MSRV 1.85][msrv-1.85] |
| [`polyval`]  | [![crates.io](https://img.shields.io/crates/v/polyval.svg)](https://crates.io/crates/polyval) | [![Documentation](https://docs.rs/polyval/badge.svg)](https://docs.rs/polyval) | ![MSRV 1.85][msrv-1.85] |

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

Universal hash functions have subtle security properties and are primarily intended as a 
building block for constructions like AEAD algorithms.

USE AT YOUR OWN RISK!

## Usage

Crates functionality is expressed in terms of traits defined in the [`universal-hash`] crate.

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

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/channel/260051-universal-hashes
[deps-image]: https://deps.rs/repo/github/RustCrypto/universal-hashes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/universal-hashes
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[msrv-1.85]: https://img.shields.io/badge/rustc-1.85.0+-blue.svg

[//]: # (crates)

[`ghash`]: https://github.com/RustCrypto/universal-hashes/tree/master/ghash
[`poly1305`]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
[`polyval`]: https://github.com/RustCrypto/universal-hashes/tree/master/polyval

[//]: # (footnotes)

[Universal Hash Functions]: https://en.wikipedia.org/wiki/Universal_hashing
[`universal-hash`]: https://docs.rs/universal-hash
