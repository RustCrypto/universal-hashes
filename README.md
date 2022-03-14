# RustCrypto: Universal Hash Functions

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]

Collection of [Universal Hash Functions][1] (UHF) written in pure Rust.

## Crates

| Algorithm  | Crate        | Crates.io | Documentation | MSRV |
|------------|--------------|:---------:|:-------------:|:----:|
| [GHASH]    | [`ghash`]    | [![crates.io](https://img.shields.io/crates/v/ghash.svg)](https://crates.io/crates/ghash) | [![Documentation](https://docs.rs/ghash/badge.svg)](https://docs.rs/ghash) | ![MSRV 1.56][msrv-1.56] |
| [Poly1305] | [`poly1305`] | [![crates.io](https://img.shields.io/crates/v/poly1305.svg)](https://crates.io/crates/poly1305) | [![Documentation](https://docs.rs/poly1305/badge.svg)](https://docs.rs/poly1305) | ![MSRV 1.56][msrv-1.56] |
| [POLYVAL]  | [`polyval`]  | [![crates.io](https://img.shields.io/crates/v/polyval.svg)](https://crates.io/crates/polyval) | [![Documentation](https://docs.rs/polyval/badge.svg)](https://docs.rs/polyval) | ![MSRV 1.56][msrv-1.56] |

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the [`universal-hash`] crate.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260051-universal-hashes
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/universal-hashes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/universal-hashes
[msrv-1.56]: https://img.shields.io/badge/rustc-1.56+-blue.svg

[//]: # (crates)

[`ghash`]: ./ghash
[`poly1305`]: ./poly1305
[`polyval`]: ./polyval

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Universal_hashing
[`universal-hash`]: https://docs.rs/universal-hash

[//]: # (algorithms)

[GHASH]: https://en.wikipedia.org/wiki/Galois/Counter_Mode#Mathematical_basis
[Poly1305]: https://en.wikipedia.org/wiki/Poly1305
[POLYVAL]: https://datatracker.ietf.org/doc/html/rfc8452#section-3
