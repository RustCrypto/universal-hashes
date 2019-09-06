#[macro_use]
extern crate hex_literal;

#[cfg(feature = "ghash")]
use polyval::GHash;
use polyval::{universal_hash::UniversalHash, Polyval};

//
// Test vectors for POLYVAL from RFC 8452 Appendix A
// <https://tools.ietf.org/html/rfc8452#appendix-A>
//

const H: [u8; 16] = hex!("25629347589242761d31f826ba4b757b");
const X_1: [u8; 16] = hex!("4f4f95668c83dfb6401762bb2d01a262");
const X_2: [u8; 16] = hex!("d1a24ddd2721d006bbe45f20d3c9f362");

/// POLYVAL(H, X_1, X_2)
const POLYVAL_RESULT: [u8; 16] = hex!("f7a3b47b846119fae5b7866cf5e5b77e");

/// GHASH(H, X_1, X_2)
#[cfg(feature = "ghash")]
const GHASH_RESULT: [u8; 16] = hex!("bd9b3997046731fb96251b91f9c99d7a");

#[test]
fn polyval_test_vector() {
    let mut poly = Polyval::new(&H.into());
    poly.update_block(&X_1.into());
    poly.update_block(&X_2.into());

    let result = poly.result();
    assert_eq!(&POLYVAL_RESULT[..], result.into_bytes().as_slice());
}

#[cfg(feature = "ghash")]
#[test]
fn ghash_test_vector() {
    let mut ghash = GHash::new(&H.into());
    ghash.update_block(&X_1.into());
    ghash.update_block(&X_2.into());

    let result = ghash.result();
    assert_eq!(&GHASH_RESULT[..], result.into_bytes().as_slice());
}
