//! Longer test cases to ensure that long-input optimizations behave correctly.

use hex_literal::hex;
use polyval::{
    BLOCK_SIZE, PolyvalGeneric,
    universal_hash::{KeyInit, Reset, UniversalHash, common::KeySizeUser, typenum::U16},
};

//
// Test vectors for POLYVAL from RFC 8452 Appendix A
// <https://tools.ietf.org/html/rfc8452#appendix-A>
//

const H: [u8; BLOCK_SIZE] = hex!("25629347589242761d31f826ba4b757b");

fn longer_test<Imp>()
where
    Imp: UniversalHash + KeyInit + Reset + Clone + KeySizeUser<KeySize = U16>,
{
    let inp = (1..=4096).map(|n| (n * 47) as u8).collect::<Vec<_>>();

    // Try computing polyval all at once.
    let mut poly = Imp::new(&H.into());
    poly.update_padded(&inp);
    let result1 = poly.finalize_reset();

    // Try computing polyval one block at a time.
    for block in inp.chunks(BLOCK_SIZE) {
        poly.update(&[block.try_into().unwrap()]);
    }
    let result2 = poly.finalize();

    // Make sure the results are the same.
    assert_eq!(result1, result2);
}

#[test]
fn longer_test_x1() {
    longer_test::<PolyvalGeneric<1>>();
}
#[test]
fn longer_test_x2() {
    longer_test::<PolyvalGeneric<2>>();
}
#[test]
fn longer_test_x4() {
    longer_test::<PolyvalGeneric<4>>();
}
#[test]
fn longer_test_x8() {
    longer_test::<PolyvalGeneric<8>>();
}
