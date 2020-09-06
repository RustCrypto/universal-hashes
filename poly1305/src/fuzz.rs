use super::fuzz_avx2;

fn avx2_fuzzer_test_case(data: &[u8]) {
    fuzz_avx2(data[0..32].into(), &data[32..]);
}

#[test]
fn crash_0() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000000,sig:06,src:000014,op:flip4,pos:11"
    ));
}

#[test]
fn crash_1() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000001,sig:06,src:000006+000014,op:splice,rep:64"
    ));
}

#[test]
fn crash_2() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000002,sig:06,src:000008+000014,op:splice,rep:32"
    ));
}

#[test]
fn crash_3() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000003,sig:06,src:000003,op:havoc,rep:64"
    ));
}

#[test]
fn crash_4() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000004,sig:06,src:000022+000005,op:splice,rep:32"
    ));
}

#[test]
fn crash_5() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000005,sig:06,src:000008+000007,op:splice,rep:128"
    ));
}

#[test]
fn crash_6() {
    // This input corresponds to a key of:
    //     r = 0x04040404040404040404040404040404
    //     s = 0x0404040403ef04040404040404040404
    //
    // and input:
    //     [0x04, 0x04, 0x04, 0xf2]
    //
    // The input fits into a single short block:
    //     m = 0x01f2040404
    //
    // and we should have the following computation:
    //     tag = ((m * r) % p) + s
    //         = ((0x01f2040404 * 0x04040404040404040404040404040404) % p) + s
    //         = (0x7cfdfeffffffffffffffffffffffffff8302010 % ((1 << 130) - 5)) + s
    //         = 0x1f3f7fc + 0x0404040403ef04040404040404040404
    //         = 0x0404040403ef04040404040405f7fc00
    //
    // or in bytes:
    //     tag = [
    //         0x00, 0xfc, 0xf7, 0x05, 0x04, 0x04, 0x04, 0x04,
    //         0x04, 0x04, 0xef, 0x03, 0x04, 0x04, 0x04, 0x04,
    //     ];
    //
    // The crash was caused by the final modular reduction (in the `addkey` method of the
    // Goll-Gueron implementation, and `impl Add<Aligned130> for AdditionKey` here) not
    // fully carrying all bits. `Aligned130` is guaranteed to be a 130-bit integer, but is
    // not guaranteed to be an integer modulo 2^130 - 5.
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000006,sig:06,src:000005,op:havoc,rep:8"
    ));
}

#[test]
fn crash_7() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id:000007,sig:06,src:000024+000000,op:splice,rep:64"
    ));
}
