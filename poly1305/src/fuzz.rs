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
    // This input corresponds to a key of:
    //     r = 0x0f245bfc0f7fe5fc0fffff3400fb1c2b
    //     s = 0xffffff000001000040f6fff5ffffffff
    //
    // and input blocks:
    //    [0x01ea0010000a00ff108b72ffffffffffff, 0x01ffffffff245b74ff7fe5ffffff0040ff,
    //     0x01000a00ff108b7200ff04000002ffffff, 0x01ffffffffffffffffffff0000ffea0010,
    //     0x0180ffffffffffffffffffffffe3ffffff, 0x01ffffffffffffffffffffffffffffffff,
    //     0x01ffffffffffffffffffdfffff03ffffff, 0x01ffffffffff245b74ff7fe5ffffe4ffff,
    //     0x0112118b7d00ffeaffffffffffffffffff, 0x010e40eb10ffffffff1edd7f0010000a00]
    //
    // When this crash occurred, the software and AVX2 backends would generate the same
    // tags given the first seven blocks as input. Given the first eight blocks, the
    // following tags were generated:
    //
    //      |                                tag     |  low 128 bits of final accumulator
    // soft | 0x0004d01b9168ded528a9b541cc461988 - s = 0x0004d11b9167ded4e7b2b54bcc461989
    // avx2 | 0x0004d01b9168ded528a9b540cc461988 - s = 0x0004d11b9167ded4e7b2b54acc461989
    //                 difference = 0x0100000000
    //
    // This discrepancy was due to Unreduced130::reduce (as called during finalization)
    // not correctly reducing. TODO: Figure out what about it was wrong.
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
