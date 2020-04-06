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
