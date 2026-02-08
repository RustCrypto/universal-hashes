mod soft;

cpubits::cfg_if! {
    if #[cfg(all(target_arch = "aarch64", not(polyval_backend = "soft")))] {
        // PMULL/NEON backend for aarch64
        mod autodetect;
        mod neon;
        pub(crate) use autodetect::State;
        pub(crate) use neon::InitToken;
    } else if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(polyval_backend = "soft")
    ))] {
        // CLMUL/AVX2 backend for x86/x86-64
        mod autodetect;
        mod avx2;
        pub(crate) use autodetect::State;
        pub(crate) use avx2::InitToken;
    } else {
        // "soft" pure Rust portable fallback implementation for other targets
        pub(crate) use soft::{State, InitToken};
    }
}
