//! Poly1305 backends

cfg_if::cfg_if! {
    if #[cfg(poly1305_backend = "soft")] {
        mod soft;
        pub(crate) use soft::State;
    } else if #[cfg(target_arch = "aarch64")] {
        mod neon;
        mod simd;
        pub(crate) use simd::State;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod autodetect;
        mod avx2;
        mod simd;
        pub(crate) use autodetect::State;
    } else {
        mod soft;
        pub(crate) use soft::State;
    }
}
