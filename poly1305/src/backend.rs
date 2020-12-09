//! Poly1305 backends

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(feature = "force-soft")
))]
pub(crate) mod avx2;

pub(crate) mod soft;
