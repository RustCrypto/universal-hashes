//! POLYVAL backends

mod soft;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", not(polyval_force_soft)))] {
        mod autodetect;
        mod pmull;
        mod common;
        pub use crate::backend::autodetect::Polyval as PolyvalGeneric;
    } else if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(polyval_force_soft)
    ))] {
        mod autodetect;
        mod clmul;
        mod common;
        pub use crate::backend::autodetect::Polyval as PolyvalGeneric;
    } else {
        pub use crate::backend::soft::Polyval as PolyvalGeneric;
    }
}

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
//
// We have to define a type alias here, or existing code will break.
pub type Polyval = PolyvalGeneric<8>;
