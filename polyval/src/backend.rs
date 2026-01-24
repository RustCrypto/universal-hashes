//! POLYVAL backends

mod soft;

use cpubits::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", not(polyval_backend = "soft")))] {
        mod autodetect;
        mod pmull;
        mod common;

        pub(crate) use autodetect::{FieldElement, InitToken};
        pub use autodetect::DEFAULT_N_BLOCKS;
    } else if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(polyval_backend = "soft")
    ))] {
        mod autodetect;
        mod clmul;
        mod common;

        pub(crate) use autodetect::{FieldElement, InitToken};
        pub use autodetect::DEFAULT_N_BLOCKS;
    } else {
        pub(crate) use soft::FieldElement;
        pub use soft::DEFAULT_N_BLOCKS;

        /// Fake init token (used by feature autodetection) for soft-only scenarios.
        // TODO(tarcieri): compile this out in `soft`-only scenarios
        pub(crate) type InitToken = ();
        pub(crate) fn detect_intrinsics() -> (InitToken, bool) {
            ((), false)
        }
    }
}
