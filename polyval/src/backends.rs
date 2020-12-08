//! POLYVAL backends

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    ))] {
        mod clmul;
        pub use self::clmul::Polyval;
    } else {
        #[cfg_attr(not(target_pointer_width = "64"), path = "backends/soft32.rs")]
        #[cfg_attr(target_pointer_width = "64", path = "backends/soft64.rs")]
        mod soft;
        pub use self::soft::Polyval;
    }
}
