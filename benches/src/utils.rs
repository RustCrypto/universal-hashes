use criterion::Criterion;

#[cfg(not(feature = "cpb"))]
pub type Benchmarker = Criterion;

#[cfg(feature = "cpb")]
pub type Benchmarker = Criterion<criterion_cycles_per_byte::CyclesPerByte>;

#[cfg(not(feature = "cpb"))]
pub fn config() -> Benchmarker {
    Criterion::default()
}

#[cfg(feature = "cpb")]
pub fn config() -> Benchmarker {
    Criterion::default().with_measurement(criterion_cycles_per_byte::CyclesPerByte)
}
