//! POLYVAL benchmarks.
use criterion::{criterion_group, criterion_main, BenchmarkId, Throughput};
use polyval::{universal_hash::UniversalHash, Polyval};

mod utils;
use utils::{config, Benchmarker};

fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("polyval");

    for size in &[10, 100, 1000, 10000] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("update_padded", size), |b| {
            let mut polyval = Polyval::new(&Default::default());
            b.iter(|| polyval.update_padded(&buf));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = config();
    targets = bench
);

criterion_main!(benches);
