//! Throughput of the detectors against libinjectionrs over the corpora.
//! Run with `cargo bench -p openshield-injection --bench detect`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use openshield_injection::testdata::samples;
use openshield_injection::{detect_sqli, detect_xss};

type Detect = fn(&[u8]) -> bool;

fn bench(c: &mut Criterion) {
    let detectors: [(&str, Detect, Detect); 2] = [
        (
            "xss",
            |i| detect_xss(i).is_some(),
            |i| libinjectionrs::detect_xss(i).is_injection(),
        ),
        (
            "sqli",
            |i| detect_sqli(i).is_some(),
            |i| libinjectionrs::detect_sqli(i).is_injection(),
        ),
    ];
    for (name, ours, theirs) in detectors {
        for kind in ["positive", "negative"] {
            let inputs: Vec<Vec<u8>> = samples(&format!("{name}/{kind}"))
                .into_iter()
                .map(|s| s.input)
                .collect();
            let bytes: usize = inputs.iter().map(Vec::len).sum();
            let mut group = c.benchmark_group(format!("detect_{name}"));
            group.throughput(Throughput::Bytes(bytes as u64));
            group.bench_with_input(
                BenchmarkId::new("openshield", kind),
                &inputs,
                |b, inputs| b.iter(|| inputs.iter().filter(|i| ours(black_box(i))).count()),
            );
            group.bench_with_input(
                BenchmarkId::new("libinjectionrs", kind),
                &inputs,
                |b, inputs| b.iter(|| inputs.iter().filter(|i| theirs(black_box(i))).count()),
            );
            group.finish();
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
