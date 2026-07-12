use agent_ebpf_sensor::normalizer::DataNormalizer;
use agent_ebpf_sensor::rules::{RuleEngine, RuleVerdict};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use neuromesh_common::{SecurityTelemetryEvent, MAX_COMM_LEN, MAX_FILENAME_LEN};
use std::time::Duration;

const BENIGN_PATHS: [&str; 4] = ["/bin/ls", "/bin/cat", "/usr/bin/git", "/usr/bin/bash"];

fn telemetry_event(pid: u32, ppid: u32, path: &str, comm: &str) -> SecurityTelemetryEvent {
    let mut filename = [0u8; MAX_FILENAME_LEN];
    let path_bytes = path.as_bytes();
    filename[..path_bytes.len()].copy_from_slice(path_bytes);

    let mut comm_buf = [0u8; MAX_COMM_LEN];
    let comm_bytes = comm.as_bytes();
    comm_buf[..comm_bytes.len().min(MAX_COMM_LEN)]
        .copy_from_slice(&comm_bytes[..comm_bytes.len().min(MAX_COMM_LEN)]);

    SecurityTelemetryEvent {
        pid,
        ppid,
        uid: 1000,
        euid: 1000,
        comm: comm_buf,
        filename,
    }
}

fn benign_event_vector(count: usize) -> Vec<SecurityTelemetryEvent> {
    (0..count)
        .map(|index| {
            let path = BENIGN_PATHS[index % BENIGN_PATHS.len()];
            telemetry_event(1_000 + index as u32, 1, path, "bench")
        })
        .collect()
}

fn spawn_burst_vector(count: usize, ppid: u32) -> Vec<SecurityTelemetryEvent> {
    (0..count)
        .map(|index| telemetry_event(2_000 + index as u32, ppid, "/usr/bin/bash", "bash"))
        .collect()
}

fn bench_rule_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_engine");
    let engine = RuleEngine::new();
    let events = benign_event_vector(10_000);

    group.throughput(Throughput::Elements(10_000));
    group.bench_function("evaluate_10k_benign_paths", |bencher| {
        bencher.iter(|| {
            for event in &events {
                black_box(engine.evaluate(black_box(event)));
            }
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("evaluate_single_benign_path", |bencher| {
        let event = &events[0];
        bencher.iter(|| black_box(engine.evaluate(black_box(event))));
    });

    group.bench_with_input(
        BenchmarkId::new("evaluate_batch", events.len()),
        &events,
        |bencher, input| {
            bencher.iter(|| {
                let mut suppressed = 0_u64;
                for event in input {
                    if matches!(engine.evaluate(event), RuleVerdict::Suppressed) {
                        suppressed += 1;
                    }
                }
                black_box(suppressed)
            });
        },
    );

    group.finish();
}

fn bench_data_normalizer(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_normalizer");
    let burst_events = spawn_burst_vector(10_000, 4242);

    group.throughput(Throughput::Elements(10_000));
    group.bench_function("ingest_10k_spawn_burst", |bencher| {
        bencher.iter(|| {
            let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 8, 64);
            for event in &burst_events {
                black_box(normalizer.ingest(black_box(event)));
            }
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("ingest_single_spawn_event", |bencher| {
        let event = &burst_events[0];
        bencher.iter(|| {
            let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 8, 64);
            black_box(normalizer.ingest(black_box(event)))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_rule_engine, bench_data_normalizer);
criterion_main!(benches);
