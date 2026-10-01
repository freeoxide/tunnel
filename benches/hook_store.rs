#![allow(dead_code, unused_imports)]

#[path = "../src/cli.rs"]
mod cli;
#[path = "../src/cloudflared.rs"]
mod cloudflared;
#[path = "../src/cmd/mod.rs"]
mod cmd;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/fsutil.rs"]
mod fsutil;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/name.rs"]
mod name;
#[path = "../src/output.rs"]
mod output;
#[path = "../src/port.rs"]
mod port;
#[path = "../src/proc.rs"]
mod proc;
#[path = "../src/registry.rs"]
mod registry;
#[path = "../src/server/mod.rs"]
mod server;
#[path = "../src/spawn.rs"]
mod spawn;
#[path = "../src/state.rs"]
mod state;
#[path = "../src/worker.rs"]
mod worker;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use server::hook_server::{HookLog, RecordedRequest};

fn record_64b(seq: u64) -> RecordedRequest {
    RecordedRequest {
        seq,
        received_at: model::now_utc(),
        method: "POST".to_string(),
        path: "/webhook".to_string(),
        query: None,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: "h".repeat(64),
        body_len: 64,
        truncated: false,
    }
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_store");
    for (id, keep) in [("record_keep_10", 10usize), ("record_keep_1000", 1000usize)] {
        let dir = tempfile::tempdir().expect("tempdir for the hook store");
        let mut log =
            HookLog::load(dir.path().join("requests.json"), keep).expect("load a fresh HookLog");
        let mut seq = 0u64;
        group.bench_function(id, |b| {
            b.iter(|| {
                seq += 1;
                log.record(record_64b(black_box(seq)))
                    .expect("record must persist");
            })
        });
        let on_disk = std::fs::read_to_string(dir.path().join("requests.json"))
            .expect("read the persisted store");
        let parsed: Vec<RecordedRequest> =
            serde_json::from_str(&on_disk).expect("the persisted store must parse");
        assert_eq!(parsed.len(), keep, "retention must cap the store at keep");
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
