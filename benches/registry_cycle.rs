// Benches build with `--cfg test` but no `--test`: the mirrored #[cfg(test)]
// modules compile while their #[test] fns stay dead, tripping both allows.
#![allow(dead_code, unused_imports)]

// Bin-only crate — a bench cannot link it, so this mirrors the src/main.rs
// module tree via #[path]; that is what keeps `crate::` paths resolving.
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

use model::{Registry, Service, ServiceKind};

fn service(id: u64) -> Service {
    let port = 20_000 + (id % 20_000) as u16;
    Service {
        id,
        name: format!("bench-svc-{id:05}"),
        kind: ServiceKind::Proxy,
        dir: None,
        port,
        local_url: format!("http://127.0.0.1:{port}"),
        public_url: Some(format!("https://bench-{id}.trycloudflare.com")),
        worker_pid: 123_456,
        tunnel_pid: None,
        static_flags: Default::default(),
        command_pid: None,
        created_at: model::now_utc(),
        state_dir: std::path::PathBuf::from("/tmp/bench-state"),
        foreground: false,
    }
}

fn fixture(n: usize) -> (tempfile::TempDir, state::StateDir) {
    let dir = tempfile::tempdir().expect("tempdir for the registry state");
    let state = state::StateDir::new_at(dir.path().join("ft-state"));
    state.ensure().expect("ensure the bench state dir");
    let mut reg = Registry::default();
    for id in 1..=n as u64 {
        reg.services.push(service(id));
    }
    reg.next_id = n as u64 + 1;
    reg.save(&state).expect("seed the fixture registry");
    (dir, state)
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry_cycle");
    for (id, n) in [
        ("load_parse_100", 100usize),
        ("load_parse_1000", 1000),
        ("load_parse_5000", 5000),
    ] {
        let dir = fixture(n);
        let state = &dir.1;
        assert_eq!(
            Registry::load(state).expect("sanity load").services.len(),
            n,
            "fixture must round-trip its service count"
        );
        group.bench_function(id, |b| {
            b.iter(|| black_box(Registry::load(black_box(state)).expect("load")))
        });
    }
    {
        let dir = fixture(1000);
        let state = &dir.1;
        group.bench_function("update_1000", |b| {
            b.iter(|| {
                black_box(
                    Registry::update(black_box(state), |reg| reg.allocate_id())
                        .expect("update cycle"),
                )
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
