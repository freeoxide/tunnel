//! Criterion benches for the registry's on-disk cycle: `Registry::load`
//! (bounded read + JSON parse + validate) at 100/1000/5000 services, and one
//! full `Registry::update` cycle at the 1000-service fixture — flock acquire,
//! load, mutate, and `save`'s durable path (temp write + fsync, `.bak`
//! promotion, rename, parent-dir fsync) included.

// The crate is bin-only (no lib target), so a bench cannot link it as a
// library; instead each bench compiles the SAME module tree into its own
// crate via #[path], mirroring the declarations in src/main.rs. That is also
// what keeps the modules' internal `crate::` paths resolving.
// cargo builds bench targets with `--cfg test` (but no `--test`), so the
// mirrored tree's #[cfg(test)] modules compile while their #[test] fns stay
// dead — dead_code alone would leave their imports dangling into
// unused_imports warnings. Both allows exist only for that fallout.
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

use model::{Registry, Service, ServiceKind};

/// A minimal valid service — Proxy kind (no directory to materialize), on a
/// dead-looking high port, `public_url` set like a live Running entry.
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

/// A tempdir state dir holding a saved registry of `n` services, built once
/// per bench outside the measured closure.
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
        // Verify the work actually happened (measurement hygiene): the
        // fixture must load back with every seeded service.
        assert_eq!(
            Registry::load(state).expect("sanity load").services.len(),
            n,
            "fixture must round-trip its service count"
        );
        group.bench_function(id, |b| {
            b.iter(|| black_box(Registry::load(black_box(state)).expect("load")))
        });
    }
    // The one full update cycle, at the mid fixture: flock + load + mutate +
    // durable save. The mutation advances `next_id` only, so the registry
    // stays a constant n across iterations (a growing one would skew late
    // samples) while the whole write path still runs.
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
