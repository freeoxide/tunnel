// Bench targets build with `--cfg test` but no `--test`: the mirrored
// #[cfg(test)] modules then hold dead tests and dangling imports.
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

mod common;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use server::static_server::render_listing;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("listing");
    for (id, size) in [
        ("render_100_plain", 100usize),
        ("render_1000_plain", 1000),
        ("render_5000_plain", 5000),
    ] {
        let dir = common::build_tree(size);
        let root = dir
            .path()
            .canonicalize()
            .expect("canonicalize the fixture root");
        let html = render_listing(&root, &root).expect("fixture must render a listing");
        assert_eq!(
            html.matches("<li>").count(),
            common::visible_entries(&root),
            "rendered listing must cover every visible entry"
        );
        group.bench_function(id, |b| {
            b.iter(|| black_box(render_listing(black_box(&root), black_box(&root))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
