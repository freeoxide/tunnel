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

mod common;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use server::drop_server::{DropStore, render_listing};

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_listing");
    for (id, size) in [("render_100_plain", 100usize), ("render_1000_plain", 1000)] {
        let dir = common::build_tree(size);
        let store = DropStore::open(
            dir.path(),
            "bench-token-0000111122223333".to_string(),
            8 * 1024 * 1024,
            1024 * 1024 * 1024,
        )
        .expect("open the bench DropStore");
        let html = render_listing(&store);
        assert_eq!(
            html.matches("<li>").count(),
            common::visible_entries(dir.path()),
            "rendered drop listing must cover every visible entry"
        );
        group.bench_function(id, |b| {
            b.iter(|| black_box(render_listing(black_box(&store))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
