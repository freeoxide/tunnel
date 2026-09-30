//! Criterion benches for the drop bucket's listing render
//! (`server::drop_server::render_listing`) — read-dir + canonicalize +
//! metadata + format over a `DropStore`, measured pure. Same tree shape as
//! the static listing benches (`common::build_tree`), built once per size
//! outside the measured closure.

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

mod common;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use server::drop_server::{DropStore, render_listing};

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_listing");
    for (id, size) in [("render_100_plain", 100usize), ("render_1000_plain", 1000)] {
        let dir = common::build_tree(size);
        // Generous caps: `open` only measures the tree against them, and the
        // bench must never be cap-bound — it measures the render, not upload
        // accounting.
        let store = DropStore::open(
            dir.path(),
            "bench-token-0000111122223333".to_string(),
            8 * 1024 * 1024,
            1024 * 1024 * 1024,
        )
        .expect("open the bench DropStore");
        // Verify the work actually happened (measurement hygiene): one render
        // outside the timer must list every visible top-level entry (an empty
        // store would print a single "(nothing uploaded yet)" row).
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
