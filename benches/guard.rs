// Cargo builds bench targets with `--cfg test` but no `--test`, so the
// mirrored #[test] fns compile dead and their imports dangle into warnings.
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

use axum::body::Body;
use axum::http::{Request, StatusCode};
use criterion::{Criterion, criterion_group, criterion_main};
use tower::ServiceExt;

const FILE_PATH: &str = "/bench-file.txt";
const FILE_LEN: usize = 32 * 1024;

fn bench(c: &mut Criterion) {
    let dir = common::build_tree(50);
    std::fs::write(
        dir.path().join("bench-file.txt"),
        common::content(FILE_LEN, 0xC0FFEE),
    )
    .expect("write the benched file");
    let root = dir
        .path()
        .canonicalize()
        .expect("canonicalize the fixture root");
    let router = server::static_server::router_with(root, model::StaticFlags::default());
    // ONE runtime for every iteration (and for the sanity GET below): thread
    // spawn and reactor setup are not part of the measured work.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build the bench runtime");

    {
        let req = Request::builder()
            .method("GET")
            .uri(FILE_PATH)
            .body(Body::empty())
            .expect("build the sanity request");
        let resp = rt
            .block_on(router.clone().oneshot(req))
            .expect("oneshot is infallible");
        assert_eq!(resp.status(), StatusCode::OK, "the bench file must serve");
        let bytes = rt
            .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
            .expect("read the sanity body");
        assert_eq!(bytes.len(), FILE_LEN, "the whole file must come back");
    }

    let mut group = c.benchmark_group("guard");
    group.bench_function("get_file", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = Request::builder()
                    .method("GET")
                    .uri(FILE_PATH)
                    .body(Body::empty())
                    .expect("build the benched request");
                let resp = router
                    .clone()
                    .oneshot(req)
                    .await
                    .expect("oneshot is infallible");
                let status = resp.status();
                // Drain the body inside the timer: a GET is not done until
                // the last byte is out.
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .expect("read the benched body");
                black_box((status, bytes.len()))
            })
        })
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
