//! Shared fixtures for the criterion benches: the served-tree builder. The
//! bench files pull this in via `mod common;` (each bench compiles the
//! crate's own module tree at its root — the crate is bin-only, so there is
//! no library for benches to link against).

use std::path::Path;

use tempfile::TempDir;

/// Realistic top-level file names, cycled with disambiguating numeric
/// suffixes once the pool is exhausted. `index.html` is deliberately ABSENT
/// from the pool: a root index hands the request to `ServeDir`, and these
/// trees exist to exercise the listing render.
const FILE_NAMES: &[&str] = &[
    "README.md",
    "CHANGELOG.md",
    "Cargo.toml",
    "main.rs",
    "lib.rs",
    "utils.rs",
    "app.js",
    "style.css",
    "schema.sql",
    "notes.txt",
    "todo.txt",
    "logo.png",
    "banner.jpg",
    "report-2026-q3.pdf",
    "budget-draft.xlsx",
    "photo_01.jpg",
    "photo_02.jpg",
    "data.csv",
    "config.yaml",
    "Dockerfile",
    "Makefile",
    "LICENSE",
    "install.sh",
    "migration_0001.sql",
];

/// Realistic subdirectory names, cycled the same way.
const DIR_NAMES: &[&str] = &[
    "src",
    "docs",
    "tests",
    "assets",
    "examples",
    "scripts",
    "build",
    "images",
    "data",
    "migrations",
    "target",
    "vendor",
];

/// Dotfiles planted at the root: the listing must hide them, and their
/// presence keeps the entry loop honest (skip-path work per render).
const DOTFILES: &[&str] = &[".gitignore", ".env", ".DS_Store"];

/// Deterministic LCG — every run builds the byte-identical tree shape.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// `len` pseudo-random bytes (seeded), so file contents are stable per tree.
pub fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..len).map(|_| (rng.below(251) as u8) + b' ').collect()
}

/// Unique per pool position: the bare name for the first cycle, then a
/// numeric suffix (extension preserved) once the pool wraps.
fn file_name(i: usize) -> String {
    let base = FILE_NAMES[i % FILE_NAMES.len()];
    if i < FILE_NAMES.len() {
        base.to_string()
    } else {
        let (stem, ext) = base.rsplit_once('.').unwrap_or((base, ""));
        format!("{stem}-{i:04}.{ext}")
    }
}

/// Directory counterpart of [`file_name`].
fn dir_name(i: usize) -> String {
    let base = DIR_NAMES[i % DIR_NAMES.len()];
    if i < DIR_NAMES.len() {
        base.to_string()
    } else {
        format!("{base}-{i:04}")
    }
}

/// A symlink-free tempdir tree with exactly `entries` VISIBLE top-level
/// entries — a realistic mix of plain files (small deterministic contents)
/// and subdirectories (every 4th entry; each holds 2–4 plain files), plus a
/// few dotfiles the listing must hide. Deterministic, so bench fixtures are
/// comparable run-to-run. Built ONCE per fixture, outside measured closures.
pub fn build_tree(entries: usize) -> TempDir {
    let dir = TempDir::new().expect("tempdir for the served tree");
    let root = dir.path();
    let mut rng = Rng(0x5eed_1234);
    for i in 0..entries {
        // Every 4th entry a subdirectory (~25% of the tree).
        if i % 4 == 3 {
            let sub = root.join(dir_name(i / 4));
            std::fs::create_dir_all(&sub).expect("mkdir fixture subdirectory");
            let nested = 2 + rng.below(3);
            for j in 0..nested {
                let path = sub.join(format!("page-{j:02}.txt"));
                let len = 120 + rng.below(1_800) as usize;
                std::fs::write(&path, content(len, rng.next())).expect("write nested file");
            }
        } else {
            let path = root.join(file_name(i));
            let len = 120 + rng.below(1_800) as usize;
            std::fs::write(&path, content(len, rng.next())).expect("write fixture file");
        }
    }
    for dot in DOTFILES {
        std::fs::write(root.join(dot), b"fixture dotfile\n").expect("write dotfile");
    }
    dir
}

/// Count of non-dot top-level entries — the sanity check for "the render
/// listed the whole tree" (dotfiles are hidden by design).
pub fn visible_entries(root: &Path) -> usize {
    std::fs::read_dir(root)
        .expect("read fixture root")
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .count()
}
