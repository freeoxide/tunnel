use std::path::Path;

use tempfile::TempDir;

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

const DOTFILES: &[&str] = &[".gitignore", ".env", ".DS_Store"];

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

pub fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..len).map(|_| (rng.below(251) as u8) + b' ').collect()
}

fn file_name(i: usize) -> String {
    let base = FILE_NAMES[i % FILE_NAMES.len()];
    if i < FILE_NAMES.len() {
        base.to_string()
    } else {
        let (stem, ext) = base.rsplit_once('.').unwrap_or((base, ""));
        format!("{stem}-{i:04}.{ext}")
    }
}

fn dir_name(i: usize) -> String {
    let base = DIR_NAMES[i % DIR_NAMES.len()];
    if i < DIR_NAMES.len() {
        base.to_string()
    } else {
        format!("{base}-{i:04}")
    }
}

/// Tempdir with exactly `entries` visible top-level entries (hidden dotfiles
/// on top). Same `entries` → the same tree, every run.
pub fn build_tree(entries: usize) -> TempDir {
    let dir = TempDir::new().expect("tempdir for the served tree");
    let root = dir.path();
    let mut rng = Rng(0x5eed_1234);
    for i in 0..entries {
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

pub fn visible_entries(root: &Path) -> usize {
    std::fs::read_dir(root)
        .expect("read fixture root")
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .count()
}
