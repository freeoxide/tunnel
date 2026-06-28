# Freeoxide Tunnel (`ft`) — Deep Architecture, Security & Best-Practices Audit + Remediation Plan

**Scope:** whole codebase (24 source files + CI). **Date:** 2026-06-28.
**Method:** (1) full read of every source file; (2) a dynamic multi-agent workflow of **68 agents / ~1.8M tokens** — 8 independent deep auditors (architecture, axum-HTTP, static-serving-security, async/process-safety, security-process-fs, rust-best-practices, testing/CI, observability/resilience) → **adversarial verification of every finding** (each re-read from source, bias-to-refute) → a **completeness critic**; (3) local compiler/test evidence (`cargo fmt`, `clippy`, `test`, `tree`); (4) first-principles confirmation of the highest-stakes items directly against `tower-http` 0.7 source.

**Headline:** The codebase is unusually well-structured and well-commented for its size, and prior adversarial-review passes already fixed the obvious registry/process bugs. The remaining issues cluster into **one genuine Critical (public symlink exfiltration)**, **a handful of Major lifecycle/resilience/security gaps**, and a long tail of Minor hardening and **a systemic testing gap (the entire async/HTTP/process surface is untested)**. None require a rewrite; all are tractable.

---

## 0. Verified baseline (real evidence)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | ✅ clean |
| `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo test --all` | ✅ 36/36 — **all pure-function unit tests** (`extract_url`, `name`, `registry`, `safe_component`, `status`) |
| Toolchain | rustc 1.96, edition **2024** |
| `rust-version` (MSRV) in `Cargo.toml` | ❌ **unset** |
| Supply-chain tooling | ❌ `cargo-audit` / `cargo-deny` **not installed**; **126** transitive deps, 17 direct |
| Async/HTTP/process/worker tests | ❌ **zero** (`grep tokio::test` → nothing; no `tests/` dir) |

---

## 1. Architecture assessment

### Strengths
- **Clean layering:** a frozen core (`model`, `registry`, `state`, `port`, `name`, `proc`) with cohesive single-responsibility leaf modules, a thin `cmd` dispatch layer, and a separate `worker`/`spawn`/`cloudflared`/`static_server` runtime. `main.rs` is minimal and correct.
- **Correct concurrency primitives:** `Registry::update` serializes all mutations under an exclusive `flock` held across the whole load→modify→save, with **atomic save** (temp + rename). This is the load-bearing invariant and it is sound.
- **Sound process-tree teardown:** `worker` `setsid()`s into its own session/pgid; `cloudflared` deliberately *joins* the worker's group (no `setsid`), so `kill(-worker_pid)` reaches the whole tree. `pid_matches` reads `/proc/<pid>/cmdline` before signaling, defeating PID reuse in the common case.
- **Defense-in-depth already present:** loopback-only bind, `safe_component` path-confined service dirs, `extract_url` host allowlist, atomic registry commit.
- **Edition-2024 idioms used well** (`let`-chains in `worker.rs`/`start.rs`), `anyhow` context at call sites, graceful shutdown with bounded drain.

### Seams (the architecture tax of the next maintainer / the "non-static services" roadmap)
1. **Duplicated, divergent teardown logic** — the SIGTERM→grace→SIGKILL→drain→abort sequence exists in *both* `worker.rs` and `start.rs::run_foreground`, and they have already diverged (foreground never `SIGKILL`s cloudflared, never reaps it).
2. **`Service` is a heuristic, not a state machine** — `status()` is *derived* from `(pid_alive, public_url)` + a `worker_pid==0` special case, probed per-row via `/proc`, instead of a recorded lifecycle the worker transitions.
3. **`ServiceKind` has one variant and is never read** — the type model is already hostile to the stated "proxy a local port" goal (needs a tagged union), yet today `kind` is dead.
4. **Leaky interfaces:** `cloudflared::spawn(port, _tunnel_log)` ignores its 2nd arg while both callers compute a real value; the worker is spawned with `--id` but looks itself up *by name*, so `--id` is decorative.
5. **`error.rs` is a bare `anyhow` alias** with no split between user-facing messages and internal error chains (and `cmd/mod.rs` even imports `anyhow::Result` directly instead of the canonical `crate::error::Result`).
6. **`serve()` hard-codes a Ctrl-C handler**, forcing every caller to reverse-engineer an opinionated shutdown protocol.
7. **CLI foot-gun:** `ft ls` silently STARTs a tunnel if a directory named `ls` exists (clap subcommand-vs-positional fall-through).

---

## 2. Findings (adversarially verified)

Severity = the verifier's *corrected* severity. Every item below was independently re-read from the current source; 4 candidate findings were **refuted and dropped** (§3).

### 🔴 CRITICAL (1)

**C1. `ServeDir` follows symlinks → a symlink inside the served dir exfiltrates arbitrary files to the public tunnel.**
`src/static_server.rs:21-29`. Verified against `tower-http-0.7.0` source: `build_and_validate_path` (`serve_dir/mod.rs:530-573`) blocks literal `..` (rejects `Component::ParentDir`), but performs **no symlink check** — it builds the path from `Normal` components then calls `tokio::fs::File::open`/`metadata` (`backend.rs:81,87`), which follow symlinks via the OS. `resolve_dir` uses `std::path::absolute` (**not** `canonicalize`), so neither the root nor in-tree links are resolved. Net effect: `ft ~/proj` where `proj/link -> ~/.ssh/id_rsa` (or `/etc/passwd`, `~/.aws/credentials`) serves that target to a **global, unauthenticated** `*.trycloudflare.com` URL. *This is the central risk of a public-exposure tool.*

### 🟠 MAJOR (8)

**M1. Reserve→spawn→record window lets a concurrent `ft kill` delete the entry while the detached worker keeps running (orphaned worker leak).**
`src/cmd/start.rs:117-142`. The entry is reserved with `worker_pid=0` in one locked update (117), the worker is spawned (126), and the real pid is recorded in a *separate* update (138-142). In that window a concurrent `ft kill` sees `worker_pid=0`, `pid_matches(0,…)` is false → it removes the (apparently stale) entry, but the freshly-spawned worker is already running and now orphaned (no registry entry, never cleaned up).

**M2. The "abort fallback" does not cancel in-flight connections — graceful-shutdown drain is effectively unbounded.**
`src/static_server.rs:54-63` (+ `worker.rs:201-213`, `start.rs:247-256`). In axum 0.8 each connection is a detached `tokio::spawn` task; `WithGracefulShutdown` drains by waiting on a watch channel that only closes once *all* per-connection tasks finish — it has **no built-in drain timeout**. The code's `timeout(3s, server_handle).await` then `server_handle.abort()` drops the serve-loop `JoinHandle` but **leaves the connection tasks running**, so a stuck request still pins the worker/foreground past the 3s bound. Combined with M3, a single slow request (proxied publicly via cloudflared) can pin the server indefinitely.

**M3. No request/body/keep-alive timeout (`TimeoutLayer`) — slowloris exposure via cloudflared.**
`src/static_server.rs:26-29`. `router()` stacks only `TraceLayer`. axum 0.8 `serve()` configures no http1/http2/keep-alive/request timeout. Because cloudflared exposes this loopback server publicly, a slow/stalled public client can tie up connections. *(Also the clean fix for M2.)*

**M4. No prune/reconcile path — stale entries and orphaned cloudflared persist forever after reboot/crash.**
`src/cmd/list.rs:12-17`, `model.rs:67-82`, `kill.rs:19-65`. After a reboot/OOM, `status()` correctly marks entries *Stale*, but nothing ever removes them. There is no `ft prune`, no startup reconcile; `ft kill <stale>` removes the entry but (correctly) does not signal a dead pid — and a recycled pid holding a recorded `tunnel_pid` is never cleaned.

**M5. `registry.json`, `server.log`, `worker.log`, `tunnel.log` created world-readable (0644) — leaking request URIs and local paths on multi-user hosts.**
`src/registry.rs:62-71` (+ all log opens). Plain `OpenOptions`/`fs::write` → process-umask default (0644). On a shared host any local user can read: `registry.json` (absolute served-directory paths of every tunnel), and `server.log` (full `tower_http=trace` request URIs, which may carry sensitive query params), plus local filesystem paths.

**M6. Dotfiles/dot-dirs (`.env`, `.git`, `.ssh`, `.aws`) are served with no default filtering.**
`src/static_server.rs:21-29`. `ServeDir` treats a leading `.` as a `Normal` component, so `/.env`, `/.git/config`, `/.git/HEAD`, `/.aws/credentials` are publicly served. The single most common accidental exposure for a static-publish tool.

**M7. No confirmation / auth / allow-deny / size limit before publishing an arbitrary directory to the public internet.**
`src/cmd/start.rs:36-50`. `ft ~` / `ft /` / `ft ~/.config` immediately publishes the whole tree to a global URL with no auth, allow/deny rules, size cap, rate limit, or interactive confirmation. `resolve_dir` only checks exists/is_dir/is_readable.

**M8. The worker reserve→spawn→record→poll state machine (and its partial-failure rollback) is untested** — and **process spawn/detach (`setsid`) + group teardown (`SIGTERM→grace→SIGKILL`) are untested**.
`src/cmd/start.rs:76-171`, `src/proc.rs:35-40`. (Representative of the systemic testing gap; see §4.)

### 🟡 MINOR (33) — grouped

**Lifecycle / async correctness**
- `proc::shutdown_process_group` does a **blocking `std::thread::sleep(1500ms)`** from `async kill::run`/`start::run` (`proc.rs:35-40`). Parks a tokio worker thread for 1.5s per kill.
- **Foreground mode SIGTERMs only the cloudflared leader pid, never its group**, and never `SIGKILL`s or reaps it → stuck/zombie cloudflared possible (`start.rs:234-239`; also gap §5: not reaped on Ctrl-C).
- **Foreground flow never `select!`s on `child.wait()`** — if cloudflared dies before Ctrl-C (binary error, auth failure, network down), `run_foreground` blocks forever on `ctrl_c()` (`start.rs:205-258`).
- **Worker returns `Ok(())` when cloudflared exits before publishing a URL**; the parent *does* fail-fast via `pid_alive`, but the exit cause is invisible (`worker.rs:146-217`).
- `serve_on()` accepts any listener — the **loopback guarantee rests on callers, not the type** (`static_server.rs:54-58`).
- `serve()`'s shutdown future resolves **immediately if `ctrl_c()` errors** → premature drain at startup (`static_server.rs:41-46`).
- No `RequestBodyLimitLayer`; abusive clients can buffer bodies before `ServeDir` runs (`static_server.rs:26-29`).

**Resilience / durability**
- **Corrupted/malformed `registry.json` bricks the entire CLI** — `load()` bails "corrupted" with no recovery (`registry.rs:47-59`).
- **`save()` is not `fsync`'d** — crash between write and rename can commit an empty/partial file (`registry.rs:62-71`).
- 30s poll timeout surfaces **no detail** about why the URL never arrived (`start.rs:144-171`).
- `ft logs --follow` **prints partial lines** and busy-polls both files (`logs.rs:82-113`).
- **No tracing subscriber in parent/foreground** — all `tracing::info!/error!`/`TraceLayer` events there are silently dropped (`worker.rs:292-327` is the only install site). *(Independently confirmed by grep.)*
- Log files grow **without bound**; `print_tail` loads the whole file into memory (`logs.rs:59-69`).

**Idioms / best practices (what clippy cannot catch)**
- Needless `dir.clone()` — `dir` is owned and unused after (`worker.rs:74`).
- Needless `url.clone()` inside the `FnOnce` closure (`worker.rs:274-287`).
- `std::mem::forget(child)` is **redundant** (Unix `Child::drop` is a no-op without `kill_on_drop`) and its comment misstates semantics (`spawn.rs:88-95`).
- `cloudflared::spawn` dead `_tunnel_log` param (`cloudflared.rs:62-86`).
- `logs.rs` helpers take `&PathBuf` instead of `&Path` (`logs.rs:48,78,96`).
- `print_tail` collects→reverses instead of iterating in reverse (`logs.rs:65-68`).
- `cmd/mod.rs` imports `anyhow::Result` instead of the canonical `crate::error::Result` (`cmd/mod.rs:17`).
- `safe_component` can return `""` (all-dashes name) → service dir collapses to `services/` root (`state.rs:92-104`).
- `resolve_dir` uses `absolute()` not `canonicalize` (compounds C1; `start.rs:53-67`).
- `cloudflared` resolved from `PATH` with **no integrity check** (`cloudflared.rs:25-30`).

**Architecture seams (detailed in §1)**
- Duplicated/divergent teardown (`worker.rs:146-213` vs `start.rs`).
- Worker spawned with `--id` but looks itself up by name (`spawn.rs:54-64`).
- `cmd/mod.rs` None-fallback shadows subcommands with same-named dirs (`cmd/mod.rs:38-41`).
- `ServiceKind` single-variant + static-hard-coded `Service` shape (`model.rs:29-60`).
- `Service::status()` heuristic over `(pid_alive, public_url)` not a state machine (`model.rs:67-81`).

**Testing/CI gaps (see §4 for the plan)**
- Port allocation / `is_port_free` untested incl. documented TOCTOU (`port.rs`).
- `ServeDir` traversal/symlink containment untested despite being a stated invariant (`static_server.rs`).
- No supply-chain scan, no MSRV, no `--locked`/`--all-features`, single-OS matrix, no coverage gate (`.github/workflows/ci.yml`).
- Output formatting (`print_started/list/detail`) untested (`output.rs`).
- Registry flock serialization untested under concurrency (`registry.rs`).
- `extract_url`/`safe_component`/`validate_name`/`generate_name` lack property tests.
- Zero async tests; entire axum/tokio/worker surface untested.

### 🔵 INFORMATIONAL (13) — incl.
- `error.rs` bare alias, no user-vs-internal split (`error.rs:9`).
- `kill.rs` find-then-clone-then-remove correct but could expose `Registry::take` (`kill.rs:24-28`).
- `kill(-pgid)` signals a group whose *leader* was cmdline-validated but not every member — residual theoretical PID-reuse risk (`kill.rs:34-43`). *(Stronger "Major" framing was refuted; kept informational.)*
- `extract_url` string-surgery (bounded, acceptable today) (`cloudflared.rs:38-54`).
- Responses lack `X-Content-Type-Options: nosniff` / `Content-Disposition` (`static_server.rs:26-28`).

---

## 3. Refuted / cleared (transparency — 4)
- `static_server::serve` hard-codes a Ctrl-C handler → **stylistic, not a defect**.
- Background poll lacks `worker_pid==0` guard → **cannot misfire** (the pid is durably recorded before the poll loop starts).
- `kill(-worker_pid)` on a recycled foreign pgid when only cloudflared is alive → **not practically exploitable** (cloudflared being alive keeps the group live; leader-pid recycling while a member lives is not a realistic vector).
- Worker 3s registry-lookup vs parent save → **safe and correctly handled** (informational only).

---

## 4. Open gaps surfaced by the completeness critic (16) — promoted where real
Several gaps are **new, actionable findings** not in §2:
- **Orphaned `registry.json.tmp` never cleaned up** — a crash between `write` and `rename` leaves it forever; clean on `load`/`ensure` or use a unique temp name.
- **`open::that(url)` on a stored URL with no scheme validation** — `ft open` reads `public_url` back from `registry.json` (hand-editable) and passes it to `xdg-open`; validate scheme=https + host before opening.
- **`registry.json` serde is fully untrusted** — no post-load validation (port=0, duplicate ids, names, bogus paths). Add `Registry::validate()` after load.
- **Worker never marks/clears its entry on exit** — returns `Ok(())` leaving `public_url`/`worker_pid` stale (ties to M4).
- **`pipe_stream` holds an async `Mutex` across awaits and silently `let _ =`s every write error** — use an mpsc writer task; surface errors.
- **Panic surface unaudited** — a panic in the detached worker is silent+fatal; audit indexing/`unwrap`/`expect`, fuzz `output::*` with hostile strings.
- **`RunWorker` is not access-controlled** — any local user can `ft run-worker --dir <anything>` directly; add a parent-issued handshake token.
- **Double `cloudflared` PATH lookup per start** (`start.rs:89` + `worker.rs:88` + inside `spawn`); resolve once and pass the path through.
- **Directory auto-indexing behavior unspecified/untested** — confirm ServeDir does *not* auto-list (it 404s without `index.html`) and lock with a test. *(Verified by source: `append_index_html_on_directories(true)` only serves `index.html`; no generated listing.)*
- Supply-chain: `Cargo.lock` shipped but never `--locked`-validated in CI; no SBOM; GitHub Actions on floating `@v4` tags (pin SHAs); add `deny.toml` + `SECURITY.md`.
- TOCTOU/state isolation on multi-user hosts — flock is advisory-only; document; retry port on worker bind failure.

---

## 5. THE PLAN — phased, prioritized remediation

Effort: **S** ≤½ day, **M** 1–2 days, **L** 3–5 days. Sequence top-to-bottom; each phase is independently shippable. **Acceptance = green CI (fmt+clippy+test, incl. new tests) + the listed criterion.**

### Phase 0 — Safety defaults & quick wins (S, low risk) *ship first*
Goal: highest value-per-effort, mostly mechanical, no behavior change for the happy path.
- [ ] **Permissions hardening (M5):** open all log files + registry temp with **mode 0600**; create state root + per-service dirs **0700** (`std::os::unix::fs::PermissionsExt`). *Acceptance: new files are `-rw-------`, dirs `drwx------`.*
- [ ] **`serve_on` loopback assertion (Minor):** `ensure!(listener.local_addr()?.ip().is_loopback(), …)` at top of `serve_on`.
- [ ] **`X-Content-Type-Options: nosniff`** via `SetResponseHeaderLayer` (enable `set-header` feature).
- [ ] **Idioms (clippy can't catch):** drop `dir.clone()` (`worker.rs:74`), `url.clone()` (`worker.rs:274-287`), `mem::forget(child)` (`spawn.rs:88-95`), dead `_tunnel_log` param (`cloudflared.rs:62-86` + both call sites), `&PathBuf`→`&Path` (`logs.rs:48,78,96`), needless collect (`logs.rs:65-68`), `anyhow::Result`→`crate::error::Result` (`cmd/mod.rs:17`).
- [ ] **`safe_component` never-empty:** substitute `"service"` when result is `""`; add test (`state.rs:92-104`).

### Phase 1 — Critical + public-exposure security (M, the must-do) *blocks public trust*
Goal: the served tree is *exactly* what the user intended — nothing more.
- [ ] **C1/M6 symlink + dotfile confinement (the headline fix).** Canonicalize the served root (`std::fs::canonicalize`) in `resolve_dir`. Replace the bare `ServeDir` fallback with a **confining static handler**: a small `axum` handler (or `from_fn` layer + `ServeFile`) that, per request, (a) **rejects any path component starting with `.`** (404) — covers `.env/.git/.ssh/.aws`; (b) resolves `canonical_base.join(rel)`, **canonicalizes the target**, and **404s if it does not start with the canonical base** — defeats symlink escape; (c) applies `nosniff` + optional `Content-Disposition`. *Immediate mitigation if the full handler is deferred:* a `from_fn` dotfile-deny layer + root canonicalize + a `walkdir` pre-scan that refuses to start if the tree contains symlinks pointing outside the root. *Acceptance: integration test `tests/static_server_security.rs` (see Phase 5) asserts `/link→/etc/passwd` → 404, `/.env` → 404, `/../secret` → 404, normal files 200.*
- [ ] **M7 public-exposure guardrail:** require `--yes` (or interactive `y/N`) when the resolved dir is `$HOME`, `/`, or a known-sensitive path; default-deny dotfiles via the layer above (opt-in `--hidden`).
- [ ] **Gap: `open::that` URL validation** — parse `public_url` (scheme=https, host `*.trycloudflare.com`) before storing *and* before opening (`cmd/open.rs`, `worker.rs`).
- [ ] **Gap: untrusted registry** — add `Registry::validate()` (unique ids/names, sane port range, `next_id > max(id)`, non-empty paths) run after every `load`.

### Phase 2 — Lifecycle & resilience correctness (M–L)
Goal: no orphans, no bricks, no silent failures, no indefinite blocks.
- [ ] **M1 race fix:** make a `worker_pid==0` entry non-killable — `kill::run` treats it as `Starting` and bails ("service is still starting") instead of removing it. *(Cleaner than collapsing reserve+record, which is impossible pre-spawn.)*
- [ ] **Worker exit cleanup (M4 + gap):** on every exit path in `worker::run`, best-effort `Registry::update` to clear `public_url`/`worker_pid` (or mark `Stale` once the lifecycle field exists). Add **`ft prune`** that drops `Stale` entries and best-effort kills orphaned cloudflared whose recorded worker is gone; optionally reconcile at the top of `ft start`/`ft ls`.
- [ ] **Foreground correctness:** add `child.wait()` to the `select!` (exit if cloudflared dies pre-Ctrl-C) and mirror the worker teardown — `SIGTERM` → bounded wait → `SIGKILL` → `child.wait().await` to reap (fixes the foreground Minor + the Ctrl-C zombie gap).
- [ ] **Blocking sleep → async (Minor):** make `shutdown_process_group` `async` (`tokio::time::sleep`, liveness-polled), or `spawn_blocking`; update `kill.rs`/`start.rs` callers.
- [ ] **Registry durability (Minor + gaps):** `fsync` temp file before rename, `fsync` parent dir after; rotate `registry.json` → `registry.json.bak` before commit; clean orphaned `*.json.tmp` on `load`. Add `ft registry repair`/`reset`.
- [ ] **Tracing subscriber everywhere (Minor):** install a default `fmt`+`EnvFilter` subscriber at the top of `main()`; the worker layers its file sinks on top.
- [ ] **Better 30s-timeout message (Minor):** before bailing, probe `tunnel_pid` liveness and say whether cloudflared is still provisioning vs exited.

### Phase 3 — HTTP robustness (S–M) *closes M2/M3 together*
- [ ] **`TimeoutLayer` + `RequestBodyLimitLayer`** in `router()` (enable `timeout`, `limit` features). `TimeoutLayer::new(30s)` makes each request self-terminate → the graceful drain is now genuinely bounded and the `abort` fallback in M2 becomes unnecessary for slow clients. `RequestBodyLimitLayer::new(0)` (static GET needs no body). *Acceptance: a test holding a connection open past the timeout is closed server-side.*
- [ ] **`serve()` ctrl_c error handling (Minor):** surface the `ctrl_c()` `Result` instead of `let _ =`; or install the signal handler once at the caller and forward only its resolution to `serve_on` (also removes the double-registration).

### Phase 4 — Architecture refactor (L, the "north star") *unblocks the roadmap*
- [ ] **Shared teardown helper:** extract `proc::shutdown_tunnel_and_drain(child, tunnel_pid, server_shutdown_tx, server_handle, grace)`; both `worker.rs` and `run_foreground` call it (eliminates the divergence; foreground gains SIGKILL+reap for free).
- [ ] **Tagged-union `Service`:** `ServiceSpec::{ Static { dir }, Proxy { upstream } }`; worker dispatches on it. Either commit to `ServiceKind` now or delete it (YAGNI) — stop carrying dead structure.
- [ ] **Explicit lifecycle field:** `Reserved→Spawned→TunnelUp→TunnelDown→Dead`, written under the lock by the worker; `status()` becomes a cheap read + optional staleness cross-check (removes per-row `/proc` fan-out; makes the registry authoritative).
- [ ] **Make `--id` load-bearing** (worker looks itself up by id) **or drop it** from `RunWorker`/`spawn.rs`.
- [ ] **CLI:** add an explicit (hidden) `Start { dir }` subcommand *or* document the `./`-prefix requirement for dirs named like subcommands (`cmd/mod.rs:38-41`).
- [ ] **Error model:** split user-facing vs internal (small `thiserror` enum or a `user_facing()` marker); decide `main` prints `{err}` vs `{err:#}`.

### Phase 5 — Test & CI foundation (M, enables everything above) *do in parallel with Phases 1–4*
- [ ] **`[dev-dependencies]`:** `tokio` (full+test-util), `tower` (`ServiceExt`)/`axum::TestServer`, `http-body-util`, `tempfile`, `proptest` (or `quickcheck`).
- [ ] **New `tests/`:**
  - `static_server_security.rs` — traversal/dotfile/symlink confinement + loopback-only bind + no-auto-listing (locks C1/M6/Phase 1).
  - `registry_concurrency.rs` — N threads allocating ids under one temp `StateDir`; assert no dup ids, exactly N services.
  - `process_group.rs` — spawn a `setsid` leader + child, `shutdown_process_group(leader)`, assert both gone + no zombie; ESRCH-on-dead path.
  - `port.rs`, `worker_state_machine.rs` (inject spawn failure → entry removed; worker-exits-pre-URL → fail-fast).
  - `output.rs` — snapshot/contains tests for the banner/list/detail (the public output contract).
  - `proptest` for `safe_component` (matches `^[A-Za-z0-9_-]*$`, no `/`, never `..`), `extract_url`, `validate_name`, `generate_name`.
- [ ] **CI:** switch to **`cargo-nextest`** (retries/isolation) + **`cargo-llvm-cov`** gate (start ~50%, raise over time); add **MSRV** `rust-version="1.85"` + a matrix build on it; add **macOS** to the matrix (builds the `not(target_os=linux)` paths); add `--locked --frozen` and `--all-features` to clippy/test/build; add **`cargo-deny` + `cargo-audit`** (PR + scheduled); commit `deny.toml`, `SECURITY.md`, `.github/dependabot.yml`; **pin Actions to SHAs**.

### Phase 6 — Hardening & polish (S–M, post-foundation)
- [ ] Bounded `print_tail` (seek near-EOF, read tail chunk) + follow-line buffering (`logs.rs`).
- [ ] Log rotation (size-capped; `tracing-appender::rolling` or manual) for `server.log`/`tunnel.log`; downgrade server filter off `tower_http=trace` by default.
- [ ] `pipe_stream` → mpsc writer task; surface write errors via `tracing::warn`.
- [ ] Resolve `cloudflared` **once**, pass the absolute path to the worker; prefer trusted PATH locations / warn on world-writable; optional `--cloudflared-path`.
- [ ] **`RunWorker` handshake token** (parent-issued, validated) so direct `ft run-worker` is rejected.
- [ ] **Panic audit:** grep `unwrap/expect/indexing/panic`; fuzz `output::*` with hostile names/URLs + control chars; ensure no panic path in the detached worker.

---

## 6. If you do nothing else — the prioritized top 7
1. **C1 — symlink confinement + dotfile deny + root canonicalize** (Phase 1). *Public exfiltration today.*
2. **M5 — 0600/0700 file permissions** (Phase 0). *One-liner per open; stops multi-user info leak.*
3. **M2/M3 — `TimeoutLayer` + `RequestBodyLimitLayer`** (Phase 3). *Two lines; bounds the drain and closes the slowloris vector.*
4. **M1 — make `worker_pid==0` non-killable** (Phase 2). *Prevents orphaned-worker leaks under concurrent `kill`.*
5. **Foreground `select!` on `child.wait()` + reap/SIGKILL** (Phase 2). *Stops indefinite blocks and zombies.*
6. **`ft prune` + worker exit cleanup** (Phase 2). *Stops stale-entry/orphan accumulation after reboot.*
7. **The `tests/static_server_security.rs` + `registry_concurrency.rs` tests + MSRV/deny in CI** (Phase 5). *Locks the fixes and the load-bearing invariant.*

---

## 7. Target-state architecture (north star, 1-paragraph)
A `Service` is a tagged union (`Static{dir} | Proxy{upstream}`) with an explicit, lock-protected lifecycle field the worker transitions; the static server is a **confining handler** (canonicalize-and-confine + dotfile-deny + `nosniff`) fronted by `TimeoutLayer`+`RequestBodyLimitLayer` and a loopback-asserting `serve_on`; a single shared `shutdown_tunnel_and_drain` helper serves both worker and foreground; all on-disk state is 0600/0700 and durably committed (fsync + `.bak` + tmp-cleanup) with a `validate()`-on-load registry; a default tracing subscriber runs in every process; `ft prune` reconciles stale entries; CI runs nextest + coverage + MSRV matrix + cargo-deny on pinned Actions. The happy-path UX is unchanged; the failure and threat surface is closed.

---

## 8. Re-audit (2026-06-28, after fix commit `2009943`)

Maintainers landed **commit `2009943` "Deep-audit fixes: orphan prevention, foreground hang, edge cases"** (7 files: `cloudflared.rs`, `cmd/kill.rs`, `cmd/logs.rs`, `cmd/start.rs`, `proc.rs`, `state.rs`, `worker.rs`). A focused re-audit (76 agents, ~2M tokens, adversarially verified; baseline **fmt/clippy/39 tests green**) produced 72 findings → 70 kept, 2 refuted.

**Bottom line:** the commit is high-quality and cleanly lands the **lifecycle/resilience** items (most of original Phase 2 + the `safe_component` Phase 0 item). It introduced **2 new Minor regressions** and left **3 partial fixes**. Crucially it **did not touch `static_server.rs`, `registry.rs`, or `spawn.rs`**, so the **entire public-facing security surface is unchanged** — the Critical and the highest-value Majors remain open.

### ✅ Confirmed fixed (cleanly verified)
- **Foreground hang** — `run_foreground` now `select!`s on `child.wait()` vs `ctrl_c()`; SIGTERM→2s grace→SIGKILL→reap; **exactly-once reap**, server always awaited/aborted on both arms (`start.rs`).
- **Orphan prevention (worker-dies)** — `PR_SET_PDEATHSIG(SIGKILL)` in `pre_exec` reaps idle cloudflared when the worker is SIGKILL'd/OOM'd. **ABI verified correct** against the locked `libc 0.2.186` (`c_ulong` variadic arg is the safe conventional form) (`cloudflared.rs:88-98`).
- **Worker id-keying** — looks up by `id`, self-registers `worker_pid`, and **removes its entry on every failure path**; ids are monotonic so **no name-reuse clobber, no double-remove/re-created-entry race** (`worker.rs`).
- **30s timeout + fail-fast** now tear down worker+entry (no leak) and **surface the failure reason inline** (`start.rs`).
- **`--port 0` rejected** (both flows).
- **`kill`** friendly "no service matches" on a stateless system, **TOCTOU-safe** (unlocked gate then locked re-check+remove).
- **`safe_component`** no longer trims dashes + falls back to `"service"` (fixes the `""`/`a`-vs-`-a` collision while staying traversal-safe).
- **`shutdown_process_group(0)`** is a no-op (avoids `kill(-0)` self-kill).
- **`logs --follow`** tolerates missing files; tail + follow reads **capped ~64 KiB**.
- **`extract_url`** scans every `https://`, skips non-tunnel prefixes; **no infinite loop** (advances past each match).

### ⚠️ New regressions introduced by the fix
- **R1 (Minor) — worker lookup loop now writes the registry every 100ms.** `worker.rs:56-77` switched from a read-only `Registry::load` probe to `Registry::update`, so for up to 3s it takes the **exclusive flock and rewrites the entire `registry.json`** every 100ms, contending with the parent's pid-record and all concurrent `ft` commands during startup. **Fix:** keep the loop read-only (`Registry::load(...).find_by_id(id)`), do the self-register `worker_pid` write **once** after the entry is found.
- **R2 (Minor) — unbounded blocking read in async.** `last_line`/`last_reason` (`start.rs:191-208`, called at :167 and :183) do `std::fs::read` of the **whole** log file inside async `run_background` on the fail-fast/timeout paths — blocks a tokio thread, unbounded for a chatty `tunnel.log`. **Fix:** bounded tail read (seek to last ~8–64 KiB like `logs.rs`) or `spawn_blocking`.

### 🔧 Partial fixes (residual gaps in addressed areas)
- **M1 race — mitigated, not closed.** Worker side is fixed, but the **parent still records `worker_pid` and polls by NAME** (`start.rs:145` `find_mut(&name)`, `:156` `find(&name)`). A concurrent `ft kill <name>` during the 30s poll can still remove the entry while the fresh worker runs orphaned; the parent's id-based cleanup fires only on timeout/fail-fast. **Fix:** key the parent by `id` too (`find_mut(&id.to_string())`). *(The "fully still leaks" framing was refuted — the worker self-cleanup closed the worst case.)*
- **M4 reboot — still open.** PDEATHSIG covers worker-dies but **not reboot/power-loss**: `registry.json` persists stale, no `ft prune`/reconcile on boot. **Fix:** reconcile on `StateDir::ensure()`/`ft prune`.
- **Foreground graceful drain — partial.** On cloudflared-initiated exit the server is **force-aborted after 3s** instead of drained (`serve()`'s shutdown is driven by its own `ctrl_c()`, which never fires on the `ChildExited` arm). Minor.
- **PDEATHSIG fork→prctl race (Minor/soundness).** If the worker is SIGKILL'd between `fork()` and `prctl()`, cloudflared is orphaned (no `getppid()==1` re-check). **Fix:** after `prctl`, `if libc::getppid()==1 { return Err(...EOWNERDEAD) }` so the child refuses to exec if it already lost the race. *(The "multi-threaded tokio tracks parent thread" soundness claim was refuted as a non-issue.)*

### ⏳ Still open (unchanged — public security surface untouched)
- 🔴 **C1 Critical** — ServeDir follows symlinks + serves dotfiles; `resolve_dir` uses `absolute()` not `canonicalize()` (`static_server.rs:21-29`, `start.rs:resolve_dir`).
- 🟠 **M2/M3 Major** — no `TimeoutLayer`/`RequestBodyLimitLayer`; abort-fallback doesn't cancel in-flight connections (unbounded drain).
- 🟠 **M5 Major** — `registry.json` + all `*.log` created **0644** (world-readable: request URIs + local paths).
- 🟠 **M7 Major** — no confirmation/auth/allowlist before publishing an arbitrary dir publicly.
- 🟠 **M4 Major** (reboot part) — no prune/reconcile.
- Minors/gaps: orphaned `registry.json.tmp`; `Registry::load` no `validate()`; no tracing subscriber in `main`/foreground; blocking `thread::sleep` in async `shutdown_process_group`; `serve_on` no loopback assert; no `nosniff`; `RunWorker` not access-controlled; `open::that` no scheme validation.

### Updated next priorities
With the lifecycle work largely done, the **public-trust** items are now the clear top of the backlog (none were touched by the fix):
1. **C1 + M7** — confining static handler (canonicalize-and-confine + dotfile deny) + publish guardrail (`--yes`/allowlist). *(Phase 1 — the Critical.)*
2. **M5** — 0600/0700 file permissions. *(Phase 0 — trivial, high value.)*
3. **M2/M3** — `TimeoutLayer` + `RequestBodyLimitLayer` (two lines, closes the slowloris + unbounded-drain). *(Phase 3.)*
4. **R1 + R2** — fix the two new regressions (read-only probe loop; bounded tail read).
5. **M1 parent-id-keying** + **fork→prctl `getppid` re-check** — close the residuals cheaply.
6. **M4 reboot** — `ft prune`/reconcile.
7. Phase 5 test/CI foundation remains the unlock for everything above.
