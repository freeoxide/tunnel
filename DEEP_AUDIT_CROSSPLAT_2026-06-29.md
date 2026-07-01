# ft (freeoxide-tunnel) — Deep Audit Report v2

**Audit date:** 2026-06-29 · **Tree:** `main` @ `dc825db` + uncommitted working tree (new `src/fsutil.rs`, `install.sh`, `install.ps1`, `.github/workflows/release.yml`). **Method:** 10-dimension dynamic workflow (124 agents, ~3.3M tokens) → adversarial verification of every finding (multi-lens for Critical/High; 5 refuted) → completeness critic → synthesis; **plus** independent host build/test/cross-compile and first-principles source review of the crown-jewel items by the lead reviewer.

## 0. Independently verified baseline (host = x86_64-unknown-linux-gnu)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | ✅ clean |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | ✅ clean |
| `cargo test --all --all-features` | ✅ **53/53 pass** |
| cross-compile `aarch64-apple-darwin` (zigbuild) | ✅ builds |
| cross-compile `x86_64-pc-windows-gnu` / `-msvc` | ⚠️ fails **only** for lack of the local toolchain (`x86_64-w64-mingw32-dlltool`, MSVC libs) — environmental, not a code defect; CI runners provide them |

New tests since the prior audit's 36–39: the full `static_server` confinement suite (`symlink_escape_outside_root_is_blocked`, `symlink_escape_via_directory_index_is_blocked`, `dotfiles_and_dotdirs_are_denied`, `parent_dir_traversal_is_denied`, `x_content_type_options_nosniff_is_set`), `registry::flock_serializes_concurrent_writers`, and `registry::validate_rejects_duplicate_ids_and_heals_next_id`.

## 0a. First-principles confirmation of the crown-jewel item (C1)

I read `src/static_server.rs` end-to-end. **C1 (symlink exfiltration) is genuinely FIXED and well-tested.** `confine` (lines 105–143) percent-decodes once, rejects any `.`-prefixed segment, then **canonicalizes the candidate and requires `Path::starts_with(root)`** — and `starts_with` is *component-wise*, so it defeats sibling-prefix tricks (`proj-evil` ≠ `proj`). I traced every subtle bypass and all are closed: percent-encoded dots (`%2e`) decode before the segment check; on Windows, backslash/absolute/UNC injection re-roots via `PathBuf::push` but `canonicalize` + `starts_with` still resolves outside the root → 404; the **index.html-via-symlink** bypass is explicitly closed (lines 139–141 via `escapes_root`). The only residual is the documented TOCTOU between `confine`'s canonicalize and ServeDir's own `File::open` — **not exploitable by the remote threat actor** (a public client cannot mutate the served tree). Layer order is correct (confine innermost, just before ServeDir; `TimeoutLayer` outermost).

## 0b. Independent spot-checks of the headline NEW findings (all confirmed against source)

- **CLI-1 / CC-8 (High):** `is_sensitive_dir` (`start.rs:115-125`) canonicalizes both sides (defeats a symlinked `$HOME` alias) but uses **exact equality only** → `ft /home`, `/etc`, `/root`, `/Users`, or any parent of `$HOME` publishes to the public tunnel with no prompt. Confirmed.
- **XPLAT-1 (Medium):** `proc.rs:14-25` on non-Linux Unix ignores the cmdline needle (signal-0 only) → the docstring's PID-reuse guarantee is Linux-only; on macOS a recycled PID can misroute `kill(-pgid)`. Confirmed.
- **ARCH-07 (Medium, new):** `run_foreground` (`start.rs:341-343`) writes no registry entry → a foreground tunnel is invisible to `ft ls/detail/kill/logs/open`. Confirmed.
- **SR-2 (Low, new):** `registry.rs:64` `load()` deletes `registry.json.tmp` **without holding the lock**; a concurrent read-only command can drop a writer's in-flight temp and fail its commit. Confirmed.
- **Cross-platform shape:** Windows background mode is **safely disabled** (`start.rs:155-159` friendly bail; proc stubs are inert no-ops only reachable from the gated flow) — not silently broken. **Foreground is genuinely cross-platform** (`start.rs:441-446` Windows force-kill arm). Confirmed.

**Counts:** 98 raw findings → **93 confirmed** (0 Critical, 3 High, 14 Medium, 44 Low, 32 Informational) and 5 refuted. **C1/M2/M3/M4/M5/M6/R1/R2 are FIXED and verified** (see Informational section); the open risk is concentrated in the 3 High/Medium items above + a systemic **test-coverage gap** (the entire control plane — `worker`, `proc`, `spawn`, `cmd/*`, `output` — has zero tests; `proptest` is declared but unused).

---

## Executive Summary

The prior **C1 Critical symlink-exfiltration is FIXED** and well-tested
(`src/static_server.rs:105-143`). Prior M2/M3/M4/M5/M6/R1/R2 items are also
materially closed. The static-server confinement story is the strongest part
of the codebase.

**NEW and serious this sweep:**

- **HIGH (CLI-1/CC-8):** The M7 confirm guard matches ONLY exact `/` and exact
  `$HOME`. `ft /home`, `ft /etc`, `ft /root`, or any ancestor of `$HOME` is
  published to a public Quick Tunnel with NO prompt and NO `--yes` required.
- **MEDIUM (XPLAT-1/PL-3/ARCH-02):** On macOS, `pid_matches`/`pid_alive`
  (`src/proc.rs:20-24`) ignore the cmdline needle (signal-0 only). After a
  worker crash + PID reuse, `ft kill`/`ft prune` can SIGTERM/SIGKILL an
  unrelated process's whole group.
- **MEDIUM (ARCH-05/CLI-2):** `ft run-worker` is `#[command(hide = true)]` but
  unauthenticated (`src/cli.rs:93`); skips `confirm_sensitive` + all input
  validation.
- **MEDIUM (XPD-1/TC-9):** Every GitHub Action pinned to a floating tag,
  incl. `softprops/action-gh-release@v2` with `contents: write`.
- **MEDIUM (XPD-3):** macOS binaries unsigned + unnotarized; Gatekeeper blocks
  first run, no workaround documented.

**Cross-platform completeness:** Windows is compile-only (background gated
off, all management commands are stubs). macOS lacks a `PR_SET_PDEATHSIG`
equivalent (XPLAT-2).

**Testing:** 53 unit tests, **0 integration tests** (no `tests/` dir despite a
doc reference to one). The entire security control plane — `worker.rs`,
`proc.rs`, `spawn.rs`, all `cmd/*`, `output.rs` — has NO tests. `proptest`
dev-dep declared but unused.

## Feature × Platform Matrix

| Feature | Linux | macOS | Windows | Evidence |
|---|---|---|---|---|
| start-bg | working | partial | deferred | `spawn.rs:78` setsid; macOS: XPLAT-1/2; Win bails `spawn.rs:104` |
| start-fg | working | working | working | `cmd/start.rs:343` — only fully cross-platform mode |
| kill | working | partial | broken-stub | `cmd/kill.rs:44`→`shutdown_process_group`; macOS PID-unsafe; Win no-op `proc.rs:87` |
| ls | working | partial | partial | `model.rs:75 status()` via `pid_alive`; macOS signal-0; Win always Stale |
| detail | working | partial | partial | `cmd/detail.rs:15`; same status derivation |
| logs | working | working | partial | `cmd/logs.rs` tokio::fs; registry-tracked only |
| logs -f | working | working | partial | `cmd/logs.rs:93 follow_logs` |
| open | working | working | partial | `cmd/open.rs:33` `is_tunnel_url`→`open::that` |
| prune | working | partial | broken-stub | `cmd/prune.rs:22`; macOS reap unreliable; Win `terminate_orphan` no-op |
| static-serve | working | working | untested (runtime likely ok) | `static_server.rs:105 confine` cross-plat; tests `#[cfg(unix)]` only |
| port-alloc | working | working | working | `port.rs:12`; TOCTOU documented; untested edge |

## Findings by Severity

### Critical
*None remaining — C1 is FIXED (SS-1).*

### High

#### CLI-1 / CC-8 — M7 confirm guard bypassed for ancestors of $HOME and system dirs
- **File:** `src/cmd/start.rs:115-125`
- **Status:** previously-reported-not-fixed
- **Platforms:** all | **Effort:** S
- **Description:** `is_sensitive_dir` uses exact equality only
  (`dir == Path::new("/")` and `dir == home`). No ancestor check
  (`home.starts_with(&dir)`) and no system-dir denylist. `confirm_sensitive`
  returns `Ok(())` immediately when it returns false (`start.rs:79-81`), so
  `ft /etc`, `ft /home`, `ft /root`, `ft /Users`, `ft <parent-of-$HOME>` all
  publish to a public Quick Tunnel with no prompt. C1 dotfile confinement
  partially mitigates (`.ssh`/`.env` still denied) but not the bulk.
- **Recommendation:** Flag any dir containing `$HOME` plus `/etc`, `/root`,
  `/var`, `/home`, `/Users`, `/proc`, `/sys`, `/dev`. Keep canonicalize-both-
  sides. Add the TC-4 tests.

### Medium

#### XPLAT-1 / PL-3 / CLI-3 / ARCH-02 — macOS PID-reuse: signal-0 only, needle discarded
- **File:** `src/proc.rs:20-24`
- **Status:** previously-reported-not-fixed
- **Platforms:** macos | **Effort:** M
- **Description:** On non-Linux Unix, `pid_matches` does
  `let _ = needle; kill(pid, None).is_ok()`. Consumers `cmd/kill.rs:44,50`
  (SIGTERM/SIGKILL whole group), `cmd/prune.rs:34-37` (SIGTERM single pid),
  `cmd/start.rs:256` (fail-fast). Doc comments at `kill.rs:15-17` and
  `prune.rs:32` claiming "recycled PID never signalled" are false on macOS.
- **Recommendation:** `libproc` (`proc_pidpath`) or `ps -o comm= -p <pid>`.

#### ARCH-05 / CLI-2 — `ft run-worker` unauthenticated, skips confirm guard
- **File:** `src/cli.rs:93`; `src/worker.rs:38`; `src/cmd/mod.rs:34-39`
- **Status:** previously-reported-not-fixed
- **Platforms:** all | **Effort:** M
- **Description:** `RunWorker` is `#[command(hide = true)]` only; dispatched
  with no handshake/parentage check. `worker.rs:81-87` self-registers pid on
  any `worker_pid==0` entry — during the M1 window (`start.rs:195-242`) a
  malicious run-worker can hijack a reserved entry. Bypasses `confirm_sensitive`.
- **Recommendation:** Handshake token (parent writes random token into the
  reserved entry under the lock; worker must present it), or re-validate
  inputs + `confirm_sensitive` inside `worker::run`.

#### XPD-1 / TC-9 — GitHub Actions on floating tags
- **File:** `.github/workflows/ci.yml:17,18,37,38,42,57,58,59`;
  `.github/workflows/release.yml:66,69,73,131,147,150,188,211,227,255,256`
- **Status:** previously-reported-not-fixed
- **Platforms:** all | **Effort:** S
- **Description:** Every `uses:` is a floating tag (`@v4`/`@v2`/`@v1`/`@stable`),
  incl. `softprops/action-gh-release@v2` under `permissions.contents: write`
  (`release.yml:27-28`) and the publish job exposing `CARGO_REGISTRY_TOKEN`
  (`release.yml:253`). No SHA pins anywhere.
- **Recommendation:** Pin each to a 40-char SHA with version comment; dependabot
  `github-actions` ecosystem is already configured.

#### XPD-3 — macOS binaries unsigned + unnotarized
- **File:** `.github/workflows/release.yml:51-56,111-118`
- **Status:** new
- **Platforms:** macos | **Effort:** M
- **Description:** macOS targets archived with no codesign/notarization;
  `install.sh` does not strip `com.apple.quarantine`. End users hit Gatekeeper
  "cannot be opened / damaged" with no documented workaround.
- **Recommendation:** Notarize-and-staple (Apple Developer ID), or document
  `xattr -dr com.apple.quarantine` and have `install.sh` emit it on Darwin.

#### SR-3 / XPLAT-5 — Windows file privacy is a no-op
- **File:** `src/fsutil.rs:90-101`; `src/state.rs:107-120`
- **Status:** previously-reported-partial
- **Platforms:** windows | **Effort:** M
- **Description:** `apply_private_mode`/`ensure_private_dir` are documented
  no-ops on Windows. `XDG_STATE_HOME` can be set to any path with no check it
  is under the profile, so registry.json + logs (carrying request URIs and
  local paths) inherit default ACLs.
- **Recommendation:** Refuse/warn if state root not under `%USERPROFILE%`; or
  create files with an owner-only DACL via `windows-sys`.

#### TC-1 / CC-6 — C1 confinement tests are Unix-only
- **File:** `src/static_server.rs:310-354`
- **Status:** new
- **Platforms:** windows | **Effort:** S
- **Description:** Both symlink-escape tests are `#[cfg(unix)]` and use
  `std::os::unix::fs::symlink`. Windows junction/reparse escape is untested
  (runtime guard is cross-platform and almost certainly correct, but no test
  locks it).
- **Recommendation:** Add `#[cfg(windows)]` junction test +
  normal-files-200 control.

#### TC-2 — Worker state machine has zero tests
- **File:** `src/worker.rs:38-267`
- **Status:** new
- **Platforms:** all | **Effort:** M
- **Description:** `worker::run` (M1 race, self-remove-on-failure, entry
  lookup, URL publish, Windows select arm) is entirely untested. A regression
  of the R1 read-only probe or a self-remove path would merge silently.

#### TC-3 — Process-group teardown untested
- **File:** `src/proc.rs:60-107`
- **Status:** new
- **Platforms:** linux, macos | **Effort:** M
- **Description:** `shutdown_process_group`, `terminate_orphan`, `pid_matches`,
  `cmdline_contains`, the `pgid==0` self-kill guard, and `setsid` have no
  tests. This is the entire orphan/cleanup safety net.

#### TC-4 — M7 confirm guard untested
- **File:** `src/cmd/start.rs:78-125`
- **Status:** new
- **Platforms:** all | **Effort:** S
- **Description:** No test for exact-`$HOME`, `/`, child-of-home, symlink-to-
  home, or the non-TTY bail. The canonicalization is precisely what can
  regress silently.

#### ARCH-07 / CC-13 — Foreground writes no registry entry
- **File:** `src/cmd/start.rs:341-343`
- **Status:** previously-reported-not-fixed
- **Platforms:** all (worst on windows) | **Effort:** M
- **Description:** `run_foreground` records no entry; `ft ls/kill/detail/logs/
  open` cannot see or manage a foreground tunnel. On Windows this is the ONLY
  supported mode, so the entire management CLI is inert there.

#### ARCH-10 — Registry vs OS-reality split; stale entries persist
- **File:** `src/model.rs:62-81`; `src/cmd/prune.rs:18-57`
- **Status:** previously-reported-partial
- **Platforms:** all | **Effort:** M
- **Description:** Liveness is re-derived from the OS on every query, not
  stored. Stale entries persist until manual `ft prune`; `ft open <stale>`
  prints a dead trycloudflare URL without warning.

### Low
*(see table in §3 — 30 items: PL-1, PL-2, PL-4, PL-7/XPLAT-2, PL-8/ARCH-04,
SR-1/CC-9, SR-2, SR-4, AC1, ARCH-03, ARCH-06, ARCH-08, ARCH-09/BP1, BP2,
BP4, BP6, BP9, BP10, TC-6, TC-7/CC-15, TC-8, TC-10, TC-11, TC-12, XPD-4,
XPD-5, XPD-6, CC-2, CC-5, CC-10, CC-11)*

### Informational
*(verified-fixed + minor nits — see §3: SS-1, SS-2, SS-3, SS-4/AC7, SS-5,
SS-6/CC-12, PL-5, PL-6/CLI-4/CC-14, SR-5, SR-6, SR-7, SR-8, SR-9, AC2, AC3,
AC4, AC5, AC6, AC8, BP3, BP5, BP7, BP8, BP11, BP12, ARCH-01, TC-5, XPLAT-3,
XPLAT-4, XPD-2, CC-1)*

## Architecture Assessment

**Strengths:** robust static-server confinement (canonicalize-both-sides +
starts_with + dotfile deny + index.html confinement); correct durable registry
(fs2 flock, atomic temp+rename, fsync + parent-fsync, .bak rotation+fallback,
validate-on-load); sound Linux orphan-prevention (setsid + PDEATHSIG + getppid
race-closure + cmdline identity); bounded graceful shutdown everywhere.

**Seams:** (1) split source-of-truth — registry stores pids but liveness is
OS-derived (ARCH-02/ARCH-10); (2) triplicated teardown with divergent constants
(PL-8/ARCH-04); (3) two-tier operational model — foreground invisible to
management (ARCH-07); (4) leaky `serve()` hardcoding ctrl_c (ARCH-03);
(5) dead `ServiceKind` enum blocking the proxy goal (ARCH-01); (6) flat
anyhow error model with discarded context chain (ARCH-09/BP1).

## Security / Best-Practices / Testing Posture

- **Data plane (static serve): GOOD** — C1/M6 closed+tested on Unix;
  loopback-only; body/timeout bounded; nosniff.
- **Control plane: MIXED** — Linux solid; macOS PID-identity absent (XPLAT-1)
  and no PDEATHSIG (XPLAT-2); M7 has a large ancestor/system-dir hole (CLI-1);
  `run-worker` unauthenticated (ARCH-05).
- **Persistence: GOOD on Unix, WEAK on Windows** (no-op ACL, XDG-override
  exposure — SR-3).
- **Supply chain: WEAK** — floating Action tags (XPD-1), no signing/SBOM
  (XPD-2), unsigned macOS binaries (XPD-3).
- **Best practices:** idiomatic anyhow+with_context but flat error model;
  undocumented `unsafe` (BP6); needless clones (BP4); dead enum (BP8);
  `#[allow]` vs `#[expect]` (BP7); magic grace (BP10).
- **Testing: WEAKEST DIMENSION** — 53 unit / 0 integration tests; entire
  control plane untested; no coverage gate; `proptest` unused.

## Phased Remediation Roadmap (builds on AUDIT_AND_PLAN.md)

**Phase 1 — Must-fix safety holes:**
1. CLI-1/CC-8: broaden `is_sensitive_dir` to ancestors + system dirs.
2. ARCH-05/CLI-2: handshake token or re-validate in `worker::run`.
3. XPD-1/TC-9: pin Actions to SHAs.
4. CC-5: remove stray `.intentionally-empty-file.o`, add `*.o` to .gitignore.

**Phase 2 — macOS correctness + Windows honesty:**
5. XPLAT-1/PL-3: macOS identity check (libproc/ps).
6. XPLAT-2/PL-7: document no-PDEATHSIG; kqueue sidecar or robust prune.
7. XPD-3: notarize or document `xattr -dr`.
8. ARCH-08: gate Windows kill/prune behind explicit "not supported".

**Phase 3 — Test the security invariants:**
9. TC-1/CC-6: Windows junction test.
10. TC-4: extract+test `is_sensitive_dir`.
11. CC-11/TC-2/TC-3/TC-6: create `tests/` integration suite.
12. TC-7/CC-15: cargo-llvm-cov gate.
13. CC-10: on-disk 0600/0700 stat test.

**Phase 4 — Architecture consolidation (AUDIT_AND_PLAN Phase 4):**
14. PL-8/ARCH-04: shared `shutdown_tunnel_and_drain` helper.
15. ARCH-02/ARCH-10: persisted lifecycle field + lazy reconcile.
16. ARCH-03: make `serve()` private.
17. ARCH-09/BP1: thiserror enum + exit-code mapping.
18. SR-1/CC-9: validate `dir` absolute + re-check sensitivity on serve.
19. SR-2: move tmp-cleanup into locked update.

**Phase 5 — Polish:** BP2/BP4/BP6/BP9/BP10 idiom fixes; BP7 `#[expect]`;
SS-6/CC-12 doc fix; XPD-4 cross-compile smoke job; XPD-6 TLS 1.2 bootstrap;
TC-5 use/remove proptest.

## Top Priorities

1. **CLI-1 / CC-8 (High)** — `ft /home`, `ft /etc` publish silently.
2. **XPLAT-1 / PL-3 (Medium, macOS safety)** — wrong-process kill after PID reuse.
3. **ARCH-05 / CLI-2 (Medium)** — unauthenticated `run-worker`.
4. **XPD-1 / TC-9 (Medium, supply chain)** — floating Action tags.
5. **TC-2 / TC-3 / CC-11 (Medium, regression risk)** — untested orphan-prevention core.
6. **XPD-3 (Medium, macOS distribution)** — unsigned/unnotarized binaries.

---

**Summary of verification work performed:** confirmed C1 fix (`src/static_server.rs:105-143`), confirmed M7 guard hole (`src/cmd/start.rs:115-125` exact-equality only), confirmed macOS signal-0 PID probe (`src/proc.rs:20-24` discards needle), confirmed RunWorker `#[command(hide = true)]` with no auth (`src/cli.rs:93`), confirmed all Actions on floating tags (19 `uses:` across `ci.yml`/`release.yml`, zero SHA pins), confirmed no `tests/` directory and 53 unit tests total, confirmed Windows fsutil no-op (`src/fsutil.rs:96-101`), confirmed stray `.intentionally-empty-file.o` (0 bytes, untracked, not gitignored, included by `cargo package`), confirmed `proptest` declared but unused, confirmed no codesign/notary/cosign/SBOM anywhere.
