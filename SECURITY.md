# Security Policy

## Reporting a Vulnerability

This project has a public-facing security surface: `ft` publishes local services —
directories, local ports, spawned commands, and ft-built webhook/upload origins — to the
internet through an ephemeral Cloudflare Quick Tunnel. Please
report security issues responsibly.

- **Preferred:** open a private security advisory on GitHub
  (`Security` → `Advisories` → `Report a vulnerability`).
- Alternatively, email the maintainer directly.

Please **do not** open a public issue for a suspected vulnerability. We will
acknowledge reports within 72 hours and aim to ship a fix or mitigation within
30 days, keeping reporters informed.

## Scope

The most security-relevant components are:

- **Static file serving** (`src/static_server.rs`) — the confinement guard that
  denies dotfiles and blocks symlink/path-traversal escape from the served root.
  The served tree must be exactly what the operator intended.
- **Webhook receiver** (`src/hook_server.rs`) — what gets recorded from public
  traffic (header allowlist, body cap) and the escape-proof rendering of the
  inspection view.
- **Upload receiver** (`src/drop_server.rs`) — token auth on a public WRITE
  surface, reject-style filename validation, confinement of the download side,
  and the cross-process no-clobber write discipline.
- **Process control** (`src/proc.rs`, `src/spawn.rs`, `src/cloudflared.rs`) —
  PID-reuse-safe signalling and the `PR_SET_PDEATHSIG` orphan-reap logic.
- **On-disk state** (`src/registry.rs`, `src/state.rs`) — file permissions and
  the durability/validation of `registry.json`.

## Hardening posture

- The static server binds **only** to `127.0.0.1`; the public surface is
  cloudflared. The same holds for the hook and drop origins — they are ft-owned
  axum servers inside the worker, never exposed beyond cloudflared.
- `registry.json` and all logs are created mode `0600`; state directories `0700`.
  Hook request stores (`requests.json`) and drop token files (`drop-token`) are
  `0600` as well.
- Dotfiles and any path escaping the canonical served root are refused (404) —
  on the static origin and, verbatim (the same confinement middleware), on the
  drop origin's download side.
- The hook origin records only an allowlist of request headers (Authorization,
  Cookie, and signature headers are never stored) and caps recorded bodies at
  64 KiB. It is otherwise public **by design**: anyone holding the tunnel URL
  can post requests and read everything recorded — the payloads reached that
  same URL anyway. Do not point a hook at traffic you would not publish.
- The drop origin is a public WRITE surface gated by a token: every upload must
  present it (constant-time compare, 401 answered before the body is read),
  filenames are rejected rather than mangled, uploads never overwrite (the
  publish primitive fails on an existing name, cross-process), and per-upload
  plus fixed total-store caps bound what the internet can place on disk.
  Downloads are unauthenticated — anyone with the URL can read the bucket.
- `ft prune` reconciles stale entries left by a crash or reboot.

## Token secrets in query strings

Both token-gated surfaces — the static origin's `--token` and the drop bucket's
upload token — accept the secret as `Authorization: Bearer <secret>` **or** as a
`?token=<secret>` query parameter. The header form is the safe one: a query
string ends up in shell history and in client and intermediary proxy logs.
For the static origin there is one ft-owned sink on top of that: it is the
only origin whose worker opens a `server.log` at all (the hook and drop
origins run no request tracing, so they keep no per-request log). As shipped,
that file keeps no request URLs at all: the worker hardcodes both tracing
filters as literal strings (`EnvFilter::new` never consults `RUST_LOG`, so
there is no environment knob to raise the level), and the hardcoded
`tower_http=info` floor sits above the debug level of tower-http's default
request spans and started/finished events — nothing per-request passes the
filter. The only tower-http event that can is the error-level "response
failed" line, and it carries no URL. `server.log` is still created mode `0600`
(defense in depth), but the real exposure of a `?token=` secret is every log
outside ft that keeps URLs — shell history, client and intermediary proxy
logs. Relatedly, the query form is
percent-decoded, so a secret containing `%` or `+` authenticates in its written
form only via the header.

## `--cors` together with `--token`

On a static origin started with both flags, cross-origin **browser** clients
cannot use Bearer auth: requests carrying an `Authorization` header trigger a
CORS preflight, and this origin deliberately never answers preflights (OPTIONS
reaches the router's uniform 405). The browser never sends the authenticated
GET, so cross-origin browsers are pushed to `?token=` — with the exposure
caveats above. Same-origin pages and non-browser clients (curl, scripts) are
unaffected; the token still gates every request, and the CORS headers are
stamped on the 401/404/405 error responses too.

## Disclosure

Coordinated disclosure is preferred; we credit reporters in the release notes
unless they prefer to remain anonymous.
