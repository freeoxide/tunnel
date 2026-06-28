# Security Policy

## Reporting a Vulnerability

This project has a public-facing security surface: `ft` publishes a local
directory to the internet through an ephemeral Cloudflare Quick Tunnel. Please
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
- **Process control** (`src/proc.rs`, `src/spawn.rs`, `src/cloudflared.rs`) —
  PID-reuse-safe signalling and the `PR_SET_PDEATHSIG` orphan-reap logic.
- **On-disk state** (`src/registry.rs`, `src/state.rs`) — file permissions and
  the durability/validation of `registry.json`.

## Hardening posture

- The static server binds **only** to `127.0.0.1`; the public surface is
  cloudflared.
- `registry.json` and all logs are created mode `0600`; state directories `0700`.
- Dotfiles and any path escaping the canonical served root are refused (404).
- `ft prune` reconciles stale entries left by a crash or reboot.

## Disclosure

Coordinated disclosure is preferred; we credit reporters in the release notes
unless they prefer to remain anonymous.
