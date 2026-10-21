# Should ft add persistent and self-hosted tunnels?

Research report for the ft maintainer, 2026-10-14, revised after two cold-read reviews. All project facts come from the four verified research lanes (each independently fact-checked against primary sources; verifier corrections are folded in). All claims about ft's code were checked in this repo during this session — exact commands and outputs are listed below. Effort estimates and product recommendations are my judgement, grounded in that evidence, and labelled as such.

**Verification set for every repo claim in this report (all run this session):**
- `grep -rnE '\btrait\b|\bbackend\b' src/` → no output, exit 1 (zero hits). A first attempt used `grep -rn "trait |backend"`, which is broken in GNU basic regex (`|` is literal, so zero hits proved nothing) — that command is retracted; the ERE version above is the evidence.
- `grep -rn 'dyn ' src/` → no output (no trait-object sites). `grep -rn 'enum ' src/ --include='*.rs'` (full listing, not `-l`) → 14 enum declarations: `cli.rs:61` Command, `model.rs:9` ServiceStatus, `model.rs:31` ServiceKind, `worker.rs:463` / `hook.rs:98` / `start.rs:699` / `drop.rs:222` ReaderExit, `kill.rs:8` TeardownKind, `kill.rs:21` KillPlan, `doctor.rs:17` CheckStatus, `sanitize.rs:16` ZombieReason, `sanitize.rs:37` Action, `static_server.rs:1645` Seed, `drop_server.rs:270` StoreError. None models a tunnel provider; the origin-classifying `ServiceKind` was read at `src/model.rs:31-48` — variants Static/Proxy/Run/Hook/Drop, i.e. it classifies the *origin*, not the tunnel provider.
- `grep -n 'cloudflared' src/proc.rs` → identity needles at `src/proc.rs:211` (Windows name mapping), `:245` (pid-gated terminate), `:364` (`terminate_orphan` gate); remaining hits are SAFETY-adjacent test fixtures (:709-711, :890-892).
- `sed -n '40,70p' src/proc.rs` → `parent_death_signal()` at `:50-65`: `prctl(PR_SET_PDEATHSIG, SIGKILL)` plus a getppid()==1 refusal. `grep -ni 'job' src/proc.rs src/worker.rs` → Windows `JobGuard` / `create_kill_on_close_job` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` at `src/proc.rs:264-289`.
- `grep -n 'cloudflared' src/cmd/kill.rs src/cmd/prune.rs src/cmd/sanitize.rs src/cmd/doctor.rs` → needles at `src/cmd/kill.rs:65,87,97`, `src/cmd/prune.rs:31`, `src/cmd/sanitize.rs:175,189`; doctor's binary check at `src/cmd/doctor.rs:113-133`, returning `CheckStatus::Warn` (not fail) when cloudflared is absent.
- `grep -rn 'cloudflared::spawn\|drain_and_announce\|pipe_stream' src/` → the four orchestration sites: detached worker `src/worker.rs:306`, foreground start `src/cmd/start.rs:581`, foreground hook `src/cmd/hook.rs:144`, foreground drop `src/cmd/drop.rs:273`; URL-drain helpers `pipe_stream` (`src/worker.rs:609`) and `drain_and_announce` (`src/cmd/start.rs:725`).
- `grep -rn 'find_binary' src/` → `src/cloudflared.rs:23` and `src/cmd/doctor.rs:114`, both calling `toride_runner::discovery::find_binary("cloudflared")`; `grep -n 'toride' Cargo.toml` → the dep is git-rev-pinned at `Cargo.toml:84`.
- Reads: `src/cloudflared.rs` (full file), `src/cmd/open.rs`, `src/model.rs:31-48` and `:82-123`, `src/proc.rs:40-70`, `deny.toml` (license allow-list at :5-19, source locks at :26-30), `.github/workflows/release.yml:25-75` (6-target matrix; comment states aarch64-musl links with rust-lld, which "cannot compile C"), `Cargo.toml` grep (MSRV `rust-version = "1.88"` at :7; `[package.metadata.binstall]` at :54).
- `gh issue list -R freeoxide/tunnel --state all --limit 40` and a demand-keyword search → both empty: the tracker contains **no issues at all**, so no user-request or complaint signals exist either way.

## TL;DR

**Q1 — a persistent tunnel with a persistent domain: Yes, and it should be Cloudflare named tunnels.** A named tunnel is a persistent object in a free Cloudflare account; a proxied CNAME `<hostname> → <tunnel-id>.cfargotunnel.com` gives a stable URL on your own domain. The research found **no zero-account persistent option** — quick tunnels (ft's current mode) die with the process, churn the hostname, and sit on a domain security vendors blocklist. Note the honest trade-off: ft today is fully accountless (the spawn command at `src/cloudflared.rs:66-75` needs no auth), and named mode requires a Cloudflare account **and** moving your domain's DNS to Cloudflare nameservers — so named mode must ship as an opt-in addition, with quick mode staying the zero-config default (my judgement; nothing in the repo establishes accountless operation as a hard requirement, so treat that as a product assumption to confirm).

**Q2 — self-hosted tunnels on your own VPS with custom domains: Yes — but of the nine self-hostable projects detailed in the single-binary section below, add exactly two: sish and frp.** sish's client is plain `ssh -R` (nothing new to install); frp has the best self-hosted custom-domain routing (per-proxy `customDomains`/`subdomain` on vhost HTTP ports). Both MIT/Apache Go single binaries, both actively maintained. **Effort: the backend seam refactor is medium; frp after it is small; sish is small-to-medium** — its happy path is small, but ft's orphan-reaping safety gate does not transfer to a generic `ssh` process (details in ranked item 3), and that fix is safety-critical and not precisely priced.

**Ranked recommendation (effort is my judgement from the verified seam):**

1. **Cloudflare named-tunnel mode — medium.** Answers Q1. Ship it as a persistent *mode* of the existing `cloudflared` module — same binary, same child semantics, same identity needles — so it does not wait on the seam refactor.
2. **Tunnel-backend seam extraction — medium** (pure refactor, no user-visible feature). Prerequisite for Q2, and the place where the provider-identity needles get parameterized (needed by both #3 and #4).
3. **sish backend — small-to-medium** (given #2). Q2 with the lightest possible client: system `ssh -R`. The extra weight over frp is the orphan-identity fix described below.
4. **frp backend — small** (given #2). Q2 with the best custom-domain story: ft generates a temp `frpc.toml` and execs `frpc`, mirroring the cloudflared pattern; the identity needle ("frpc") is clean.

**Do not add:** Pangolin or zrok as shell-out backends (dashboard/account bootstrap, not process-spawn tools); Headscale+Funnel (fails both questions — Funnel is unsupported on Headscale and `*.ts.net`-only anywhere); anything whose hosted instance is dead (bore.pub down since 2026-09-08, localtunnel 503ing) or which has no license (jprq).

**Limits of this report** (read before acting): (a) **no demand evidence** — ft's issue tracker is empty (command above), so the only demand signal is your own ask; the ranking is driven by landscape fit, not user pull; (b) effort estimates are judgement from code reading, not from implementing; (c) the exact cloudflared log line that signals a named tunnel's readiness was not established in the lane facts and must be checked against real output before coding; (d) whether a serveo custom-domain mapping survives reconnects is not established by the lanes (see the serveo section).

## Comparison table

Maintenance dates were checked against the GitHub API on 2026-10-14 by the lanes' verifiers; for proprietary services with no public repo, the cell says so instead of faking a date.

| Name | Hosted / self-host | License & language | Custom domains | Maintenance | Fit for ft |
|---|---|---|---|---|---|
| **Cloudflare Tunnel** | Hosted edge (client self-hostable) | Apache-2.0, Go (cloudflared) | Yes — named tunnels, any hostname in a zone on Cloudflare DNS; free | Very active — 2026.10.0 (2026-10-05), pushed 2026-10-13 | **Best** — current backend; named mode answers Q1 |
| **frp** | Self-host | Apache-2.0, Go | Yes — best-in-lane vhost routing (`customDomains`, `subdomain`, path routing) | Very active — v0.71.0 (2026-08-14) | **Strong** — mirrors ft's exec-a-binary pattern |
| **sish** | Self-host (tuns.sh hosted) | MIT, Go | Yes via wildcard DNS + `--domain`; no per-user arbitrary domains | Very active — v2.24.1 (2026-10-09) | **Strongest client story** — plain `ssh -R`, zero new binary; orphan-gating fix needed |
| **gost** | Self-host | MIT, Go | Yes via tunnel-handler ingress (hostname→UUID) | Active — v3.3.0 (2026-08-30) | Moderate — expressive flags, but tunnel ingress needs YAML |
| **chisel** | Self-host | MIT, Go | No — port forwarding; external reverse proxy required | Active — v1.13.0 (2026-10-11) | Good flags-only fallback; no domains |
| **rathole** | Self-host | Apache-2.0, Rust | No — raw TCP/UDP only | Quiet — no release since v0.5.0 (2023-10); pushes to 2026-08 | Poor for domains; pin binaries yourself |
| **wstunnel** | Self-host | BSD-3-Clause, Rust | No — ports only; domain only on the listener itself | Active — v11.0.0 (2026-09-19) | Good for hostile networks; no domains |
| **zrok** | Both — self-host is heavy; zrok.io hosted | Apache-2.0, Go | Self-host: yes (own wildcard zone). Hosted: free reserved subdomains; custom domain is contact-sales | Very active — v2.0.8 (2026-10-08) | Best CLI in the platform lane; heavy self-host stack |
| **Pangolin** | Self-host | AGPL-3.0 dual Fossorial Commercial (<$100K rev free); TS + Go connectors | Yes — wildcard via DNS-01, `prefer_wildcard_cert: true` | Very active — v1.24.0 (2026-09-30) | **Poor shell-out fit** — dashboard + newt connector, not a spawnable process |
| **Wiredoor** | Self-host | Apache-2.0, TypeScript | Yes — NGINX domain/path routing, auto Let's Encrypt | Active — v1.8.0 (2026-09-22) | **Watch** — single-container VPS platform with the right CLI, but a server ft integrates against, not just execs |
| **pgrok** | Self-host | MIT, Go | Stable per-user subdomains only; no arbitrary per-user domains | Active-ish — v1.7.0 (2026-06-02) | Moderate — mandatory SSO-gated tokens fight instant use |
| **piko** | Self-host | MIT, Go | Yes — host-based via wildcard domain | Active — v0.10.1 (2026-10-07) | Good headless; ft would own all state |
| **portr** | Self-host | AGPL-3.0, Go | Wildcard subdomains under server domain (`*.$PORTR_DOMAIN`) | Active — v2.0.0 (2026-09-27) | Moderate — brings its own 3-container stack |
| **Headscale + Funnel** | Self-host mesh; Funnel SaaS-only | BSD-3-Clause, Go | **No** — Funnel unsupported on Headscale (#1040 closed not_planned); `*.ts.net`-only even on Tailscale | Very active — v0.29.5 (2026-10-13) | **Skip** — fails both questions |
| **Orbien** | Self-host | Apache-2.0, Rust | Unconfirmed — confirmed absent from the full README | Active — v3.8.0 (2026-09-27) | Watch — language match, domains unproven |
| **Tunnelmole** | Both | Client MIT / server AGPL-3.0, TypeScript | Partial — API-key subdomains; full domains manual (DNS + nginx) | Alive, slow — client 2026-04, service 2026-10 | Weak self-host path (default `changeme` monitoring password) |
| **boringproxy** | Self-host | MIT, Go | Yes — own domain, auto-HTTPS | **Dead** — release 2023-01, push 2024-07, website DNS gone | Avoid — architectural reference only |
| **ngrok** | Hosted | Proprietary SaaS (ngrok-go lib MIT) | Paid only — $20/mo PAYG + $0.01/active-hour per domain | Actively developed closed SaaS; ngrok-go repo pushed 2026-10-06 | Good CLI; 1 GB/mo free quota is the pain point |
| **localhost.run** | Hosted | Proprietary; plain-ssh client | $9/mo billed annually | Closed source; live (HTTP 200, 2026-10-14) | Trivial ssh; persistence paywalled |
| **Pinggy** | Hosted | Proprietary | Included in Pro — $3.00/mo ($2.50/mo annual) | Active (docs/blog updated recently; closed service) | Easy; free tier 60-minute timeout churns URLs |
| **serveo** | Hosted | Proprietary; plain-ssh client | Documented free — CNAME + TXT `_serveo-authkey` fingerprint | No public code; live (SSH handshake 2026-10-14), history of abuse-driven outages | Not a persistence answer (free ports live 10–30 min); see body |
| **tuns.sh** (hosted sish) | Hosted | MIT server; paid pico+ instance | Yes — CNAME + TXT `_tuns`; $24/yr | Very active — sish v2.24.1 | Great; natural upgrade path to self-hosted sish |
| **MS dev tunnels** | Hosted | Proprietary + MIT client libs | **No** — `*.devtunnels.ms` only; request closed not_planned (#272, 2024-02-26) | Active closed service — docs FAQ updated 2026-02-12 (lane check); no public repo | Free persistence, no custom domains |
| **Wormhole** | Partial — relay is a self-deployable CF Worker | MIT, Go | Subdomains with GitHub sign-in; full domains undocumented | New — repo 2026-03, solo maintainer, 435 stars | Watch only — bus-factor risk |
| **jprq** | Partial both | **No license** (GitHub `license=null`), Go | Hosted: free is a 1-week trial; custom domains Pro-only. Self-host server-side CNAME support: unconfirmed | Active-ish, solo — pushed 2026-06-20 | Weak — no license to bundle, no real free tier |
| **bore** | Self-host (bore.pub hosted instance **down**) | MIT, Rust | No — host:port only | Slow — v0.6.0 (2025-06); public server down since 2026-09-08 (#202) | Mechanically ideal; no domains, no default endpoint |
| **localtunnel** | Both | MIT, JavaScript — client repo; the separate server repo is also MIT per lane verification | No on hosted | **Dying** — server repo push 2024-03; public server 503s | Poor |

## The Cloudflare named-tunnel path — what ft would actually add

This is Q1's answer and the highest-ranked item. The tunnel is a persistent UUID object in the user's Cloudflare account; `cloudflared` makes outbound-only connections to the edge, and a proxied CNAME `<hostname> → <tunnel-id>.cfargotunnel.com` makes the URL stable. A free account suffices (limits: 1,000 tunnels/account, 1,000 routes/account, 25 active replicas/tunnel — no plan gating anywhere in the tunnel docs).

**Two management modes (from the lane):**

- **Locally-managed:** one interactive `cloudflared tunnel login` (browser) writes `~/.cloudflared/cert.pem`; `tunnel create <NAME>` writes a `<uuid>.json` credentials file; `tunnel route dns <NAME> <hostname>` creates the CNAME; `tunnel run <NAME>` serves it. ft could shell out to all four, but the login step is interactive.
- **Remotely-managed (recommended for ft — fully headless):** one API token (Account: **Cloudflare Tunnel Edit** + Zone: **DNS: Edit**) drives the whole bootstrap via REST — `POST /accounts/{id}/cfd_tunnel` (with `config_src=cloudflare`), `PUT .../cfd_tunnel/{id}/configurations` for ingress, `POST /zones/{zone_id}/dns_records` for the CNAME — and the connector then runs from just the tunnel token. No cert.pem, no credentials JSON.

**Recommended v1 scope (my judgement, stated so it can be overruled):** implement the remotely-managed mode only; leave the cert.pem flow out of v1. Named mode activates via an explicit opt-in — `ft start --hostname app.example.com` plus a token from env/config — while quick tunnels remain the default zero-config path. Credential storage (env var vs config file vs keyring) is deliberately left open as an ft design decision; see the security note below for why the choice matters.

**Concrete ft changes (each anchored to code verified this session):**

1. **Spawn args** — `src/cloudflared.rs:66-75` builds `tunnel --no-autoupdate --url http://127.0.0.1:{port}`; named mode adds a branch running `tunnel run --token <T>` (remote mode). Child semantics are unchanged: same piped streams, same inherited process group, same PDEATHSIG/Job-Object handling (`src/cloudflared.rs:73-84`; `src/proc.rs:50-65` Unix, `:264-289` Windows Job Object).
2. **URL handling inverts.** `extract_url` (`src/cloudflared.rs:32-49`) scans for a `*.trycloudflare.com` host; in named mode the hostname is *configured*, so ft publishes the known URL once cloudflared's piped log lines confirm the connector registered. The exact readiness line is not established in the lane facts — verify against real output before coding.
3. **URL validation changes a security property — state it and mitigate it, don't call it an extension.** Today `is_tunnel_url` (`src/cloudflared.rs:53-59`) requires https + a host ending in `.trycloudflare.com` — a namespace *Cloudflare controls*. Because that suffix is fixed and third-party, a tampered `public_url` in the user-editable registry.json cannot aim the browser launcher (`src/cmd/open.rs:24-31`) at an arbitrary attacker host; it can only aim it at another trycloudflare name. That is the property the current check guarantees, and it is why the gate exists. In named mode the acceptable host becomes "the configured hostname" — and if that hostname is read from the same user-editable registry, exact-matching it verifies nothing: whoever tampered with `public_url` can tamper with the hostname field too, so the check passes by construction. Mitigations (my judgement): (a) anchor the hostname (and tunnel ID) in a config file written once by the operator — outside registry.json — and treat that file as the trust root the gate matches against; (b) when a token is available, re-verify at open-time via the Cloudflare API that the hostname's DNS route points at the recorded tunnel ID; (c) at minimum, document that `ft open`'s guarantee changes from "Cloudflare-controlled namespace" to "equality with a config-resident hostname." The proptests at `src/cloudflared.rs:222-250` pin today's behavior and must be extended for the new rule — never weakened (AGENTS.md).
4. **Registry evolution** — add serde-defaulted fields (backend discriminator, tunnel ID, hostname) following the existing pattern at `src/model.rs:89-122` (`kind`, `dir`, `static_flags`, `command_pid`, `foreground` all default) so old registries deserialize.
5. **Teardown and orphans: free.** The identity needles stay `"cloudflared"` (`src/proc.rs:211,245,364` and the call sites at `src/cmd/kill.rs:65,87,97`, `src/cmd/prune.rs:31`, `src/cmd/sanitize.rs:175,189`), so kill/prune/sanitize and orphan reaping work unchanged.
6. **New work:** the bootstrap REST calls, credential storage, a doctor check for the token/config (the warn-not-fail pattern is at `src/cmd/doctor.rs:113-133`), and an explicit cleanup command for tunnels + DNS records — tunnels accrue toward the 1,000/account cap, so ft should not leak them (judgement: default to keeping the tunnel — persistence is the point — with an `ft tunnel delete`-style teardown).
7. **Dependency note (judgement):** the REST bootstrap needs an HTTP client. A pure-Rust, rustls-based crate keeps the static cross-builds intact — the release matrix builds aarch64-musl by linking with rust-lld, which per the workflow's own comment "cannot compile C" (`.github/workflows/release.yml:64-67`) — and stays inside the deny.toml license allow-list (MIT/Apache/BSD/ISC/MPL/Zlib, `deny.toml:5-19`). It is a deliberate, announced `Cargo.lock` change under the `--locked` policy.

**User-facing payoffs (as supported by the lanes):** persistent HTTPS on the user's own domain, free; and unlike trycloudflare URLs, a custom-domain tunnel does not share the reputation of a hostname space that security vendors blocklist wholesale (McAfee and cloudflared issue #629 per the lane). The lanes document no interstitial for Cloudflare tunnels, but they do not explicitly contrast quick vs named on that axis either — the sourced differentiators are stability, custom naming, and reputation, not interstitials.

**Sequencing trade-off (my judgement):** shipping #1 first means each of the four copy-pasted orchestration sites (`src/worker.rs:306`, `src/cmd/start.rs:581`, `src/cmd/hook.rs:144`, `src/cmd/drop.rs:273`) gains a quick-vs-named branch in its spawn and URL handling — 4 sites carrying 2 modes each, 8 combinations that #2 must then collapse to one parameterized loop. The tax is bounded because the branch is confined to spawn args and URL handling; child semantics, teardown, and needles are identical across modes. #1's value is that Q1 ships now and the product decisions (bootstrap mode, trust anchor, opt-in UX) get de-risked before the trait freezes the interface. Verdict: keep the order, but start #2 from the post-#1 code so the refactor collapses both modes across all four sites. If the named-mode design turns out to need per-flow plumbing beyond args-and-URL, do #2 first instead.

## Cross-cutting design decisions for any second backend (Q2)

These apply to sish and frp alike and were missing from the first draft:

- **Binary sourcing:** per the repo's distribution contract, vendor binaries are **user-installed; ft only PATH-discovers them** via `toride_runner::discovery::find_binary` (used at `src/cloudflared.rs:23` and `src/cmd/doctor.rs:114`; the crate is git-rev-pinned at `Cargo.toml:84`), with `ft doctor` reporting absence as a warn (`src/cmd/doctor.rs:113-133`). Bundling or auto-downloading would break the cargo-binstall single-binary contract (`[package.metadata.binstall]`, `Cargo.toml:54`, mirrored verbatim by the release workflow's asset naming). So: document "install frpc" / "have ssh" in the install message, exactly like cloudflared's `MISSING_MESSAGE` (`src/cloudflared.rs:11-19`).
- **Per-backend server config:** the registry-evolution design in the named-tunnel section covers only Cloudflare fields. Q2 backends need somewhere to record *which server* to dial — sish host/port (and desired subdomain), frp server address + token. Minimum viable shape (my judgement): serde-defaulted per-service fields in the registry (`server`, `hostname`, `token_ref`) following the `src/model.rs:89-122` pattern, plus a named-server profile concept (ft's equivalent of `~/.ssh/config`) so users don't retype VPS addresses per command. This is an open design item that belongs in refactor #2, since the backend trait must carry connection config, not just spawn args.
- **Identity needles:** every backend needs a PID-reuse-safe process identity for kill/prune/sanitize. "cloudflared" and "frpc" are distinctive binary names; "ssh" is not (see sish below). The needles are currently hardcoded in `src/proc.rs:211,245,364` and as literals in kill/prune/sanitize — parameterizing them is part of #2.

## Option details

Fit ratings are the lanes' assessments; rankings, effort, and product recommendations are mine.

### Cloudflare Tunnel (cloudflared) — the incumbent
- **Hosted/self-host:** Cloudflare operates the edge; cloudflared is an outbound connector. Not self-hostable.
- **License/language:** Apache-2.0, Go. **Maintenance:** 2026.10.0 (2026-10-05), pushed 2026-10-13, ~16.1k stars.
- **Custom domains:** free, via named tunnels, any hostname in a Cloudflare zone.
- **Notes:** quick tunnels (today's ft backend) churn hostnames every run, have no uptime guarantee, cap at 200 in-flight requests (429), no SSE, and are increasingly poisoned by abuse (Securonix SERPENTINE#CLOUD, Proofpoint, Cofense reports; vendor-wide blocklisting of trycloudflare.com). The docs restructure means old `/connections/connect-networks/` URLs redirect to `/networks/connectors/` paths.

### Self-hosted single-binary servers

Nine self-hostable projects below; eight ship a native single-binary client (localtunnel's is a Node package).

**frp** — [github.com/fatedier/frp](https://github.com/fatedier/frp)
- Apache-2.0, Go. v0.71.0 (2026-08-14), pushed 2026-10-13, 110k stars.
- TCP/UDP/HTTP/HTTPS + P2P xtcp/stcp. The only lane member with full HTTP virtual-host routing: server-side `vhostHTTPPort` + `subdomainHost`; per-proxy `customDomains = ["app.mydomain.com"]` (DNS A record to the VPS) or `subdomain` under wildcard DNS; path routing via `locations`; `hostHeaderRewrite`. Auth: token (default), OIDC, optional forced TLS since v0.50, per-proxy basic auth. TOML config since v0.52 with verify/reload subcommands.
- **Fit:** strong — ft generates a temp `frpc.toml` and execs `frpc -c file.toml`; one static binary, no daemon or account bootstrap; the "frpc" process name is a clean identity needle. Surprise: frp also grew an SSH server mode (`sshTunnelGateway.bindPort`), so users can connect with plain ssh.

**sish** — [github.com/antoniomika/sish](https://github.com/antoniomika/sish)
- MIT, Go. v2.24.1 (2026-10-09), pushed 2026-10-09, 4,788 stars.
- SSH-based HTTP(S)/WS(S)/TCP/TLS-by-SNI tunnels; no UDP. Server flags: `--domain=example.com`, wildcard `*.example.com` A record at the VPS, `--https-certificate-directory` (bring-your-own wildcard certs; the official compose uses dnsrobocert/Let's Encrypt), SSH-key auth with hot reload. Client is plain OpenSSH: `ssh -p 2222 -R myapp:80:localhost:8080 host` → `https://myapp.example.com`.
- **Fit:** strongest client story surveyed — no vendor binary at all, subdomain choice inline in the command line. **ft-specific hazard (my judgement):** ft spawns `ssh`, and the orphan-reaping gate matches on a process-name needle (today the literal `"cloudflared"` at `src/proc.rs:364`); "ssh" is unusable as that needle because after PID reuse it could match the user's unrelated ssh session and kill it. The fix has two parts: needle parameterization (belongs in refactor #2, which already must touch the needle sites in kill/prune/sanitize) and choosing sish's match string — e.g. the sish host or the `-R` target substring of the cmdline (belongs in #3, and needs its own PID-reuse tests). This unresolved piece is why sish is priced small-to-medium rather than small.

**gost** — [github.com/go-gost/gost](https://github.com/go-gost/gost)
- MIT, Go. v3.3.0 (2026-08-30), pushed 2026-10-07.
- Swiss-army proxy/tunnel (HTTP/2/3, SOCKS, Shadowsocks, SSH, WS, QUIC, KCP, gRPC; relay chains). frp-style reverse-proxy tunnel: clients with `tunnel.id` UUIDs connect to a tunnel handler; ingress rules map hostname patterns (`.example.com` → UUID). Stable v3.3.0 ships only tar.gz/zip assets — deb/rpm appear on nightlies only (verifier-checked).
- **Fit:** moderate — expressive `-L tunnel://...` flags ft could compose, but tunnel-mode ingress needs a YAML file; bigger surface than chisel/bore.

**chisel** — [github.com/jpillora/chisel](https://github.com/jpillora/chisel)
- MIT, Go. Latest v1.13.0 (2026-10-11); repo pushed 2026-10-11.
- Fast TCP/UDP over HTTP/WebSocket; reverses via `R:` syntax; works through CDNs/HTTP proxies. Auth: user/pass or hot-reloadable authfile with per-user address regexes; ECDSA key pinning; TLS via `--tls-domain`. Pure CLI flags, no file config.
- **Fit:** excellent flag-driven client, but it is port forwarding — custom domains require the operator to run nginx/Caddy in front. A fallback, not the pick.

**rathole** — [github.com/rathole-org/rathole](https://github.com/rathole-org/rathole)
- Apache-2.0, Rust. No release since v0.5.0 (2023-10-01) despite pushes into 2026-08 (moved from rapiz1 to rathole-org, confirmed 301).
- High-performance TCP/UDP NAT traversal, frp-like. Mandatory per-service tokens, optional Noise encryption. TOML-only config; same binary auto-detects server/client role.
- **Fit:** poor for this ask — no HTTP layer, so no custom domains. Same language as ft (could be vendored as a library), but the release cadence means ft would pin binaries itself.

**wstunnel** — [github.com/erebe/wstunnel](https://github.com/erebe/wstunnel)
- BSD-3-Clause, Rust. v11.0.0 (2026-09-19, stable WebTransport/HTTP3), pushed 2026-10-12.
- Encrypted TCP/UDP/unix/stdio over WebSocket/HTTP2/WebTransport; built for hostile networks (443-only egress), not host-based routing. `--restrict-to` destination allow-listing, mTLS, flags/env-only config.
- **Fit:** excellent to exec, no domains — a niche second backend at best.

**bore** — [github.com/ekzhang/bore](https://github.com/ekzhang/bore)
- MIT, Rust. v0.6.0 (2025-06-09), pushed 2026-02-04, 68 commits total.
- Minimalist TCP-only tunnel, optional shared-secret HMAC handshake, traffic unencrypted, no HTTP layer. **The public bore.pub instance is down** — connection refused on port 2200 verified 2026-10-14, matching open issue #202 (outage since 2026-09-08) after an earlier abuse-suspension thread (#150).
- **Fit:** the Rust CLI is mechanically ideal for ft, but there are no domains and no working default endpoint. Self-host only.

**jprq** — [github.com/azimjohn/jprq](https://github.com/azimjohn/jprq)
- **No license file** (GitHub API `license=null` — all rights reserved despite public source), Go. Pushed 2026-06-20.
- TCP-protocol tunnels with `-s` subdomains and `--cname` custom domains against the hosted service; the hosted free tier is a 1-week trial, and custom domains require Pro (~$5/mo; pricing page internally inconsistent). Server component exists and the author says it stays self-hostable, but self-host needs its own token issuer and server-side CNAME support is undocumented.
- **Fit:** weak — without a license ft cannot bundle or patch the client.

**localtunnel** — [github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- MIT, JavaScript (Node) — verified for the client repo; the **server is a separate repo** ([localtunnel/server](https://github.com/localtunnel/server), also MIT per the lane's verification), last pushed 2024-03-20. Client repo pushed 2025-08-29, no releases.
- The hosted endpoint 503s over a self-signed cert when probed 2026-10-14; open issues include #737 ("Is LocalTunnel Down ??") and #739 ("someone somehow stole my tunnel"). No auth, no hosted custom domains, Node client rather than a native binary.
- **Fit:** poor.

### Self-hosted platforms (server + management layer)

**Pangolin** — [github.com/fosrl/pangolin](https://github.com/fosrl/pangolin)
- AGPL-3.0 dual-licensed with the Fossorial Commercial License (free under $100K gross revenue); TypeScript monorepo, Go connectors (newt, gerbil). v1.24.0 (2026-09-30), 23,082 stars.
- Identity-aware ingress ("open-source SASE"): Traefik + dashboard, users/roles/OIDC/TOTP, browser VNC/RDP/SSH, auto SSL. Installer deploys 3 Docker containers (pangolin, gerbil, traefik); Gerbil optional. Custom domains: wildcard via DNS-01, `prefer_wildcard_cert: true` (verifier-corrected option name).
- **Fit:** poor shell-out fit — the newt connector needs Pangolin-issued ID+secret and a websocket control channel; ft would have to become an API client, not spawn a process.

**zrok** — [github.com/openziti/zrok](https://github.com/openziti/zrok)
- Apache-2.0, Go. v2.0.8 (2026-10-08), 4,774 stars.
- Sharing platform on an OpenZiti overlay; hosted (zrok.io) or self-hosted. The CLI is the best in the platform lane: `zrok share --headless public http://localhost:3000`, `zrok reserve public` for persistent names. Self-host is the heaviest stack surveyed (~8 processes: OpenZiti controller+router, zrok controller+frontend+metrics, PostgreSQL, RabbitMQ, InfluxDB) and requires wildcard DNS + wildcard TLS. Hosted free tier: 5 GB/**day**, reserved (persistent) subdomains free; custom domains are a contact-sales commercial item.
- **Fit:** strong CLI, wrong shape — account bootstrap (`zrok enable`) before any share, and the self-host stack is far beyond "deploy on a VPS." The hosted free tier is a decent watchlist option for persistent subdomains without a Cloudflare zone (my judgement).

**Wiredoor** — [github.com/wiredoor/wiredoor](https://github.com/wiredoor/wiredoor)
- Apache-2.0, TypeScript. v1.8.0 (2026-09-22), 1,621 stars.
- 2025-2026 entrant: nodes dial in over WireGuard; server terminates TLS and routes via NGINX with auto Let's Encrypt; OAuth2 + per-service IP restrictions. Single Docker container on any VPS. Ships a CLI close to what ft would want: `wiredoor http first-app --domain app.example.com --port 3000`.
- **Verdict (single, replacing the earlier wavering):** **watch item, not a candidate for the ranked list.** ft would have to integrate against a Wiredoor server (node enrollment, dashboard-issued credentials) rather than merely exec a process, so it fails ft's shell-out test today; revisit if it grows a stateless one-shot client (my judgement).

**pgrok** — [github.com/pgrok/pgrok](https://github.com/pgrok/pgrok)
- MIT, Go. v1.7.0 (2026-06-02).
- Multi-tenant SSH reverse tunnels for small teams; stable per-user subdomains, SSO (OIDC) is the core feature. Requires PostgreSQL + an OIDC provider + a TLS-terminating proxy. Client is flag-driven and scriptable, but tokens only come from the SSO-gated console.
- **Fit:** decent mechanics, wrong auth model for ft-style instant ephemeral use; subdomains only, no arbitrary custom domains per user.

**piko** — [github.com/andydunstall/piko](https://github.com/andydunstall/piko)
- MIT, Go. v0.10.1 (2026-10-07), pushed 2026-10-12, 2,197 stars.
- Production-oriented ngrok alternative: single node up to a StatefulSet cluster behind a load balancer. Host-based routing via wildcard domain — any hostname pointed at the proxy routes to the matching endpoint. No admin UI at all.
- **Fit:** good for a headless self-hosted backend; ft would own all state. More moving parts than sish/frp for a single-VPS user.

**portr** — [github.com/amalshaji/portr](https://github.com/amalshaji/portr)
- AGPL-3.0, Go. v2.0.0 (2026-09-27), 3,189 stars. (Older repo URLs — amitsaghe/portr, portr-dev/portr — are dead.)
- Team-oriented tunneling with request inspection/replay. Prod compose verified: 3 containers (caddy-docker-proxy, portr server, postgres:16.2); wildcard subdomain model (`*.$PORTR_DOMAIN`, Cloudflare DNS-01 TLS). No arbitrary per-tunnel custom domains documented.
- **Fit:** moderate — pairing/inspection value, not an ft backend.

**Headscale + Tailscale Funnel** — [github.com/juanfont/headscale](https://github.com/juanfont/headscale)
- BSD-3-Clause, Go. v0.29.5 (2026-10-13), 44,602 stars.
- Answers both questions **no**: Funnel is on Headscale's unsupported list (issue #1040 closed not_planned 2022-12-08, still unsupported in v0.29.5), and Funnel anywhere is `*.ts.net`-only — no custom domains, period.
- **Fit:** skip for this lane. (Headscale itself is fine as a private mesh; it just provides no public ingress.)

**Orbien** — [github.com/orbien-org/orbien](https://github.com/orbien-org/orbien)
- Apache-2.0, Rust (Tokio). v3.8.0 (2026-09-27), 1,329 stars, ~5 MB binary, token auth, TLS/mTLS, web admin UI.
- **Custom domains: confirmed absent** from the full README (verifier read it end-to-end) — closest features are HTTPS transparent forwarding and ACME certs.
- **Fit:** watch — strongest language match of the platform cohort, but the feature this lane is about is unproven.

**Tunnelmole** — [tunnelmole-client](https://github.com/robbie-cahill/tunnelmole-client) / [tunnelmole-service](https://github.com/robbie-cahill/tunnelmole-service)
- Client MIT, server AGPL-3.0; both TypeScript. Client pushed 2026-04-13, service 2026-10-03.
- Self-host requires Node + your own nginx for HTTPS; the monitoring endpoint ships with default password `changeme`.
- **Fit:** acceptable to shell out to `tmole` for a hosted-style URL; too manual to be ft's self-host backend.

**boringproxy** — [github.com/boringproxy/boringproxy](https://github.com/boringproxy/boringproxy)
- MIT, Go. Last release 2023-01-04, last push 2024-07-06; boringproxy.io DNS no longer resolves (verifier-checked).
- Was a good ft shape (single binary, web UI, REST-controlled clients, own-domain auto-HTTPS via TakingNames.io). **Dead — do not adopt; read as an architectural reference only.**

### Hosted SaaS (no VPS)

**ngrok** — [ngrok.com](https://ngrok.com)
- Proprietary SaaS; ngrok-go agent library MIT. Free: 1 persistent static domain, endpoints with no timeout, but 1 GB/mo out, 20k req/mo, 3 endpoints, browser interstitial. Custom domains only from $20/mo PAYG + $0.01/active-hour per domain. AUP actively enforced against phishing/malware.
- **Fit:** excellent CLI to drive, but dominated by Cloudflare named tunnels for this ask (free custom domains vs $20/mo); ft should surface the quota if it ever adds ngrok.

**localhost.run** — [localhost.run](https://localhost.run)
- Proprietary; client is plain `ssh -R 80:localhost:PORT`, nothing to install. Free domains are speed-limited (explicitly an anti-phishing measure); custom domains (CNAME or A+TXT, wildcard supported) are $9/mo billed annually. Live as of 2026-10-14.
- **Fit:** trivial to drive, no machine-readable output, persistence paywalled.

**Pinggy** — [pinggy.io](https://pinggy.io)
- Proprietary. Free: unlimited data transfer but a 60-minute tunnel timeout with random subdomains — URLs churn every reconnect. Pro **$3.00/mo ($2.50/mo annual) includes custom domains** (verifier-corrected: the often-quoted $8/mo figure belongs to LocalXpose). HTTP/TLS/TCP only, not UDP.
- **Fit:** easy, but free-tier churn means reconnect-and-rewrite-URL logic in ft for little gain over Cloudflare.

**serveo** — [serveo.net](https://serveo.net)
- Proprietary since 2017; plain-ssh client. **Documented free custom domains**: CNAME to serveo.net + TXT `_serveo-authkey.<domain>` = your SSH key fingerprint, then `ssh -R sub.example.com:80:localhost:3000 serveo.net`. Free caps: 3 tunnels, 256 KiB/s (1 MiB/s with a key), interstitial, and **ports live 10–30 min**. SSH handshake verified 2026-10-14; history of months-long abuse-driven outages, no status page or SLA.
- **Persistence honesty:** the lane does not establish whether a serveo custom-domain mapping survives a reconnect — and with free tunnels living 10–30 minutes, serveo cannot be recommended as an answer to Q1 regardless. It is at best a free *ephemeral* hosted convenience with nice naming, and even that is undercut by the caps and outage history (my judgement). For a persistent hosted fallback without moving DNS to Cloudflare, tuns.sh ($24/yr) is the defensible pick.

**tuns.sh** (hosted sish, by pico.sh) — [pico.sh/tuns](https://pico.sh/tuns)
- The managed sish instance; pico+ members-only at $2/mo billed yearly ($24/yr). Persistent `{user}-{name}.tuns.sh` hostnames, auto-HTTPS, multi-region. Custom domains: CNAME to tuns.sh + TXT `_tuns.<domain>` — two DNS records, no other ceremony.
- **Fit:** great — `ssh -R dev:80:localhost:3000 tuns.sh` — and the natural on-ramp to self-hosted sish.

**Microsoft dev tunnels** — [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/)
- Free with a Microsoft/Entra/GitHub account. Named tunnels are persistent (deleted after 30 days of inactivity, adjustable); `*.devtunnels.ms` only. Limits: 5 GB/mo, 10 tunnels, 16 MB max request body. Custom domains: **closed as not_planned** (issue #272, 2024-02-26 — Microsoft's stated position, verifier-corrected from "open request").
- **Fit:** free persistence, but zero custom-domain value for this ask.

**Wormhole** — [github.com/MuhammadHananAsghar/wormhole](https://github.com/MuhammadHananAsghar/wormhole)
- MIT, Go client + Cloudflare Workers relay. Repo created 2026-03-07, 435 stars, single maintainer, pushed 2026-09-27. Random URLs without an account; custom subdomains with GitHub sign-in; full custom domains undocumented; the relay is self-deployable but that means bringing your own Cloudflare account — at which point named tunnels are strictly better (my judgement).
- **Fit:** watch only.

### Dead or dying, for the record

Named by the lanes so nobody re-proposes them: **inlets** (OSS repo deleted — went commercial as source-available inlets-pro; community archive at codeberg.org/danb/inlets), **ehang-io/nps** (34k stars, abandoned since 2021), **tunnelto** (client dead since 2022, though the hosted site still sells $4/mo), **localtunnel** and **bore.pub** (see above), **boringproxy** (dead), **jprq** (no license). Context list: [awesome-tunneling](https://github.com/anderspitman/awesome-tunneling).

## Sources

Primary URL(s) per option. Cloudflare links marked *(legacy path)* use the pre-restructure URLs the lanes verified; they redirect to the current `/cloudflare-one/networks/connectors/` tree, so they resolve — the body's redirect note refers to exactly these.

- **Cloudflare Tunnel / named tunnels:** [Tunnel overview](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/), [locally-managed setup](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-local-tunnel/) *(legacy path)*, [remotely-managed via API](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel-api/) *(legacy path)*, [account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/), [quick tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/) *(legacy path)*, [100 MB body cap](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/), [cloudflared repo](https://github.com/cloudflare/cloudflared)
- **frp:** [repo](https://github.com/fatedier/frp), [docs](https://gofrp.org/en/docs/), [releases](https://github.com/fatedier/frp/releases)
- **sish:** [repo](https://github.com/antoniomika/sish), [docs](https://docs.ssi.sh), [releases](https://github.com/antoniomika/sish/releases), [tuns.sh](https://pico.sh/tuns), [pico+ pricing](https://pico.sh/plus)
- **gost:** [repo](https://github.com/go-gost/gost), [tunnel tutorial](https://gost.run/en/tutorials/reverse-proxy-tunnel/), [releases](https://github.com/go-gost/gost/releases)
- **chisel:** [repo](https://github.com/jpillora/chisel), [releases](https://github.com/jpillora/chisel/releases)
- **rathole:** [repo](https://github.com/rathole-org/rathole), [releases](https://github.com/rathole-org/rathole/releases)
- **wstunnel:** [repo](https://github.com/erebe/wstunnel), [releases](https://github.com/erebe/wstunnel/releases)
- **zrok:** [repo](https://github.com/openziti/zrok), [self-host deployment](https://netfoundry.io/docs/zrok/self-hosting/deployment/linux), [hosted pricing](https://zrok.io/pricing/), [custom domains post](https://blog.openziti.io/zrok-custom-domains), [releases](https://github.com/openziti/zrok/releases)
- **Pangolin:** [repo](https://github.com/fosrl/pangolin), [quick install](https://docs.pangolin.net/self-host/quick-install), [wildcard domains](https://docs.pangolin.net/self-host/advanced/wild-card-domains), [newt connector](https://github.com/fosrl/newt)
- **Wiredoor:** [repo](https://github.com/wiredoor/wiredoor), [releases](https://github.com/wiredoor/wiredoor/releases)
- **pgrok:** [repo](https://github.com/pgrok/pgrok), [releases](https://github.com/pgrok/pgrok/releases)
- **piko:** [repo](https://github.com/andydunstall/piko), [releases](https://github.com/andydunstall/piko/releases)
- **Headscale + Funnel:** [Headscale repo](https://github.com/juanfont/headscale), [features page](https://headscale.net/stable/about/features/), [Tailscale Funnel docs](https://tailscale.com/kb/1223/funnel), [issue #1040](https://github.com/juanfont/headscale/issues/1040)
- **Orbien:** [repo](https://github.com/orbien-org/orbien)
- **Tunnelmole:** [client](https://github.com/robbie-cahill/tunnelmole-client), [service](https://github.com/robbie-cahill/tunnelmole-service)
- **boringproxy:** [repo](https://github.com/boringproxy/boringproxy)
- **ngrok:** [free plan limits](https://ngrok.com/docs/pricing-limits/free-plan-limits), [pricing](https://ngrok.com/pricing), [ngrok-go](https://github.com/ngrok/ngrok-go)
- **localhost.run:** [free tier](https://localhost.run/docs/forever-free/), [custom domains](https://localhost.run/docs/custom-domains/)
- **Pinggy:** [site](https://pinggy.io), [custom domain docs](https://pinggy.io/docs/custom_domain/), [compare page](https://pinggy.io/compare/)
- **serveo:** [site](https://serveo.net), [docs](https://serveo.net/docs/)
- **Microsoft dev tunnels:** [docs](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/), [service limits](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#dev-tunnels-limits), [issue #272](https://github.com/microsoft/dev-tunnels/issues/272)
- **Wormhole:** [repo](https://github.com/MuhammadHananAsghar/wormhole)
- **jprq:** [repo](https://github.com/azimjohn/jprq), [site](https://jprq.io)
- **bore:** [repo](https://github.com/ekzhang/bore), [outage issue #202](https://github.com/ekzhang/bore/issues/202)
- **localtunnel:** [client repo](https://github.com/localtunnel/localtunnel), [server repo](https://github.com/localtunnel/server)
- **Context / cohort:** [awesome-tunneling](https://github.com/anderspitman/awesome-tunneling)
