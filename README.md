# Freeoxide Tunnel

Expose a local static directory to the internet through a Cloudflare Quick Tunnel.

Freeoxide Tunnel is a small Rust CLI, shipped as the `ft` binary, that runs a localhost static
file server and fronts it with an ephemeral `cloudflared` Quick Tunnel — giving you a public
`*.trycloudflare.com` URL in seconds, with no Cloudflare account or DNS setup required.

---

## Install

Build from source with Rust / Cargo:

```sh
git clone https://github.com/freeoxide/tunnel.git
cd tunnel
cargo build --release
# binary: target/release/ft
```

Or install it directly from a local checkout:

```sh
cargo install --path .
```

`ft` will then be on your `PATH` (typically `~/.cargo/bin/ft`).

## Prerequisites

[`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
must be installed and on your `PATH`. It is the external binary that creates the Quick Tunnel —
Freeoxide Tunnel never vendors it. If `ft` cannot find it, it prints a friendly install message
and exits.

Install cloudflared: <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/>

## Quick start

Serve a directory and get a public URL:

```sh
ft ./dist
```

`ft` prints the Quick Tunnel URL and keeps the tunnel running as a detached background worker.

## Commands

The default action is START: `ft <dir>` with no subcommand spawns a tunnel for that directory.
Everything else is an explicit subcommand. `<id|name>` accepts either the numeric registry ID
or the service name.

| Command | Description |
| --- | --- |
| `ft <dir>` | Start a tunnel for a directory (the implicit START). |
| `ft <dir> --name <name>` | Start a tunnel with an explicit service name. |
| `ft <dir> --port <port>` | Bind the local server to a specific port. |
| `ft <dir> --foreground` | Run the worker in the foreground instead of detaching. |
| `ft ls` | List all known services. (alias: `ps`) |
| `ft ps` | Alias for `ls`. |
| `ft detail <id\|name>` | Show detailed information about a single service. (alias: `inspect`) |
| `ft kill <id\|name>` | Stop a running service and remove it from the registry. (alias: `stop`) |
| `ft logs <id\|name>` | Print the logs for a service. |
| `ft logs <id\|name> --follow` | Tail the log output (`tail -f` style). |
| `ft open <id\|name>` | Open the public URL of a service in your default browser. |

### Flags for START

- `--name <name>` — explicit service name; defaults to a generated, unique name.
- `--port <port>` — local port to bind on; defaults to a free, allocated port.
- `--foreground` / `-f` — run in the foreground instead of spawning a detached worker.

### Examples

```sh
ft ./dist                                 # start with an auto-generated name and port
ft ./dist --name blog --port 3009         # start with a fixed name and port
ft ./dist --foreground                    # run attached to the current shell
ft ls                                     # list services
ft ps                                     # same as `ft ls`
ft detail blog                            # inspect by name
ft detail 2                               # inspect by numeric ID
ft kill blog                              # stop and remove
ft logs blog                              # print logs
ft logs blog --follow                     # stream logs
ft open blog                              # open the public URL in a browser
```

## How it works

`ft <dir>` spawns a detached worker process (a new session via `setsid`) that:

1. Starts a localhost static file server for `<dir>` (axum + tower-http) on the chosen port.
2. Launches `cloudflared` as a Quick Tunnel pointing at `http://127.0.0.1:<port>`.
3. Captures the generated `https://<random>.trycloudflare.com` URL and records it in the registry.

The worker survives shell exit and runs until you stop it with `ft kill`, which signals the
worker's process group so the local server and `cloudflared` are torn down together. Use
`--foreground` to run the worker attached to your terminal instead.

## State location

All state lives under:

```
~/.local/state/freeoxide/tunnel/
├── registry.json        # service registry (IDs, names, ports, URLs, status)
├── registry.lock        # advisory lock serializing registry mutations
└── services/<name>/     # per-service state and logs
    ├── worker.log
    ├── server.log
    └── tunnel.log
```

The root honors `$XDG_STATE_HOME` (defaulting to `~/.local/state`). Service names are reduced to
a single safe path segment, so a registry-controlled name can never escape `services/` via `..`
or separators.

## Platform support

- **Linux** — primary target. Process supervision uses `nix`, `setsid`, and `/proc`.
- **macOS** — partial / fallback support; some process-management paths are weaker than on Linux.
- **Windows** — unsupported. The code relies on POSIX process groups, signals, and `/proc`, which
  Windows does not provide.

## Project status

**MVP** — complete and usable. Functional start/stop/list/logs flow for static directories over
Cloudflare Quick Tunnels.

> Branded as **Freeoxide Tunnel** · binary `ft` · repo [freeoxide/tunnel](https://github.com/freeoxide/tunnel) · [tunnel.freeoxide.com](https://tunnel.freeoxide.com)

## License

MIT
