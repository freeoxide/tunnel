# Freeoxide Tunnel

`ft` is a small Rust CLI that exposes local services to the internet through
ephemeral Cloudflare Quick Tunnels (`*.trycloudflare.com`) — no Cloudflare
account or DNS setup required. It can serve a static directory, front a local
port you already serve, or run a command and tunnel it as one unit; `ft hook`
and `ft drop` add a webhook inspector and a token-gated upload bucket.

## Install

```sh
cargo binstall freeoxide-tunnel          # prebuilt binary
cargo install freeoxide-tunnel --locked  # build from crates.io
```

[`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads)
must be installed and on your `PATH`.

## Usage

```sh
ft ./dist                          # serve a directory and print its public URL
ft proxy 3000                      # tunnel a local server already on port 3000
ft run --port 3000 -- npm run dev  # run a command and tunnel it as one unit
ft ls                              # list services
ft kill <id|name>                  # stop a service and remove it
```

Run `ft --help` — or any subcommand's `--help` — for the full command and
flag list.

## License

MIT — see [LICENSE](LICENSE).
