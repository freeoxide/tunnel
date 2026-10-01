#!/usr/bin/env python3
"""CLI wall-clock harness for `ft sanitize`.
MEDIAN_S=<seconds> is the last stdout line; ~1.0 s with 5 zombies (one
overlapped 750 ms reprobe window) — near N x 750 ms the probes serialized."""

import argparse
import json
import os
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

VERSION_RUNS = 7
LS_RUNS = 7
# Far outside any real pid namespace on a test host (same convention as
# tests/integration.rs).
DEAD_PID_BASE = 4_000_000


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def dead_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cmdline_contains(pid: int, needle: str) -> bool:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return needle in f.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        try:
            out = subprocess.run(
                ["ps", "-o", "command=", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return needle in out.stdout
        except (OSError, subprocess.SubprocessError):
            return False


def spawn_decoy_worker() -> int:
    read_fd, write_fd = os.pipe()
    # Double-fork so init reaps the decoy: an unreaped one holds ft's
    # group poll to its 1.5 s deadline (proc.rs) and inflates MEDIAN_S.
    intermediate = os.fork()
    if intermediate == 0:
        os.close(read_fd)
        try:
            decoy = os.fork()
            if decoy == 0:
                # Own session => pgid == this pid, so the group kill signaled
                # at worker_pid reaches exactly the decoy and its `sleep`.
                os.setsid()
                os.close(write_fd)
                # Trailing "run-worker" $0 + endless loop keep the needle in
                # /proc/cmdline; sh tail-execs a lone final (proc.rs pid_alive).
                os.execv("/bin/sh", ["sh", "-c", "while :; do sleep 30; done", "run-worker"])
                os._exit(127)
            os.write(write_fd, str(decoy).encode())
            os._exit(0)
        except BaseException:
            os._exit(111)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as pipe:
        handed_over = pipe.read()
    os.waitpid(intermediate, 0)
    if not handed_over:
        raise RuntimeError("double-fork failed to hand over the decoy pid")
    pid = int(handed_over)
    # Readiness barrier: the cmdline the probe reads can lag the fork.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if cmdline_contains(pid, "run-worker"):
            return pid
        time.sleep(0.02)
    kill_decoy(pid)
    raise RuntimeError(f"decoy {pid} never became probe-ready")


def kill_decoy(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def seed(xdg_root: str, zombies: int) -> list[int]:
    decoys = [spawn_decoy_worker() for _ in range(zombies)]
    services = []
    for i in range(zombies):
        # Accepted race: the dropped port may rebind before ft probes it.
        port = dead_loopback_port()
        services.append(
            {
                "id": i + 1,
                "name": f"bench-zombie-{i}",
                "kind": "proxy",
                "dir": None,
                "port": port,
                "local_url": f"http://127.0.0.1:{port}",
                # public_url must be Some: services without one never reach
                # the double probe (sanitize.rs), and MEDIAN_S collapses.
                "public_url": f"https://bench-{i}.trycloudflare.com",
                "worker_pid": decoys[i],
                "tunnel_pid": DEAD_PID_BASE + i,
                # static_flags / command_pid omitted: serde defaults (model.rs).
                "created_at": now_iso(),
                "state_dir": os.path.join(
                    xdg_root, "freeoxide", "tunnel", "services", f"bench-zombie-{i}"
                ),
                "foreground": False,
            }
        )
    registry = {"next_id": zombies + 1, "services": services}
    reg_dir = os.path.join(xdg_root, "freeoxide", "tunnel")
    os.makedirs(reg_dir, exist_ok=True)
    with open(os.path.join(reg_dir, "registry.json"), "w", encoding="utf-8") as f:
        json.dump(registry, f)
    return decoys


def child_env(xdg_root: str) -> dict:
    env = os.environ.copy()
    env["XDG_STATE_HOME"] = xdg_root
    # Hermeticity: a stray RUST_LOG would pollute the measured process.
    env["RUST_LOG"] = ""
    return env


def run_timed(ft: str, args: list[str], env: dict) -> tuple[float, subprocess.CompletedProcess]:
    start = time.perf_counter()
    proc = subprocess.run(
        [ft, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    elapsed = time.perf_counter() - start
    return elapsed, proc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ft", required=True, help="path to the ft binary to measure")
    parser.add_argument("--zombies", type=int, default=5, help="double-probe services per run")
    parser.add_argument("--runs", type=int, default=31, help="sanitize runs in the median")
    args = parser.parse_args()

    ft = os.path.abspath(args.ft)
    if not (os.path.isfile(ft) and os.access(ft, os.X_OK)):
        print(f"error: {ft} is not an executable file", file=sys.stderr)
        return 2

    xdg_root = tempfile.mkdtemp(prefix="ft-sanitize-bench-")
    ls_root = tempfile.mkdtemp(prefix="ft-ls-bench-")
    env = child_env(xdg_root)
    try:
        version_times = []
        for _ in range(VERSION_RUNS):
            elapsed, proc = run_timed(ft, ["--version"], env)
            if proc.returncode != 0:
                print(f"error: `ft --version` failed: {proc.stderr}", file=sys.stderr)
                return 1
            version_times.append(elapsed)

        ls_env = child_env(ls_root)
        ls_times = []
        for _ in range(LS_RUNS):
            elapsed, proc = run_timed(ft, ["ls"], ls_env)
            if proc.returncode != 0:
                print(f"error: `ft ls` failed: {proc.stderr}", file=sys.stderr)
                return 1
            ls_times.append(elapsed)

        sanitize_times = []
        first_output = None
        for run in range(args.runs):
            # sanitize tears the zombies down, so every run re-seeds
            decoys = seed(xdg_root, args.zombies)
            try:
                elapsed, proc = run_timed(ft, ["sanitize"], env)
                if proc.returncode != 0:
                    print(
                        f"error: `ft sanitize` run {run} failed "
                        f"(rc={proc.returncode}): {proc.stderr}",
                        file=sys.stderr,
                    )
                    return 1
                if first_output is None:
                    first_output = proc.stdout.strip()
                sanitize_times.append(elapsed)
            finally:
                for pid in decoys:
                    kill_decoy(pid)

        print(f"ZOMBIES={args.zombies}")
        print(f"RUNS={args.runs}")
        if first_output is not None:
            print(f"FIRST_RUN_OUTPUT={first_output!r}")
        print(f"VERSION_S={statistics.median(version_times):.3f}")
        print(f"LS_S={statistics.median(ls_times):.3f}")
        print(f"MEDIAN_S={statistics.median(sanitize_times):.3f}", flush=True)
        return 0
    finally:
        shutil.rmtree(xdg_root, ignore_errors=True)
        shutil.rmtree(ls_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
