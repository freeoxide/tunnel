#!/usr/bin/env python3
"""CLI wall-clock harness for `ft sanitize` — the double-probe wait this
campaign overlapped (serialized at baseline, concurrent since 49cfdd5).

Command line:
    python3 benches/sanitize_median.py --ft <binary> --zombies 5 --runs 31

Isolation: every `ft` invocation runs with XDG_STATE_HOME pointed at a
private tempdir (child env only — the pattern tests/integration.rs uses), so
the real user state is never touched.

Seeding, re-done before EVERY run (sanitize tears the zombies down): a
service only reaches the double probe when its worker looks alive
(proc::pid_alive: the cmdline contains "run-worker") AND public_url is set;
then a dead origin port costs probe + 750 ms (REPROBE_DELAY) + probe. So
each zombie is seeded as:
  - worker_pid  = a decoy `sh` whose argv carries "run-worker" (its own
                  session, so teardown's group-kill is contained to it),
  - port        = a dead loopback port (bind ephemeral, drop — connect fails
                  instantly with ECONNREFUSED, the delay dominates),
  - tunnel_pid  = a pid nothing owns (4_000_000+i, far outside any real pid
                  namespace) — exercises the dead tunnel-pid lookups in
                  teardown (pid_matches("cloudflared") miss),
  - kind proxy, dir null, public_url set, foreground false — a registry.json
    shape model.rs accepts (see its serde defaults).
Since the double-probes went concurrent (49cfdd5), the 5 zombies overlap
their gaps into ONE 750 ms window: MEDIAN_S ~1.0 s, with process startup and
teardown riding along. If MEDIAN_S ever loses that window, the harness
stopped measuring the thing being guarded; if it climbs back toward
N x 750 ms (~3.75 s for 5 zombies), the overlap regressed.

Output: context lines, then VERSION_S=, LS_S= (medians of 7 runs each
against the isolated state), and finally MEDIAN_S=<seconds> as the LAST
stdout line.
"""

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
    """Bind an ephemeral loopback listener, drop it: the port is (almost
    certainly) dead — the same accepted-risk pattern as the integration
    tests."""
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
    """A decoy worker via the classic double-fork: the decoy `sh` ends up
    session-leader AND parented to init. Its argv carries the `run-worker`
    needle pid_alive probes for (the trailing arg is the script's $0, so `sh`
    keeps it in its cmdline; the `-c` body must stay an endless LOOP — shells
    tail-exec a final command, replacing argv). Being init-parented matters
    for the measurement: when sanitize group-kills the decoy, init reaps it
    at once, so ft's group-emptiness poll (shutdown_process_group) ends after
    ~one 50 ms step instead of riding its 1.5 s deadline against an unreaped
    zombie — which would otherwise swamp the double-probe wait this harness
    exists to time."""
    read_fd, write_fd = os.pipe()
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
                os.execv("/bin/sh", ["sh", "-c", "while :; do sleep 30; done", "run-worker"])
                os._exit(127)  # exec failed
            os.write(write_fd, str(decoy).encode())
            os._exit(0)  # orphan the decoy -> init re-parents (and reaps) it
        except BaseException:
            os._exit(111)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as pipe:
        handed_over = pipe.read()
    os.waitpid(intermediate, 0)  # reap the intermediate; the decoy is init's now
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
    """Defensive reap: sanitize's teardown should already have killed the
    group (the decoy is init-parented, so init reaps it); a survivor must
    never outlive the harness — its loop is endless."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def seed(xdg_root: str, zombies: int) -> list[int]:
    """Write a fresh registry.json with `zombies` double-probe candidates and
    return the decoy pids it references."""
    decoys = [spawn_decoy_worker() for _ in range(zombies)]
    services = []
    for i in range(zombies):
        port = dead_loopback_port()
        services.append(
            {
                "id": i + 1,
                "name": f"bench-zombie-{i}",
                "kind": "proxy",
                "dir": None,
                "port": port,
                "local_url": f"http://127.0.0.1:{port}",
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
    # An EMPTY isolated state for the ls timings (never the user's own).
    ls_root = tempfile.mkdtemp(prefix="ft-ls-bench-")
    env = child_env(xdg_root)
    try:
        # --- `ft --version`: process startup + arg parse, no state ----------
        version_times = []
        for _ in range(VERSION_RUNS):
            elapsed, proc = run_timed(ft, ["--version"], env)
            if proc.returncode != 0:
                print(f"error: `ft --version` failed: {proc.stderr}", file=sys.stderr)
                return 1
            version_times.append(elapsed)

        # --- `ft ls` against an empty isolated state ------------------------
        ls_env = child_env(ls_root)
        ls_times = []
        for _ in range(LS_RUNS):
            elapsed, proc = run_timed(ft, ["ls"], ls_env)
            if proc.returncode != 0:
                print(f"error: `ft ls` failed: {proc.stderr}", file=sys.stderr)
                return 1
            ls_times.append(elapsed)

        # --- `ft sanitize`: re-seed before EVERY run ------------------------
        sanitize_times = []
        first_output = None
        for run in range(args.runs):
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
        # Contract: the LAST stdout line is the sanitize median.
        print(f"MEDIAN_S={statistics.median(sanitize_times):.3f}", flush=True)
        return 0
    finally:
        shutil.rmtree(xdg_root, ignore_errors=True)
        shutil.rmtree(ls_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
