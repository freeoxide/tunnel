#!/bin/sh
# Freeoxide Tunnel (`ft`) installer for Linux and macOS.
#
# Designed to be safe to pipe to a POSIX shell:
#
#     curl -fsSL https://github.com/freeoxide/tunnel/raw/main/install.sh | sh
#
# It downloads the prebuilt `ft` binary for the current platform from the
# GitHub release, verifies it against the published SHA256SUMS, and installs
# it into an install dir on PATH (default $HOME/.local/bin). No sudo, no
# reading stdin, no reliance on $0. Pin a release with `--version v0.1.0`;
# install elsewhere with `--to /some/dir`.

set -eu

# ---------------------------------------------------------------------------
# Defaults / constants
# ---------------------------------------------------------------------------

REPO="freeoxide/tunnel"
# The single archive shipped per release. The asset name is fixed; only the
# release directory (latest/download vs download/<version>) changes.
ASSET_NAME="freeoxide-tunnel"
# Default install dir matches the XDG user-bin convention ($HOME/.local/bin);
# never touch system dirs — the installer is deliberately sudo-free.
INSTALL_DIR="${HOME}/.local/bin"
VERSION="latest"

# ---------------------------------------------------------------------------
# Messaging helpers — everything user-facing goes through these so the output
# has a consistent shape. Info/notice to stdout, errors to stderr.
# ---------------------------------------------------------------------------

info()  { printf '   %s\n' "$*"; }

# `err`/`die` accept one or more string fragments and concatenate them with no
# separator, then interpret backslash escapes (so multi-line callers may embed
# "\n" in their message, e.g. the checksum-mismatch block). Single-line callers
# pass a single arg and are unaffected. We avoid "$*" here because it joins
# args with a space, which would mangle "\n"-split continuation lines.
err() {
    # Build the message by direct concatenation of all args.
    msg=
    for fragment in "$@"; do
        msg="${msg}${fragment}"
    done
    printf 'install: %b\n' "${msg}" >&2
}

die() {
    err "$@"
    exit 1
}

# ---------------------------------------------------------------------------
# argv parsing — a plain while loop, no getopts (portable and easy to reason
# about). Unknown flags are a hard error rather than silently ignored.
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --to)
            [ $# -ge 2 ] || die "--to requires a directory argument"
            INSTALL_DIR="$2"
            shift 2
            ;;
        --to=*)
            INSTALL_DIR="${1#--to=}"
            shift
            ;;
        --version)
            [ $# -ge 2 ] || die "--version requires a version argument"
            VERSION="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#--version=}"
            shift
            ;;
        -h|--help)
            cat <<'EOF'
install.sh — install Freeoxide Tunnel (`ft`)

Usage: install.sh [--to <dir>] [--version <v>]

Options:
  --to <dir>       Install directory (default: $HOME/.local/bin).
  --version <v>    Release to install, e.g. v0.1.0 (default: latest).

When piped to sh (curl -fsSL .../install.sh | sh), pass options after the
pipe with `sh -s -- --to /opt/ft --version v0.1.0`.
EOF
            exit 0
            ;;
        *)
            die "unknown option: $1 (see --help)"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Platform detection. uname -s/-m is the portable cross-Unix way; we support
# exactly the four release targets and refuse anything else with a clear
# message.
# ---------------------------------------------------------------------------

os_raw=$(uname -s 2>/dev/null || true)
arch_raw=$(uname -m 2>/dev/null || true)

target=
case "${os_raw}-${arch_raw}" in
    Linux-x86_64)        target="x86_64-unknown-linux-musl" ;;
    Linux-aarch64)       target="aarch64-unknown-linux-musl" ;;
    Linux-arm64)         target="aarch64-unknown-linux-musl" ;;
    Darwin-x86_64)       target="x86_64-apple-darwin" ;;
    Darwin-arm64)        target="aarch64-apple-darwin" ;;
    *)
        die "unsupported platform: os='${os_raw:-unknown}' arch='${arch_raw:-unknown}'.\n" \
            "Supported: linux x86_64/aarch64, macOS x86_64/arm64."
        ;;
esac

info "Detected platform: ${os_raw} ${arch_raw} -> ${target}"

# ---------------------------------------------------------------------------
# Resolve the release directory and asset URL. `latest` maps to the
# releases/latest/download shortcut; a pinned version (with or without a
# leading v) maps to releases/download/<v>/... We normalize the pinned form to
# a leading-v so callers can pass either "0.1.0" or "v0.1.0".
# ---------------------------------------------------------------------------

archive="${ASSET_NAME}-${target}.tgz"

if [ "${VERSION}" = "latest" ]; then
    release_url="https://github.com/${REPO}/releases/latest/download"
    version_label="latest"
else
    # Normalize to a leading "v". A caller may pass "0.1.0" or "v0.1.0".
    pinned="${VERSION}"
    case "${pinned}" in
        v*) ;;
        *)  pinned="v${pinned}" ;;
    esac
    release_url="https://github.com/${REPO}/releases/download/${pinned}"
    version_label="${pinned}"
fi

archive_url="${release_url}/${archive}"
sums_url="${release_url}/SHA256SUMS"

info "Release: ${version_label}"
info "Asset:   ${archive}"

# ---------------------------------------------------------------------------
# Preflight: the tools we unconditionally need. curl, tar, mktemp are
# mandatory; the hash tool is resolved below (sha256sum > sha256 -r > shasum).
# ---------------------------------------------------------------------------

command -v curl >/dev/null 2>&1   || die "curl is required but was not found in PATH."
command -v tar >/dev/null 2>&1    || die "tar is required but was not found in PATH."

# mktemp -d is in POSIXIssue8 / present on every Linux+macOS in the wild; if a
# host lacks it, fail loudly rather than inventing an insecure fallback.
TMPDIR_ROOT=$(mktemp -d 2>/dev/null) || die "failed to create a temp directory with mktemp."

# Always tear down the temp tree, even on success, signal, or error. The trap
# fires on normal exit and on INT/TERM; `set -e` failures route through EXIT.
# Quoting "$TMPDIR_ROOT" survives spaces in the path; rm -f tolerates a missing
# hash file if we never got that far.
cleanup() {
    rc=$?
    [ -n "${TMPDIR_ROOT}" ] && rm -rf "${TMPDIR_ROOT}"
    exit "${rc}"
}
trap cleanup EXIT
trap cleanup INT
trap cleanup TERM

# ---------------------------------------------------------------------------
# Resolve a SHA-256 tool. Order: sha256sum (coreutils, Linux), then
# `sha256 -r` (macOS / CommonCrypto), then `shasum -a 256` (Perl, both). The
# helper echoes the hex digest of its first argument (a file path).
# ---------------------------------------------------------------------------

sha_tool=
compute_sha() {
    # $1 = file to hash; echoes the lowercase hex digest. `sha_tool` may hold a
    # MULTI-WORD command ("sha256 -r", "shasum -a 256"), so it MUST be left
    # UNQUOTED: POSIX field-splitting then yields the command plus its flags as
    # separate words. Quoting it ("${sha_tool}") collapses "sha256 -r" into one
    # bogus command name and breaks every macOS install (which lacks sha256sum
    # and falls through to this branch). sha_tool is assigned only from the
    # hard-coded values below, never user input, so the unquoted expansion is
    # safe here.
    ${sha_tool} "$1" | awk '{ print $1 }'
}

if command -v sha256sum >/dev/null 2>&1; then
    sha_tool="sha256sum"
elif command -v sha256 >/dev/null 2>&1; then
    # macOS `sha256 -r` prints "<hash> <path>"; the bare form differs, so force
    # the reverse/BSD-style output that we then split on whitespace.
    sha_tool="sha256 -r"
elif command -v shasum >/dev/null 2>&1 && shasum -a 256 </dev/null >/dev/null 2>&1; then
    sha_tool="shasum -a 256"
else
    die "no SHA-256 tool found (need one of: sha256sum, sha256, shasum)."
fi

# ---------------------------------------------------------------------------
# Download the archive and the SHA256SUMS manifest from the same release dir.
# ---------------------------------------------------------------------------

info "Downloading ${archive} ..."
# -fL: fail (non-zero) on HTTP errors and follow redirects (GitHub release
# assets 302 to the CDN). -s keeps it quiet; stderr is discarded because we
# surface our own message via the ok/fail sentinel below.
http_code=$(curl -fsSL -o "${TMPDIR_ROOT}/${archive}" "${archive_url}" 2>/dev/null && echo ok || echo fail)
if [ "${http_code}" != "ok" ]; then
    die "failed to download ${archive_url} (HTTP error or network failure)."
fi

info "Downloading SHA256SUMS ..."
# A missing SHA256SUMS is a hard failure: verification is mandatory, never
# silently skipped — an unsigned/unverifiable binary is treated as untrusted.
if ! curl -fsSL -o "${TMPDIR_ROOT}/SHA256SUMS" "${sums_url}" 2>/dev/null; then
    die "failed to download ${sums_url}.\n" \
        "The release is missing SHA256SUMS, so the archive cannot be verified; " \
        "refusing to install."
fi

# ---------------------------------------------------------------------------
# Verify: pull the expected hash for *our* asset out of the manifest, compute
# the archive's hash, and compare. The manifest lists every asset in the
# release; we grep for the exact asset name and take the first match.
# ---------------------------------------------------------------------------

# Match the trailing asset name so we are not fooled by a different asset that
# merely contains ours as a substring. The field order in a sha256sum file is
# "<hash>  <name>" (two spaces); awk handles either one or two.
expected=$(awk -v want="${archive}" '$2 == want { print $1; exit }' "${TMPDIR_ROOT}/SHA256SUMS")
if [ -z "${expected}" ]; then
    die "SHA256SUMS does not contain an entry for '${archive}'.\n" \
        "The release manifest and the asset name are out of sync; refusing to install."
fi

actual=$(compute_sha "${TMPDIR_ROOT}/${archive}")
# Normalize to lowercase before comparing (BSD/macOS tools have emitted
# uppercase historically); both sides are hex, so tr is safe.
expected=$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')
actual=$(printf '%s' "${actual}"   | tr '[:upper:]' '[:lower:]')

if [ "${expected}" != "${actual}" ]; then
    die "checksum mismatch for '${archive}'.\n" \
        "  expected: ${expected}\n" \
        "  actual:   ${actual}\n" \
        "The downloaded archive may be corrupted or tampered with; refusing to install."
fi
info "Checksum OK."

# ---------------------------------------------------------------------------
# Extract and install. The archive ships `ft` at its root. We chmod +x the
# binary, ensure the install dir exists, and move it into place.
# ---------------------------------------------------------------------------

info "Extracting ..."
# Strip-components is unnecessary: the archive root is the binary. Extract into
# the temp dir so a partial archive cannot leak into the install dir.
(
    cd "${TMPDIR_ROOT}" || exit 1
    tar -xzf "${archive}"
)

if [ ! -f "${TMPDIR_ROOT}/ft" ]; then
    die "archive did not contain an 'ft' binary at its root."
fi
chmod +x "${TMPDIR_ROOT}/ft"

mkdir -p "${INSTALL_DIR}" || die "could not create install directory: ${INSTALL_DIR}"

# mv over an existing ft atomically replaces it (same filesystem in the common
# case); the temp-tree trap cleans up the old binary's temp copy regardless.
mv "${TMPDIR_ROOT}/ft" "${INSTALL_DIR}/ft"

# ---------------------------------------------------------------------------
# Verify the installed binary actually runs, then advise on PATH if needed.
# ---------------------------------------------------------------------------

FT_BIN="${INSTALL_DIR}/ft"
installed_version=$("${FT_BIN}" --version 2>/dev/null) || {
    die "installed binary at ${FT_BIN} failed to report its version."
}

info "Installed: ${FT_BIN}"
info "Version:   ${installed_version}"

# Is the install dir already on PATH? A literal substring check is good enough
# here — we compare against colon-delimited PATH segments to avoid false
# positives (e.g. /opt/bin matching a dir named /opt/binx).
on_path=no
oldifs="${IFS}"
IFS=":"
for seg in ${PATH:-}; do
    if [ "${seg}" = "${INSTALL_DIR}" ]; then
        on_path=yes
        break
    fi
done
IFS="${oldifs}"

if [ "${on_path}" = "no" ]; then
    cat >&2 <<EOF

note: '${INSTALL_DIR}' is not on your PATH.

  Add it to your shell startup file, then open a new shell:

    export PATH="${INSTALL_DIR}:\$PATH"

  Edit ~/.bashrc and ~/.profile (bash), or ~/.zshrc (zsh).
  Run 'ft --version' to confirm.
EOF
fi

info "Done."
