#!/bin/sh

set -eu

REPO="freeoxide/tunnel"
ASSET_NAME="freeoxide-tunnel"
INSTALL_DIR="${HOME}/.local/bin"
VERSION="latest"

info()  { printf '   %s\n' "$*"; }

# "$*" joins args with a space, which would mangle the "\n"-split
# continuation lines the multi-arg err/die callers pass.
err() {
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

archive="${ASSET_NAME}-${target}.tgz"

if [ "${VERSION}" = "latest" ]; then
    release_url="https://github.com/${REPO}/releases/latest/download"
    version_label="latest"
else
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

command -v curl >/dev/null 2>&1   || die "curl is required but was not found in PATH."
command -v tar >/dev/null 2>&1    || die "tar is required but was not found in PATH."

TMPDIR_ROOT=$(mktemp -d 2>/dev/null) || die "failed to create a temp directory with mktemp."

cleanup() {
    rc=$?
    [ -n "${TMPDIR_ROOT}" ] && rm -rf "${TMPDIR_ROOT}"
    exit "${rc}"
}
trap cleanup EXIT
trap cleanup INT
trap cleanup TERM

sha_tool=
compute_sha() {
    # SAFETY: leave ${sha_tool} unquoted — it holds a multi-word command
    # ("sha256 -r", "shasum -a 256") that needs POSIX field splitting, and is
    # assigned only from the hard-coded values below, never user input.
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

info "Downloading ${archive} ..."
# -L is load-bearing: GitHub release assets 302 to the CDN.
http_code=$(curl -fsSL -o "${TMPDIR_ROOT}/${archive}" "${archive_url}" 2>/dev/null && echo ok || echo fail)
if [ "${http_code}" != "ok" ]; then
    die "failed to download ${archive_url} (HTTP error or network failure)."
fi

info "Downloading SHA256SUMS ..."
if ! curl -fsSL -o "${TMPDIR_ROOT}/SHA256SUMS" "${sums_url}" 2>/dev/null; then
    die "failed to download ${sums_url}.\n" \
        "The release is missing SHA256SUMS, so the archive cannot be verified; " \
        "refusing to install."
fi

expected=$(awk -v want="${archive}" '$2 == want { print $1; exit }' "${TMPDIR_ROOT}/SHA256SUMS")
if [ -z "${expected}" ]; then
    die "SHA256SUMS does not contain an entry for '${archive}'.\n" \
        "The release manifest and the asset name are out of sync; refusing to install."
fi

actual=$(compute_sha "${TMPDIR_ROOT}/${archive}")
expected=$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')
actual=$(printf '%s' "${actual}"   | tr '[:upper:]' '[:lower:]')

if [ "${expected}" != "${actual}" ]; then
    die "checksum mismatch for '${archive}'.\n" \
        "  expected: ${expected}\n" \
        "  actual:   ${actual}\n" \
        "The downloaded archive may be corrupted or tampered with; refusing to install."
fi
info "Checksum OK."

info "Extracting ..."
(
    cd "${TMPDIR_ROOT}" || exit 1
    tar -xzf "${archive}"
)

if [ ! -f "${TMPDIR_ROOT}/ft" ]; then
    die "archive did not contain an 'ft' binary at its root."
fi
chmod +x "${TMPDIR_ROOT}/ft"

mkdir -p "${INSTALL_DIR}" || die "could not create install directory: ${INSTALL_DIR}"

mv "${TMPDIR_ROOT}/ft" "${INSTALL_DIR}/ft"

FT_BIN="${INSTALL_DIR}/ft"
installed_version=$("${FT_BIN}" --version 2>/dev/null) || {
    die "installed binary at ${FT_BIN} failed to report its version."
}

info "Installed: ${FT_BIN}"
info "Version:   ${installed_version}"

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
