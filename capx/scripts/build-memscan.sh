#!/usr/bin/env bash
# Build the Rust memory-scan engine (native/memscan-rs) and stage its static
# library under native/memscan-rs/lib/ so the Go cgo backend can link it with
# `-tags memscan_ffi`.
#
# Usage:
#   packet-capture/capx/scripts/build-memscan.sh
#
# Requirements: rustup/cargo + a C toolchain (MinGW-w64 on Windows, gcc on Linux).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$here/native/memscan-rs"
mkdir -p "$crate/lib"

uname_s="$(uname -s)"
case "$uname_s" in
  MINGW*|MSYS*|CYGWIN*)
    target="x86_64-pc-windows-gnu"
    rustup target add "$target" >/dev/null 2>&1 || true
    (cd "$crate" && cargo build --release --target "$target")
    cp "$crate/target/$target/release/libmemscan.a" "$crate/lib/"
    ;;
  *)
    (cd "$crate" && cargo build --release)
    cp "$crate/target/release/libmemscan.a" "$crate/lib/"
    ;;
esac

echo "staged: $crate/lib/libmemscan.a"
echo "now build Go with: cd $here && CGO_ENABLED=1 go build -tags memscan_ffi ./..."
