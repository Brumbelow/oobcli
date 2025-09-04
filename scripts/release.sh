#!/usr/bin/env bash
set -euo pipefail

# Minimal release builder for oobcli
# - Cross-compiles common targets with CGO disabled
# - Strips symbols (-s -w) and places artifacts in dist/
# - Produces dist/checksums.txt when shasum/sha256sum is available

PROJECT_NAME="oobcli"
VERSION="${VERSION:-}"

# Derive VERSION if not provided (best effort)
if [[ -z "$VERSION" ]]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || true)"
  fi
  if [[ -z "$VERSION" ]]; then
    VERSION="v0.0.0-$(date +%Y%m%d%H%M%S)"
  fi
fi

DIST_DIR="dist"
mkdir -p "$DIST_DIR"

# Default target matrix; override by exporting TARGETS="os/arch os/arch ..."
TARGETS_DEFAULT=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
)

read -r -a TARGETS <<< "${TARGETS:-${TARGETS_DEFAULT[*]}}"

checksum_file="$DIST_DIR/checksums.txt"
rm -f "$checksum_file"
touch "$checksum_file"

sum_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
  sum_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  sum_cmd="shasum -a 256"
fi

echo "Building $PROJECT_NAME $VERSION -> $DIST_DIR" >&2

for tgt in "${TARGETS[@]}"; do
  os="${tgt%%/*}"
  arch="${tgt##*/}"
  ext=""
  [[ "$os" == "windows" ]] && ext=".exe"
  out="$DIST_DIR/${PROJECT_NAME}_${VERSION}_${os}_${arch}${ext}"

  echo "  -> $tgt" >&2
  env \
    CGO_ENABLED=0 \
    GOOS="$os" \
    GOARCH="$arch" \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o "$out" ./cmd/oobcli

  if [[ -n "$sum_cmd" ]]; then
    $sum_cmd "$out" >> "$checksum_file"
  fi
done

echo "Done. Artifacts in $DIST_DIR" >&2
[[ -s "$checksum_file" ]] && echo "Checksums: $checksum_file" >&2 || rm -f "$checksum_file"

