#!/usr/bin/env bash
# Cross-compile self-contained 2ms-web binaries for the common platforms.
# Output goes to ./bin. Requires Go to be installed.
set -euo pipefail

cd "$(dirname "$0")"

APP="2ms-web"
BIN_DIR="bin"
mkdir -p "$BIN_DIR"

platforms=(
  "darwin/amd64"   # Intel Mac
  "darwin/arm64"   # Apple Silicon
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

echo "Building $APP for ${#platforms[@]} platforms..."
for p in "${platforms[@]}"; do
  os="${p%/*}"
  arch="${p#*/}"
  out="$BIN_DIR/${APP}-${os}-${arch}"
  [ "$os" = "windows" ] && out="${out}.exe"
  echo "  -> $out"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out" .
done

echo "Done. Binaries are in ./$BIN_DIR/"
