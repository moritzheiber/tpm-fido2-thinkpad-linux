#!/usr/bin/env bash
# Repeatable Docker-based build of the tpm-fido Debian package for Ubuntu 26.04.
#
# Usage:
#   ./packaging/build-deb.sh
#
# Result:
#   build/deb/tpm-fido_*.deb and the accompanying .changes/.buildinfo files.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="tpm-fido-deb-builder:ubuntu-26.04"
OUT_DIR="$REPO_ROOT/build/deb"

echo "==> Building the packaging image"
docker build \
  -t "$IMAGE" \
  -f "$REPO_ROOT/packaging/docker/Dockerfile" \
  "$REPO_ROOT/packaging/docker"

mkdir -p "$OUT_DIR"

echo "==> Building the package in a container"
docker run --rm \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  -v "$REPO_ROOT":/src:ro \
  -v "$OUT_DIR":/out \
  "$IMAGE"

echo ""
echo "==> Package(s) written to $OUT_DIR:"
ls -1 "$OUT_DIR"/*.deb
