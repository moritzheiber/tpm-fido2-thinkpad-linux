#!/bin/bash
# Builds the tpm-fido Debian package inside the container.
#
# Expected bind mounts:
#   /src  read-only source tree
#   /out  output directory for the resulting artifacts
#
# Optional environment:
#   HOST_UID, HOST_GID  ownership to apply to the artifacts in /out
set -euo pipefail

SRC=/src
WORK=/work
OUT=/out
BUILDER_HOME=/home/builder

echo "==> Preparing a writable build tree"
rm -rf "$WORK"
mkdir -p "$WORK/tpm-fido"
# Copy the source without the host build directory or the git metadata.
tar -C "$SRC" --exclude=./build --exclude=./.git -cf - . | tar -C "$WORK/tpm-fido" -xf -
chown -R builder:builder "$WORK"

echo "==> Vendoring Go dependencies (network access required)"
runuser -u builder -- env \
  HOME="$BUILDER_HOME" \
  GOCACHE="$WORK/.gocache" \
  GOMODCACHE="$WORK/.gomod" \
  GOFLAGS=-mod=mod \
  sh -c "cd '$WORK/tpm-fido' && go mod vendor"

echo "==> Building the Debian package"
runuser -u builder -- env \
  HOME="$BUILDER_HOME" \
  sh -c "cd '$WORK/tpm-fido' && dpkg-buildpackage -us -uc -b"

echo "==> Collecting artifacts"
mkdir -p "$OUT"
cp -v "$WORK"/*.deb "$OUT"/
cp -v "$WORK"/*.buildinfo "$WORK"/*.changes "$OUT"/ 2>/dev/null || true

echo "==> Running lintian"
runuser -u builder -- sh -c "cd '$WORK' && lintian --no-tag-display-limit --info *.changes" || true

if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
  chown -R "$HOST_UID:$HOST_GID" "$OUT"
fi

echo "==> Done. Artifacts in $OUT:"
ls -l "$OUT"
