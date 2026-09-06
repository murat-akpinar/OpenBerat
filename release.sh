#!/bin/sh
# Cuts a release: one tarball an air-gapped host installs from (ADR-0023).
#
#   ./release.sh [git-ref]      default HEAD; a release cuts a tag
#
# The bundle is the tagged source plus every image the release compose
# references, saved. There is no second, online-only artifact: the offline one
# is a superset, and two artifacts would mean testing two.
#
# The version comes from backend/Cargo.toml and from nowhere else. Run this
# where `.env` is — compose reads it to expand the file, and it warns rather
# than fails without it, which is how a bundle ends up named after nothing.
set -eu
cd "$(dirname "$0")"
ref=${1:-HEAD}

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' backend/Cargo.toml | head -1)
[ -n "$version" ] || { echo "no version in backend/Cargo.toml" >&2; exit 1; }
out=dist/openberat-$version

echo "== openberat $version from $ref =="
rm -rf "$out"
mkdir -p "$out"

# From git, not from the working tree: a release must not carry a file nobody
# committed, and must carry every file somebody did.
git archive --format=tar "$ref" | tar -x -C "$out"

# Only the services in no profile — the lab directory and the sample
# applications are not part of a release (ADR-0010).
docker compose build
docker compose pull --ignore-buildable
docker compose config --images | sort -u > "$out/images.txt"
echo "images:"; sed 's/^/  /' "$out/images.txt"

# Layers are stored uncompressed, so this is the slow half and the large one.
docker save -o "$out/images.tar" $(cat "$out/images.txt")
echo "$version" > "$out/VERSION"
tar -C dist -czf "dist/openberat-$version.tar.gz" "openberat-$version"
rm -rf "$out"

ls -lh "dist/openberat-$version.tar.gz"
echo "install: INSTALL.md section 11"
