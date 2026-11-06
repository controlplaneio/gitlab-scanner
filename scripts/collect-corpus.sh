#!/usr/bin/env bash
# Collect GitLab CE webpack manifests for a list of release tags, one at a time,
# WITHOUT booting any instance: pull -> docker cp the manifest -> delete the image.
# Resumable: a version whose manifest already exists is skipped. Designed to run
# in the background with immediate image deletion so disk stays bounded.
#
# Usage: collect-corpus.sh <version-list.txt> <output-manifests-dir> [log-file]
#   version-list.txt: one tag per line, e.g. "16.0.0-ce.0"
set -u

LIST="${1:?version list required}"
OUT="${2:?output dir required}"
LOG="${3:-/dev/stdout}"
IMG_REPO="${4:-gitlab/gitlab-ce}"
MP=/opt/gitlab/embedded/service/gitlab-rails/public/assets/webpack/manifest.json
mkdir -p "$OUT"

total=$(grep -c . "$LIST")
i=0
while IFS= read -r tag; do
  [ -z "$tag" ] && continue
  i=$((i+1))
  ver="${tag%-ce.*}"; ver="${ver%-ee.*}"
  dest="$OUT/${ver}.json"
  if [ -s "$dest" ]; then
    echo "[$i/$total] $ver: already have, skip" >>"$LOG"; continue
  fi
  img="${IMG_REPO}:${tag}"
  if ! docker pull --platform linux/amd64 "$img" >/dev/null 2>&1; then
    echo "[$i/$total] $ver: PULL FAILED" >>"$LOG"; continue
  fi
  cid=$(docker create "$img" 2>/dev/null)
  if [ -n "$cid" ]; then
    docker cp "$cid:$MP" "$dest" >/dev/null 2>&1 || echo "[$i/$total] $ver: CP FAILED (no webpack manifest?)" >>"$LOG"
    docker rm "$cid" >/dev/null 2>&1
  fi
  docker rmi "$img" >/dev/null 2>&1
  if [ -s "$dest" ]; then
    echo "[$i/$total] $ver: OK ($(wc -c <"$dest") bytes)" >>"$LOG"
  fi
done < "$LIST"
echo "COLLECTION COMPLETE: $(ls "$OUT"/*.json 2>/dev/null | wc -l) manifests in $OUT" >>"$LOG"
