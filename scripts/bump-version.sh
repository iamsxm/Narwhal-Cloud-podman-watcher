#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/VERSION"
NEW_VERSION="${1:-}"

if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Usage: bash scripts/bump-version.sh <major.minor.patch>"
  exit 1
fi

printf '%s\n' "$NEW_VERSION" >"$VERSION_FILE"
echo "Narwhal Monitor version: $NEW_VERSION"
