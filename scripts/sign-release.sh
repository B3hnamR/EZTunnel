#!/usr/bin/env bash
# Read-only official-release verifier. Signing authority is deliberately external.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
[[ ${1:-} == --verify && $# -eq 2 ]] || {
  echo 'Usage: scripts/sign-release.sh --verify <candidate>' >&2
  echo 'Signing and key generation are not part of application builds. Use an independently controlled release-signing workflow.' >&2
  exit 2
}
exec cargo run --locked --release --manifest-path "$here/Cargo.toml" --no-default-features --bin verify-release -- "$2"
