#!/usr/bin/env bash
# Wrap an existing local Linux tar.gz bundle; no downloads and no build steps.
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'Create self-extracting bundles on Linux.' >&2; exit 1; }
if (( $# < 1 || $# > 3 )); then
  echo 'Usage: bash scripts/package-selfextracting.sh BUNDLE.tar.gz [OUTPUT.run] [ARCHITECTURE]' >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
archive=$(realpath -- "$1")
[[ -f $archive ]] || { echo 'Local tar.gz bundle is missing.' >&2; exit 1; }
if (( $# >= 2 )); then output=$2; else output=${archive%.tar.gz}.run; fi
if (( $# >= 3 )); then architecture=$3; else architecture=$(uname -m); fi
[[ $architecture =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid architecture label.' >&2; exit 2; }
mkdir -p -- "$(dirname -- "$output")"
output=$(realpath -m -- "$output")
[[ $archive != "$output" ]] || { echo 'Output must differ from the input archive.' >&2; exit 2; }
digest=$(sha256sum < "$archive"); digest=${digest%% *}
temporary=$(mktemp "$output.tmp.XXXXXXXX")
trap 'rm -f -- "$temporary"' EXIT
sed -e "s/@PAYLOAD_SHA256@/$digest/g" -e "s/@ARCHITECTURE@/$architecture/g" "$script_dir/offline-runner.sh.in" > "$temporary"
cat -- "$archive" >> "$temporary"
chmod 755 "$temporary"
mv -f -- "$temporary" "$output"
(cd -- "$(dirname -- "$output")" && sha256sum "$(basename -- "$output")" > "$(basename -- "$output").sha256")
printf 'Self-extracting offline bundle: %s\n' "$output"
printf 'Install and open the tunnel manager: sudo bash %q\n' "$output"
