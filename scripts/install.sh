#!/usr/bin/env bash
# Install a local, already-built binary. This script never downloads code.
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'This installer supports Linux only.' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root_dir=$(cd -- "$script_dir/.." && pwd)
if (( EUID == 0 )); then prefix=/usr/local; else prefix=${HOME:?}/.local; fi
binary=''
while (( $# )); do
  case $1 in
    --prefix) prefix=${2:?Missing --prefix value}; shift 2 ;;
    --binary) binary=${2:?Missing --binary value}; shift 2 ;;
    -h|--help)
      echo 'Usage: bash scripts/install.sh [--binary ./eztunnel] [--prefix /usr/local]'
      echo 'Installs a local release binary. Does not download, overwrite tunnels or start services.'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ $prefix == /* && $prefix != *[[:cntrl:]]* && $prefix != *'"'* && $prefix != *'$'* && $prefix != *'\'* ]] || {
  echo 'The prefix must be an absolute path without control characters, quote, $ or backslash.' >&2
  exit 2
}
if [[ -z $binary ]]; then
  for candidate in "$root_dir/bin/eztunnel" "$root_dir/target/release/eztunnel"; do
    if [[ -x $candidate ]]; then binary=$candidate; break; fi
  done
fi
[[ -n $binary && -f $binary && -x $binary ]] || {
  echo 'No local Linux release binary found. Supply --binary, or build this checkout with cargo build --release --locked first.' >&2
  exit 1
}
# Reject the wrong architecture before attempting execution or touching PATH.
# od reads ELF bytes without trusting the candidate to identify itself.
magic=$(od -An -tx1 -N6 -- "$binary" | tr -d ' \n')
machine=$(od -An -tu1 -j18 -N2 -- "$binary" | xargs)
[[ $magic == 7f454c460201 ]] || { echo 'Expected a 64-bit little-endian Linux ELF executable.' >&2; exit 1; }
case $(uname -m) in
    x86_64|amd64) expected='62 0'; label=x86-64 ;;
    aarch64|arm64) expected='183 0'; label=ARM64 ;;
    *) echo 'Unsupported CPU architecture. Use Linux x86-64 or ARM64.' >&2; exit 1 ;;
esac
[[ $machine == "$expected" ]] || { echo "Wrong executable architecture for this $label host. Download the matching release; nothing was installed." >&2; exit 1; }
"$binary" --version >/dev/null
install -d -m 755 "$prefix/bin"
# Replace the file instead of writing into it, so a running tunnel keeps its old copy.
install -m 755 "$binary" "$prefix/bin/eztunnel.new"
mv -f -- "$prefix/bin/eztunnel.new" "$prefix/bin/eztunnel"
printf '#!/bin/sh\nexec "%s" menu "$@"\n' "$prefix/bin/eztunnel" > "$prefix/bin/eztunnel-setup"
chmod 755 "$prefix/bin/eztunnel-setup"
# Version 0.4 kept a separate setup script; the manager is now part of the program.
rm -f -- "$prefix/share/eztunnel/setup.sh" "$prefix/share/eztunnel/settings_tool.py"
rmdir -- "$prefix/share/eztunnel" 2>/dev/null || true
printf 'Installed %s\n' "$("$prefix/bin/eztunnel" --version)"
printf 'Open the tunnel manager with:  %s\n' "$(if (( EUID == 0 )); then echo eztunnel; else echo 'sudo eztunnel'; fi)"
