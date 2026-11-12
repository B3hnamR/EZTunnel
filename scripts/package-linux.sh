#!/usr/bin/env bash
# Produce a self-contained local installation bundle from an existing build.
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'Package on Linux using a Linux release binary.' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary=${1:-$root/target/release/eztunnel}
output=${2:-$root/dist}
[[ -x $binary ]] || { echo "Missing executable: $binary" >&2; exit 1; }
magic=$(od -An -tx1 -N6 -- "$binary" | tr -d ' \n')
machine=$(od -An -tu1 -j18 -N2 -- "$binary" | xargs)
[[ $magic == 7f454c460201 ]] || { echo 'Expected a 64-bit little-endian ELF executable.' >&2; exit 1; }
case $machine in
  '62 0') architecture=x86_64 ;;
  '183 0') architecture=aarch64 ;;
  *) echo 'Only Linux x86-64 and ARM64 executables can be packaged.' >&2; exit 1 ;;
esac
# Packaging cross-built files must not execute the foreign-architecture binary.
echo "Packaging ELF architecture: $architecture"
mkdir -p -- "$output"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
bundle=$stage/eztunnel-linux
mkdir -p -- "$bundle/bin" "$bundle/scripts"
install -m 755 "$binary" "$bundle/bin/eztunnel"
install -m 755 "$root/scripts/install.sh" "$bundle/scripts/"
cp -- "$root/LICENSE" "$root/README.md" "$root/CHANGELOG.md" "$bundle/"
cp -R -- "$root/docs" "$root/examples" "$bundle/"
# Third-party notices for everything linked into the static binary are kept outside the
# source tree; EZTUNNEL_NOTICES names the folder holding licenses/ and third-party.md.
notices=${EZTUNNEL_NOTICES:-}
if [[ -n $notices && -d $notices/licenses && -f $notices/third-party.md ]]; then
  cp -R -- "$notices/licenses" "$bundle/"
  cp -- "$notices/third-party.md" "$bundle/docs/"
else
  echo 'Warning: EZTUNNEL_NOTICES is not set; this archive has no third-party notices.' >&2
  echo 'It is fine for your own servers, but do not redistribute it without the notices.' >&2
fi
for vendored in tokio_kcp kcp; do
  mkdir -p -- "$bundle/vendor/$vendored"
  cp -- "$root/vendor/$vendored/LICENSE" "$root/vendor/$vendored/LOCAL-PATCH.md" "$bundle/vendor/$vendored/"
done
(cd -- "$bundle" && sha256sum bin/eztunnel > SHA256SUMS)
archive=$output/eztunnel-linux-$architecture.tar.gz
tar -C "$stage" -czf "$archive" eztunnel-linux
(cd -- "$output" && sha256sum "$(basename -- "$archive")" > "$(basename -- "$archive").sha256")
bash "$root/scripts/package-selfextracting.sh" "$archive" "${archive%.tar.gz}.run" "$architecture"
printf 'Local bundle: %s\n' "$archive"
echo 'Copy the .run file to the matching Linux machine and run it with sudo bash to install and open the manager.'
