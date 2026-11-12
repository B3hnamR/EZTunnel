#!/usr/bin/env bash
# Download one official GitHub Release asset. Never starts/restarts a tunnel.
set -euo pipefail
umask 077

repository=B3hnamR/EZTunnel
prefix=/usr/local
version=latest

usage() {
  cat <<'HELP'
EZTunnel GitHub Release installer
Usage: sudo bash install-latest.sh [--version v0.9.12] [--prefix /usr/local]

Downloads the matching Linux archive and SHA256SUMS from B3hnamR/EZTunnel.
Verifies the archive checksum and ELF CPU before executing the binary.
Preserves a replaced executable, installs atomically, and never starts services.
Latest means GitHub's latest published non-prerelease, not the newest source tag.
HELP
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --version) [[ $# -ge 2 ]] || die '--version needs a release tag'; version=$2; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || die '--prefix needs an absolute directory'; prefix=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ $(uname -s) == Linux ]] || die 'Linux is required.'
case $(uname -m) in
  x86_64|amd64) architecture=x86_64; machine_expected='62 0' ;;
  aarch64|arm64) architecture=aarch64; machine_expected='183 0' ;;
  *) die 'Supported CPUs: x86-64 and ARM64 (aarch64).' ;;
esac
[[ $version == latest || $version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || die 'Use latest or an explicit version tag, for example v0.9.12.'
[[ $prefix == /* && $prefix != / && $prefix != *[[:cntrl:]]* && $prefix != *'"'* && $prefix != *'$'* && $prefix != *'\'* ]] || die 'Use an absolute installation prefix without control characters, quotes, $ or backslashes.'
if (( EUID != 0 )) && [[ $prefix == /usr/local ]]; then
  die 'Run with sudo to install in /usr/local, or set --prefix "$HOME/.local".'
fi
for tool in curl tar sha256sum awk od tr xargs mktemp install mv cp chmod flock wc; do
  command -v "$tool" >/dev/null 2>&1 || die "Missing dependency: $tool. Install it with your Linux package manager and retry."
done

work=$(mktemp -d "${TMPDIR:-/tmp}/eztunnel-install.XXXXXXXX")
staged=''
cleanup() {
  [[ -z $staged ]] || rm -f -- "$staged"
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

asset=eztunnel-linux-$architecture.tar.gz
if [[ $version == latest ]]; then
  base=https://github.com/$repository/releases/latest/download
else
  base=https://github.com/$repository/releases/download/$version
fi
download() {
  # No token, arbitrary mirror, or insecure-TLS fallback. Private/unpublished
  # releases fail explicitly instead of fetching an older architecture asset.
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 300 --max-filesize 134217728 --retry 2 --output "$2" "$1"
}
printf 'EZTunnel: downloading the %s Linux release...\n' "$architecture"
download "$base/SHA256SUMS" "$work/SHA256SUMS" || die 'Cannot download SHA256SUMS. The repository/release must be public and contain the documented assets. Nothing was installed.'
[[ $(wc -c < "$work/SHA256SUMS") -le 1048576 ]] || die 'Release checksum file is unexpectedly large.'
expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name {print $1}' "$work/SHA256SUMS")
[[ $expected =~ ^[[:xdigit:]]{64}$ ]] || die "SHA256SUMS must contain exactly one checksum for $asset. No older or wrong-CPU fallback is used."
download "$base/$asset" "$work/$asset" || die "Cannot download $asset. Nothing was installed."
actual=$(sha256sum -- "$work/$asset"); actual=${actual%% *}
[[ ${actual,,} == ${expected,,} ]] || die 'Archive checksum mismatch. Nothing was installed.'

member=eztunnel-linux/bin/eztunnel
matches=$(tar -tzf "$work/$asset" -- "$member") || die 'Archive does not contain the documented executable.'
[[ $matches == "$member" ]] || die 'Archive must contain exactly one executable at the documented path.'
# Extract only the named file's bytes, never trust archive paths, links, modes or
# root-owned extraction scripts. No archive member is executed by this installer.
tar -xOzf "$work/$asset" -- "$member" > "$work/eztunnel" || die 'Cannot read the executable from the archive.'
magic=$(od -An -tx1 -N6 -- "$work/eztunnel" | tr -d ' \n')
machine=$(od -An -tu1 -j18 -N2 -- "$work/eztunnel" | xargs)
[[ $magic == 7f454c460201 && $machine == "$machine_expected" ]] || die 'The release executable has the wrong ELF format or CPU. Nothing was installed.'

chmod 700 "$work/eztunnel"
candidate_version=$("$work/eztunnel" --version) || die 'The verified executable cannot run on this host. Nothing was installed.'
[[ $candidate_version =~ ^eztunnel\ [0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || die 'The release did not return a recognized EZTunnel version.'
if [[ $version != latest ]]; then
  [[ ${candidate_version#eztunnel } == "${version#v}" ]] || die 'Release tag and executable version do not match.'
fi

destination=$prefix/bin
install -d -m 755 -- "$destination"
[[ ! -L $destination && ! -L $destination/eztunnel ]] || die 'Refusing a symlink installation destination.'
lock=$destination/.eztunnel-install.lock
[[ ! -L $lock ]] || die 'Refusing a symlink installer lock.'
exec 9>> "$lock"
flock -n 9 || die 'Another EZTunnel installation is in progress.'

backup=''
if [[ -e $destination/eztunnel ]]; then
  [[ -f $destination/eztunnel ]] || die 'Existing command is not a regular file.'
  previous=$(sha256sum -- "$destination/eztunnel"); previous=${previous%% *}
  backup=$destination/eztunnel.backup-$previous
  if [[ -e $backup || -L $backup ]]; then
    [[ -f $backup && ! -L $backup ]] || die 'Previous-binary backup path is not a regular file.'
    saved=$(sha256sum -- "$backup"); saved=${saved%% *}
    [[ $saved == "$previous" ]] || die 'Previous-binary backup checksum does not match.'
  else
    cp -p -- "$destination/eztunnel" "$backup"
  fi
fi
staged=$(mktemp "$destination/.eztunnel-new.XXXXXXXX")
install -m 755 -- "$work/eztunnel" "$staged"
copied=$(sha256sum -- "$staged"); copied=${copied%% *}
original=$(sha256sum -- "$work/eztunnel"); original=${original%% *}
[[ $copied == "$original" ]] || die 'Installed staging bytes differ from the verified download.'
mv -f -- "$staged" "$destination/eztunnel"
staged=''

printf '\nInstalled %s at %s/eztunnel\n' "$candidate_version" "$destination"
[[ -z $backup ]] || printf 'Previous executable preserved at: %s\n' "$backup"
printf 'Open the manager: sudo %s/eztunnel menu\n' "$destination"
printf 'Configurations, keys, firewall rules and services were not changed.\n'
printf 'Running tunnels retain their old binary until you explicitly restart them.\n'
printf 'Checksums detect corruption; HTTPS and control of the GitHub release remain the trust boundary.\n'
