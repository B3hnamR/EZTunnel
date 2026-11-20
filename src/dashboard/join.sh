#!/usr/bin/env bash
# Joins this server to an EZTunnel dashboard with a one-time code. Served by the dashboard itself.
#
# If the installed EZTunnel can already run the agent, it only joins. Otherwise the latest release
# is first downloaded and tried in a private folder; the installed program is replaced only if that
# release can join a dashboard. The installer keeps a backup of the old program and never restarts
# a tunnel: running tunnels keep the program they started with. Tunnel settings are not touched.
set -euo pipefail
umask 077

installer=https://raw.githubusercontent.com/B3hnamR/EZTunnel/main/scripts/install-latest.sh
installed=/usr/local/bin/eztunnel

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
can_join() { [[ -x $1 ]] && "$1" agent --help >/dev/null 2>&1; }

code=${1:-}
[[ $code == ezj1-* ]] || die 'Run it with the join code the dashboard shows: bash join.sh CODE'
(( EUID == 0 )) || die 'Run it as root (sudo -i first, or sudo bash).'
command -v curl >/dev/null 2>&1 || die 'curl is needed. Install it with your package manager and run the command again.'

if can_join "$installed"; then
  exec "$installed" agent join "$code"
fi

work=$(mktemp -d /root/.eztunnel-join.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
printf 'Checking the latest EZTunnel release (in %s; nothing is installed yet) ...\n' "$work"
curl -fsSL "$installer" -o "$work/install-latest.sh"
EZTUNNEL_NO_MENU=1 bash "$work/install-latest.sh" --prefix "$work/try" >/dev/null 2>&1
if ! can_join "$work/try/bin/eztunnel"; then
  die 'The latest EZTunnel release cannot join a dashboard yet. Nothing on this server was changed.'
fi

if [[ -x $installed ]]; then
  printf '\nThis server has %s, which cannot join a dashboard.\n' "$("$installed" --version 2>/dev/null || echo 'an older EZTunnel')"
  printf 'It will be updated to %s.\n' "$("$work/try/bin/eztunnel" --version)"
  printf 'Running tunnels are not restarted and keep the version they started with; the old program is kept as a backup.\n'
  if [[ -t 0 ]]; then
    read -r -p 'Update and join now? [Y/n] ' answer
    [[ -z $answer || $answer == [Yy]* ]] || die 'Stopped. Nothing on this server was changed.'
  fi
fi
EZTUNNEL_NO_MENU=1 bash "$work/install-latest.sh"
can_join "$installed" || die 'The installed program cannot join a dashboard.'
"$installed" agent join "$code"
