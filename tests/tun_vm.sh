#!/usr/bin/env bash
# Run only in an isolated Linux test host as root/CAP_NET_ADMIN.
set -euo pipefail
export RUST_LOG=${RUST_LOG:-debug}
BINARY="$(realpath -- "${1:?Usage: bash tests/tun_vm.sh /path/to/eztunnel [carrier] [direct]}")"
TRANSPORT=${2:-tcp}
# "direct": one tunnel key, the server dials the client, TLS uses the key-derived certificate.
DIRECTION=${3:-}
case "$DIRECTION" in ""|direct) ;; *) echo 'The third argument may only be direct' >&2; exit 2 ;; esac
case "$TRANSPORT" in tcp|http|https|ws|wss|xhttp|xhttps|tcp6|kcp|fec-udp) ;; *) echo 'Unknown carrier' >&2; exit 2 ;; esac
ROOT="$(mktemp -d)"
SERVER_NS="drs$$"
CLIENT_NS="drc$$"
SERVER_PID=''
CLIENT_PID=''
ECHO_PID=''
cleanup() {
  [[ -z "$ECHO_PID" ]] || kill "$ECHO_PID" 2>/dev/null || true
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  [[ -z "$CLIENT_PID" ]] || kill "$CLIENT_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  rm -rf -- "$ROOT"
}
trap cleanup EXIT
[[ $(id -u) -eq 0 ]] || { printf 'This test requires root in an isolated Linux environment.\n' >&2; exit 1; }
"$BINARY" keygen --out "$ROOT/server-keys" >/dev/null
"$BINARY" key > "$ROOT/tunnel.key"
"$BINARY" keygen --out "$ROOT/client-keys" >/dev/null
case "$TRANSPORT" in https|wss|xhttps) "$BINARY" certgen --out "$ROOT/tls" --name localhost >/dev/null ;; esac
ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip link add "drs$$" type veth peer name "drc$$"
ip link set "drs$$" netns "$SERVER_NS"
ip link set "drc$$" netns "$CLIENT_NS"
ip -n "$SERVER_NS" addr add 10.201.0.1/30 dev "drs$$"
ip -n "$CLIENT_NS" addr add 10.201.0.2/30 dev "drc$$"
ip -n "$SERVER_NS" -6 addr add fd42:201::1/64 dev "drs$$" nodad
ip -n "$CLIENT_NS" -6 addr add fd42:201::2/64 dev "drc$$" nodad
ip -n "$SERVER_NS" link set "drs$$" up
ip -n "$CLIENT_NS" link set "drc$$" up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up

for family in 4 6; do
  python3 - "$ROOT" "$family" "$TRANSPORT" "$DIRECTION" <<'PY'
import json,os,pathlib,sys
root=pathlib.Path(sys.argv[1]); family=sys.argv[2]; transport=sys.argv[3]; direct=sys.argv[4]=='direct'
underlay='[fd42:201::1]:24443' if transport=='tcp6' else '10.201.0.1:24443'
server_ip,client_ip=('10.202.0.1','10.202.0.2') if family=='4' else ('fd42:202::1','fd42:202::2')
common={'heartbeat_sec':1,'dead_timeout_sec':4,'max_connections':1}
server=dict(common,mode='server',private_key_file=str(root/'server-keys/private.key'),
    peer_public_keys=[(root/'client-keys/public.key').read_text().strip()],
    listeners=[{'addr':underlay,'transport':transport}],
    tun={'name':'eztest0','address':server_ip,'peer_address':client_ip,'mtu':1400})
client=dict(common,mode='client',private_key_file=str(root/'client-keys/private.key'),
    paths=[{'addr':underlay,'transport':transport,'server_public_key':(root/'server-keys/public.key').read_text().strip(),'retry_interval':1}],
    tun={'name':'eztest0','address':client_ip,'peer_address':server_ip,'mtu':1400})
if transport in ('https','wss','xhttps'):
 server['listeners'][0].update(cert_file=str(root/'tls/cert.pem'),key_file=str(root/'tls/key.pem'))
 client['paths'][0].update(ca_file=str(root/'tls/cert.pem'),server_name='localhost')
if direct:
 # The client listens on its own underlay address and the server connects to it.
 client_underlay='[fd42:201::2]:24443' if transport=='tcp6' else '10.201.0.2:24443'
 key=(root/'tunnel.key').read_text().strip()
 for config,entry in ((server,server['listeners'][0]),(client,client['paths'][0])):
  config.pop('private_key_file'); config.pop('peer_public_keys',None); entry.pop('server_public_key',None)
  for name in ('cert_file','key_file','ca_file','server_name'): entry.pop(name,None)
  config.update(tunnel_key=key,server_dials=True)
  entry['addr']=client_underlay
  if transport in ('https','wss','xhttps'): entry['tls_auto']=True
for name,config in (('server.json',server),('client.json',client)):
 path=root/name; path.write_text(json.dumps(config)); os.chmod(path,0o600)
PY
  ip netns exec "$SERVER_NS" "$BINARY" -c "$ROOT/server.json" >"$ROOT/server.log" 2>&1 & SERVER_PID=$!
  ip netns exec "$CLIENT_NS" "$BINARY" -c "$ROOT/client.json" >"$ROOT/client.log" 2>&1 & CLIENT_PID=$!
  if [[ "$family" == 4 ]]; then PEER=10.202.0.1; else PEER=fd42:202::1; fi
  ready=0
  for _ in {1..15}; do
    if ip netns exec "$CLIENT_NS" ping "-$family" -c 1 -W 1 "$PEER" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  if [[ "$ready" != 1 ]]; then
    cat "$ROOT/server.log" "$ROOT/client.log" >&2
    ip -n "$SERVER_NS" address >&2; ip -n "$SERVER_NS" -6 route >&2
    ip -n "$CLIENT_NS" address >&2; ip -n "$CLIENT_NS" -6 route >&2
    exit 1
  fi
  ip netns exec "$SERVER_NS" python3 - "$family" <<'PY' &
import socket,sys
s=socket.socket(socket.AF_INET if sys.argv[1]=='4' else socket.AF_INET6,socket.SOCK_DGRAM)
s.bind(('0.0.0.0' if sys.argv[1]=='4' else '::',25555));s.settimeout(15)
for _ in range(4):
 data,peer=s.recvfrom(65535);s.sendto(data,peer)
PY
  ECHO_PID=$!
  sleep 0.5
  ip netns exec "$CLIENT_NS" python3 - "$family" "$PEER" <<'PY'
import socket,sys
s=socket.socket(socket.AF_INET if sys.argv[1]=='4' else socket.AF_INET6,socket.SOCK_DGRAM)
s.settimeout(5)
for n in (0,1,512,1300):
 data=bytes(i%251 for i in range(n));s.sendto(data,(sys.argv[2],25555));got,_=s.recvfrom(65535);assert got==data
print('TUN IPv'+sys.argv[1]+' ICMP and UDP packet roundtrips passed')
PY
  wait "$ECHO_PID"; ECHO_PID=''
  kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=''
  # Restart only the server; the existing client's retry loop must restore packets.
  ip netns exec "$SERVER_NS" "$BINARY" -c "$ROOT/server.json" >>"$ROOT/server.log" 2>&1 & SERVER_PID=$!
  ready=0
  for _ in {1..15}; do
    if ip netns exec "$CLIENT_NS" ping "-$family" -c 1 -W 1 "$PEER" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { cat "$ROOT/server.log" "$ROOT/client.log" >&2; exit 1; }
  kill "$SERVER_PID" "$CLIENT_PID"; wait "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
  SERVER_PID=''; CLIENT_PID=''
  if ip -n "$SERVER_NS" link show eztest0 >/dev/null 2>&1 || ip -n "$CLIENT_NS" link show eztest0 >/dev/null 2>&1; then
    printf 'TUN interface leaked after process exit\n' >&2; exit 1
  fi
done
printf 'TUN %s%s namespace, IPv4/IPv6, packet, reconnect and teardown tests passed\n' "$TRANSPORT" "${DIRECTION:+ (direct, tunnel key)}"
