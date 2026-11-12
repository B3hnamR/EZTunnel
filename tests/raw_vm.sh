#!/usr/bin/env bash
# Root-only test in an isolated Linux VM. All links and policy live in namespaces.
set -euo pipefail
export RUST_LOG=${RUST_LOG:-info}
BINARY="$(realpath -- "${1:?Usage: bash tests/raw_vm.sh /path/to/eztunnel [tun|fec-raw|all]}")"
CARRIER=${2:-all}
case "$CARRIER" in tun|fec-raw|all) ;; *) printf 'Unknown raw carrier\n' >&2; exit 2 ;; esac
[[ $(id -u) == 0 ]] || { printf 'Run this matrix as root in an isolated Linux VM.\n' >&2; exit 1; }
case "${EZTUNNEL_TEST_FAMILY:-}" in ''|4|6) ;; *) printf 'EZTUNNEL_TEST_FAMILY must be 4 or 6.\n' >&2; exit 2 ;; esac
cases=()
if [[ "$CARRIER" == tun || "$CARRIER" == all ]]; then
    for profile in tcp udp icmp gre ipip raw dns; do cases+=("tun:$profile:plain"); done
    cases+=(tun:tcp:proto58 tun:tcp:spoof-src tun:tcp:spoof-dst tun:tcp:spoof-both tun:tcp:arp tun:icmp:mirror tun:tcp:wire2)
fi
if [[ "$CARRIER" == fec-raw || "$CARRIER" == all ]]; then
    for profile in tcp udp icmp gre ipip raw dns; do cases+=("fec-raw:$profile:plain"); done
    cases+=(fec-raw:tcp:proto58 fec-raw:tcp:spoof-src fec-raw:tcp:spoof-dst fec-raw:tcp:spoof-both fec-raw-gaming:tcp:plain fec-raw:icmp:mirror fec-raw:tcp:wire2)
fi
if [[ -n ${EZTUNNEL_TEST_CASE:-} ]]; then
    matched=0
    for scenario in "${cases[@]}"; do [[ $scenario != "$EZTUNNEL_TEST_CASE" ]] || matched=1; done
    (( matched > 0 )) || { printf 'EZTUNNEL_TEST_CASE does not select a case in the requested carrier matrix.\n' >&2; exit 2; }
fi
ROOT="$(mktemp -d)"
SERVER_NS="drrs$$"; CLIENT_NS="drrc$$"
SERVER_IF="drs$$"; CLIENT_IF="drc$$"
SERVER_PID=''; CLIENT_PID=''; ECHO_PID=''; OBSERVER_PID=''
cleanup() {
    for pid in "$OBSERVER_PID" "$ECHO_PID" "$CLIENT_PID" "$SERVER_PID"; do [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true; done
    for pid in "$OBSERVER_PID" "$ECHO_PID" "$CLIENT_PID" "$SERVER_PID"; do [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true; done
    ip netns del "$SERVER_NS" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    if [[ -n ${EZTUNNEL_TEST_LOG_DIR:-} ]]; then
        mkdir -p -- "$EZTUNNEL_TEST_LOG_DIR"
        cp "$ROOT"/*.log "$EZTUNNEL_TEST_LOG_DIR/" 2>/dev/null || true
    fi
    rm -rf -- "$ROOT"
}
trap cleanup EXIT
"$BINARY" keygen --out "$ROOT/server-keys" >/dev/null
"$BINARY" keygen --out "$ROOT/client-keys" >/dev/null
ip netns add "$SERVER_NS"; ip netns add "$CLIENT_NS"
ip link add "$SERVER_IF" type veth peer name "$CLIENT_IF"
ip link set "$SERVER_IF" netns "$SERVER_NS"; ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip -n "$SERVER_NS" link set "$SERVER_IF" address 02:00:00:00:42:01
ip -n "$CLIENT_NS" link set "$CLIENT_IF" address 02:00:00:00:42:02
ip -n "$SERVER_NS" address add 10.203.0.1/30 dev "$SERVER_IF"
ip -n "$CLIENT_NS" address add 10.203.0.2/30 dev "$CLIENT_IF"
ip -n "$SERVER_NS" link set "$SERVER_IF" up; ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$SERVER_NS" link set lo up; ip -n "$CLIENT_NS" link set lo up

wait_tunnel() {
    local family=$1 peer=$2
    for _ in {1..30}; do
        if ip netns exec "$CLIENT_NS" ping "-$family" -c 1 -W 1 "$peer" >/dev/null 2>&1; then return; fi
        kill -0 "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || break
        sleep 1
    done
    cat "$ROOT"/current-*.log >&2
    return 1
}

scenarios_run=0
for scenario in "${cases[@]}"; do
    [[ -z ${EZTUNNEL_TEST_CASE:-} || $scenario == "$EZTUNNEL_TEST_CASE" ]] || continue
    IFS=: read -r transport profile variant <<<"$scenario"
    for family in 4 6; do
        [[ -z ${EZTUNNEL_TEST_FAMILY:-} || $family == "$EZTUNNEL_TEST_FAMILY" ]] || continue
        (( scenarios_run+=1 ))
        label="$transport-$profile-$variant-ip$family"
        python3 - "$ROOT" "$family" "$transport" "$profile" "$variant" "$SERVER_IF" "$CLIENT_IF" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);family,transport,profile,variant,server_if,client_if=sys.argv[2:]
sip,cip=('10.204.0.1','10.204.0.2') if family=='4' else ('fd42:204::1','fd42:204::2')
raws=dict(profile=profile,interface=server_if,local_ip='10.203.0.1',peer_ip='10.203.0.2',l4_port=24443,peer_mac='02:00:00:00:42:02')
rawc=dict(profile=profile,interface=client_if,local_ip='10.203.0.2',peer_ip='10.203.0.1',l4_port=24443,peer_mac='02:00:00:00:42:01')
if variant=='proto58':
 raws['proto58_mode']=True
 rawc['proto58_mode']=True
if variant in ('spoof-src','spoof-both'):
 raws['spoof_src_ip']='198.18.42.1';rawc['spoof_src_ip']='198.18.42.2'
if variant in ('spoof-dst','spoof-both'):
 raws['spoof_dst_ip']='198.19.42.2';rawc['spoof_dst_ip']='198.19.42.1'
if variant=='arp':raws.pop('peer_mac');rawc.pop('peer_mac')
common=dict(heartbeat_sec=1,dead_timeout_sec=5,max_connections=1)
if variant in ('mirror','wire2'):common['wire_version']=2
server=dict(common,mode='server',private_key_file=str(root/'server-keys/private.key'),peer_public_keys=[(root/'client-keys/public.key').read_text().strip()],listeners=[dict(addr='10.203.0.1:24443',transport=transport,raw=raws,fec=dict(knock=False))],tun=dict(name='ezraw0',address=sip,peer_address=cip,mtu=1380))
client=dict(common,mode='client',private_key_file=str(root/'client-keys/private.key'),paths=[dict(addr='10.203.0.1:24443',transport=transport,server_public_key=(root/'server-keys/public.key').read_text().strip(),raw=rawc,fec=dict(knock=False),retry_interval=1)],tun=dict(name='ezraw0',address=cip,peer_address=sip,mtu=1380))
(root/'server.json').write_text(json.dumps(server));(root/'client.json').write_text(json.dumps(client))
PY
        "$BINARY" --check --config "$ROOT/server.json" >/dev/null
        "$BINARY" --check --config "$ROOT/client.json" >/dev/null
        # Observe actual Ethernet headers before either core starts. The observer
        # never prints payloads and terminates after both directions or 30 seconds.
        rm -f -- "$ROOT/observer-ready"
        ip netns exec "$SERVER_NS" python3 -u - "$ROOT" "$SERVER_IF" "$label" <<'PY' >"$ROOT/current-observer.log" 2>&1 &
import ipaddress,json,pathlib,socket,struct,sys,time
root=pathlib.Path(sys.argv[1]);interface=sys.argv[2];label=sys.argv[3]
server=json.loads((root/'server.json').read_text())['listeners'][0]
client=json.loads((root/'client.json').read_text())['paths'][0]
expected={bytes.fromhex('020000004201'):(server,True),bytes.fromhex('020000004202'):(client,False)}
protocols=dict(tcp=6,udp=17,icmp=1,gre=47,ipip=4,raw=253,dns=17)
marker=bytes.fromhex('da66e701');seen=set()
def checksum(data):
 if len(data)%2:data+=b'\0'
 total=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while total>>16:total=(total&65535)+(total>>16)
 return (~total)&65535
capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
capture.bind((interface,0));capture.settimeout(0.5)
(root/'observer-ready').write_text('ready')
deadline=time.monotonic()+30
while len(seen)<2 and time.monotonic()<deadline:
 try:frame=capture.recv(65549)
 except socket.timeout:continue
 if len(frame)<34 or frame[12:14]!=b'\x08\x00' or frame[6:12] not in expected:continue
 entry,is_server=expected[frame[6:12]];raw=entry['raw'];ip=frame[14:]
 ihl=(ip[0]&15)*4;length=int.from_bytes(ip[2:4],'big')
 if ip[0]>>4!=4 or ihl<20 or length<ihl or length>len(ip):continue
 protocol=ip[9];body=ip[ihl:length]
 proto58=raw.get('proto58_mode',False)
 source_port=raw['l4_port'] if is_server else raw.get('source_port',raw['l4_port']+1 if raw['l4_port']<65535 else 65534)
 if protocol==6:
  if len(body)<20:continue
  offset=(body[12]>>4)*4
  if offset<20 or offset>len(body):continue
  payload=body[offset:]
 elif protocol in (17,1):
  if len(body)<8:continue
  if protocol==1:
   cp=client['raw'].get('source_port',client['raw']['l4_port']+1 if client['raw']['l4_port']<65535 else 65534)
   if int.from_bytes(body[4:6],'big')!=(cp if '-mirror-' in label else source_port):continue
  payload=body[8:]
 elif protocol==47:
  if body[:4]!=b'\0\0\x08\0':continue
  payload=body[4:]
 elif protocol in (4,253):payload=body
 elif protocol==58:
  if body[:4]!=marker:continue
  payload=body[4:]
 else:continue
 if raw['profile']=='dns':
  assert len(payload)>=51 and payload[4:6]==b'\x00\x01',label
  payload=payload[51:]
 if entry['transport']=='tun':
  if not payload.startswith(b'EZTU\x01'):continue
 else:
  if len(payload)<8 or payload[4:6] not in (b'\xf1\0',b'\xf2\0'):continue
 assert ihl==20 and checksum(ip[:ihl])==0,(label,'invalid IPv4 header/checksum')
 assert protocol==(58 if proto58 else protocols[raw['profile']]),(label,'wrong outer protocol',protocol)
 assert ip[12:16]==ipaddress.IPv4Address(raw.get('spoof_src_ip',raw['local_ip'])).packed,(label,'wrong outer source IP',str(ipaddress.IPv4Address(ip[12:16])))
 assert ip[16:20]==ipaddress.IPv4Address(raw.get('spoof_dst_ip',raw['peer_ip'])).packed,(label,'wrong outer destination IP',str(ipaddress.IPv4Address(ip[16:20])))
 fec_tcp=entry['transport']!='tun' and raw['profile']=='tcp' and not proto58
 assert ip[1]==(0xb8 if fec_tcp else 0),(label,'wrong TOS',ip[1])
 flags=int.from_bytes(ip[6:8],'big')
 assert flags==(0x4000 if proto58 or fec_tcp else 0),(label,'wrong IPv4 flags',flags)
 if proto58:assert body[:4]==marker,(label,'wrong proto58 mode marker')
 seen.add(is_server)
capture.close()
assert len(seen)==2,(label,'did not observe tunnel packets in both directions',sorted(seen))
print(label+': actual outer source/destination, protocol, TOS/DF and carrier marker verified in both directions')
PY
        OBSERVER_PID=$!
        for _ in {1..50}; do
            [[ ! -f "$ROOT/observer-ready" ]] || break
            kill -0 "$OBSERVER_PID" 2>/dev/null || break
            sleep 0.05
        done
        [[ -f "$ROOT/observer-ready" ]] || { cat "$ROOT/current-observer.log" >&2; exit 1; }
        ip netns exec "$SERVER_NS" "$BINARY" -c "$ROOT/server.json" >"$ROOT/current-server.log" 2>&1 & SERVER_PID=$!
        ip netns exec "$CLIENT_NS" "$BINARY" -c "$ROOT/client.json" >"$ROOT/current-client.log" 2>&1 & CLIENT_PID=$!
        if [[ "$family" == 4 ]]; then PEER=10.204.0.1; else PEER=fd42:204::1; fi
        wait_tunnel "$family" "$PEER"
        # Both packet paths must work before introducing loss.
        ip netns exec "$SERVER_NS" ping "-$family" -c 1 -W 3 "${PEER%1}2" >/dev/null
        if ! wait "$OBSERVER_PID"; then OBSERVER_PID='';cat "$ROOT/current-observer.log" >&2;exit 1;fi
        OBSERVER_PID=''
        cat "$ROOT/current-observer.log"
        ip netns exec "$SERVER_NS" python3 - "$family" <<'PY' &
import socket,sys,threading
af=socket.AF_INET if sys.argv[1]=='4' else socket.AF_INET6;addr='0.0.0.0' if af==socket.AF_INET else '::'
udp=socket.socket(af,socket.SOCK_DGRAM);udp.bind((addr,25555));udp.settimeout(30)
tcp=socket.socket(af,socket.SOCK_STREAM);tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);tcp.bind((addr,25556));tcp.listen();tcp.settimeout(30)
def datagrams():
 for _ in range(16):
  data,peer=udp.recvfrom(65535);udp.sendto(data,peer)
t=threading.Thread(target=datagrams);t.start()
c,_=tcp.accept();c.settimeout(30)
while True:
 data=c.recv(16384)
 if not data:break
 c.sendall(data)
c.close();tcp.close();t.join();udp.close()
PY
        ECHO_PID=$!
        sleep 0.5
        ip netns exec "$CLIENT_NS" python3 - "$family" "$PEER" "$label" <<'PY'
import socket,sys
af=socket.AF_INET if sys.argv[1]=='4' else socket.AF_INET6;peer=sys.argv[2]
u=socket.socket(af,socket.SOCK_DGRAM);u.settimeout(15)
for _ in range(4):
 for n in (0,1,512,1300):
  data=bytes(i%251 for i in range(n));u.sendto(data,(peer,25555));got,_=u.recvfrom(65535);assert got==data,(sys.argv[3],n)
u.close()
print(sys.argv[3]+': ICMP and 16 UDP datagrams passed without injected loss')
PY
        # TUN datagrams intentionally preserve UDP's unreliable delivery semantics.
        # Introduce loss only after the UDP assertions; inner TCP must recover it.
        if [[ "$profile" == tcp && "$variant" == plain && ${EZTUNNEL_TEST_NETEM_LOSS:-2%} != none ]]; then
            ip netns exec "$CLIENT_NS" tc qdisc add dev "$CLIENT_IF" root netem loss "${EZTUNNEL_TEST_NETEM_LOSS:-2%}"
        fi
        ip netns exec "$CLIENT_NS" python3 - "$family" "$PEER" "$label" <<'PY'
import socket,sys,threading
af=socket.AF_INET if sys.argv[1]=='4' else socket.AF_INET6;peer=sys.argv[2]
c=socket.socket(af,socket.SOCK_STREAM);c.settimeout(30);c.connect((peer,25556))
data=bytes(i%251 for i in range(262145));out=bytearray();errors=[]
def upload():
 try:c.sendall(data);c.shutdown(socket.SHUT_WR)
 except BaseException as error:errors.append(error)
sender=threading.Thread(target=upload);sender.start()
while True:
 chunk=c.recv(16384)
 if not chunk:break
 out.extend(chunk)
sender.join(30);assert not sender.is_alive(),'TCP sender did not finish'
if errors:raise errors[0]
assert out==data,(sys.argv[3],len(out));c.close()
print(sys.argv[3]+': 262145-byte TCP half-close passed')
PY
        wait "$ECHO_PID"; ECHO_PID=''
        if [[ "$profile" == tcp && "$variant" == plain && ${EZTUNNEL_TEST_NETEM_LOSS:-2%} != none ]]; then
            printf '%s: injected-loss queue statistics\n' "$label"
            ip netns exec "$CLIENT_NS" tc -s qdisc show dev "$CLIENT_IF"
            ip netns exec "$CLIENT_NS" tc qdisc del dev "$CLIENT_IF" root
        fi
        kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=''
        ip netns exec "$SERVER_NS" "$BINARY" -c "$ROOT/server.json" >>"$ROOT/current-server.log" 2>&1 & SERVER_PID=$!
        wait_tunnel "$family" "$PEER"
        kill "$SERVER_PID" "$CLIENT_PID"; wait "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
        SERVER_PID='';CLIENT_PID=''
        if ip -n "$SERVER_NS" link show ezraw0 >/dev/null 2>&1 || ip -n "$CLIENT_NS" link show ezraw0 >/dev/null 2>&1; then printf 'Raw TUN interface leaked\n' >&2;exit 1;fi
        cp "$ROOT/current-server.log" "$ROOT/$label-server.log"
        cp "$ROOT/current-client.log" "$ROOT/$label-client.log"
        cp "$ROOT/current-observer.log" "$ROOT/$label-observer.log"
        printf '%s: server reconnect and interface teardown passed\n' "$label"
    done
done
(( scenarios_run > 0 )) || { printf 'Raw matrix selected no scenarios.\n' >&2; exit 2; }
printf 'Raw %s matrix passed (%s family-specific runs)\n' "$CARRIER" "$scenarios_run"
