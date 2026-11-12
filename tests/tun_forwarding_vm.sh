#!/usr/bin/env bash
# Privileged regression in isolated namespaces; no host routing or firewall changes.
set -euo pipefail
export RUST_LOG=debug
BINARY="$(realpath -- "${1:?Usage: bash tests/tun_forwarding_vm.sh /path/to/eztunnel}")"
[[ $(id -u) == 0 ]] || { printf 'Run as root in an isolated Linux VM.\n' >&2; exit 1; }
ROOT="$(mktemp -d)"
SERVER_NS="drfs$$"; CLIENT_NS="drfc$$"
SERVER_IF="drfs$$"; CLIENT_IF="drfc$$"
SERVER_PID=''; CLIENT_PID=''; ECHO_PID=''; REJECT_PID=''
cleanup() {
    for pid in "$REJECT_PID" "$ECHO_PID" "$CLIENT_PID" "$SERVER_PID"; do [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true; done
    for pid in "$REJECT_PID" "$ECHO_PID" "$CLIENT_PID" "$SERVER_PID"; do [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true; done
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
"$BINARY" keygen --out "$ROOT/rogue-keys" >/dev/null
ip netns add "$SERVER_NS"; ip netns add "$CLIENT_NS"
ip link add "$SERVER_IF" type veth peer name "$CLIENT_IF"
ip link set "$SERVER_IF" netns "$SERVER_NS"; ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip -n "$SERVER_NS" link set "$SERVER_IF" address 02:00:00:00:43:01
ip -n "$CLIENT_NS" link set "$CLIENT_IF" address 02:00:00:00:43:02
ip -n "$SERVER_NS" address add 10.205.0.1/30 dev "$SERVER_IF"
ip -n "$CLIENT_NS" address add 10.205.0.2/30 dev "$CLIENT_IF"
ip -n "$SERVER_NS" link set "$SERVER_IF" up; ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$SERVER_NS" link set lo up; ip -n "$CLIENT_NS" link set lo up

wait_forwarding() {
    for _ in {1..30}; do
        if ip netns exec "$SERVER_NS" python3 - <<'PY'
import socket
try:
 s=socket.create_connection(('127.0.0.1',28080),1);s.settimeout(1)
 s.sendall(b'ready');assert s.recv(5)==b'ready';s.close()
except (OSError,AssertionError):raise SystemExit(1)
PY
        then return; fi
        kill -0 "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID" 2>/dev/null || break
        sleep 1
    done
    cat "$ROOT"/current-*.log >&2
    return 1
}

for family in 4 6; do
    python3 - "$ROOT" "$family" "$SERVER_IF" "$CLIENT_IF" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);family,server_if,client_if=sys.argv[2:]
sip,cip=('10.206.0.1','10.206.0.2') if family=='4' else ('fd42:206::1','fd42:206::2')
loopback='127.0.0.1' if family=='4' else '::1'
endpoint=lambda ip,p:f'[{ip}]:{p}' if ':' in ip else f'{ip}:{p}'
common=dict(heartbeat_sec=1,dead_timeout_sec=4,max_connections=4,max_streams=32)
raws=dict(profile='tcp',interface=server_if,local_ip='10.205.0.1',peer_ip='10.205.0.2',l4_port=24443,peer_mac='02:00:00:00:43:02')
rawc=dict(raws,interface=client_if,local_ip='10.205.0.2',peer_ip='10.205.0.1',peer_mac='02:00:00:00:43:01')
server=dict(common,mode='server',private_key_file=str(root/'server-keys/private.key'),peer_public_keys=[(root/'client-keys/public.key').read_text().strip()],socks5='127.0.0.1:28083',
 listeners=[dict(addr='10.205.0.1:24443',transport='tun',raw=raws,maps=[
  dict(type='tcp',bind='127.0.0.1:28080',target=endpoint(loopback,25556)),
  dict(type='udp',bind='127.0.0.1:28081',target=endpoint(loopback,25555)),
  dict(type='tcp',bind='127.0.0.1:28082',target=endpoint(loopback,25557))])],
 tun=dict(name='ezfwd0',address=sip,peer_address=cip,mtu=1380,forwarding_port=47475))
client=dict(common,mode='client',private_key_file=str(root/'client-keys/private.key'),allowed_targets=[endpoint(loopback,25556),endpoint(loopback,25555)],
 paths=[dict(addr='10.205.0.1:24443',transport='tun',raw=rawc,server_public_key=(root/'server-keys/public.key').read_text().strip(),retry_interval=1,dial_timeout=3)],
 tun=dict(name='ezfwd0',address=cip,peer_address=sip,mtu=1380,forwarding_port=47475))
for name,cfg in [('server',server),('client',client)]: (root/(name+'.json')).write_text(json.dumps(cfg))
for name,private,public in [('rogue',root/'rogue-keys/private.key',root/'server-keys/public.key'),('wrong-pin',root/'client-keys/private.key',root/'rogue-keys/public.key')]:
 cfg=dict(common,mode='client',private_key_file=str(private),paths=[dict(addr=endpoint(sip,47475),server_public_key=public.read_text().strip(),retry_interval=1,dial_timeout=2)])
 (root/(name+'.json')).write_text(json.dumps(cfg))
(root/'denied-contact').unlink(missing_ok=True)
PY
    "$BINARY" --check -c "$ROOT/server.json" >/dev/null
    "$BINARY" --check -c "$ROOT/client.json" >/dev/null
    ip netns exec "$CLIENT_NS" python3 -u - "$family" "$ROOT" <<'PY' >"$ROOT/current-echo.log" 2>&1 &
import pathlib,socket,sys,threading
af=socket.AF_INET if sys.argv[1]=='4' else socket.AF_INET6;host='127.0.0.1' if af==socket.AF_INET else '::1';root=pathlib.Path(sys.argv[2])
def tcp(port,denied=False):
 s=socket.socket(af,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((host,port));s.listen()
 while True:
  c,_=s.accept()
  if denied:(root/'denied-contact').touch()
  def echo(c):
   try:
    c.settimeout(30)
    while True:
     data=c.recv(16384)
     if not data:break
     c.sendall(data)
   finally:c.close()
  threading.Thread(target=echo,args=(c,),daemon=True).start()
threading.Thread(target=tcp,args=(25556,),daemon=True).start()
threading.Thread(target=tcp,args=(25557,True),daemon=True).start()
u=socket.socket(af,socket.SOCK_DGRAM);u.bind((host,25555));print('echo services ready',flush=True)
while True:
 data,peer=u.recvfrom(65535);u.sendto(data,peer)
PY
    ECHO_PID=$!
    ip netns exec "$SERVER_NS" "$BINARY" -c "$ROOT/server.json" >"$ROOT/current-server.log" 2>&1 & SERVER_PID=$!
    ip netns exec "$CLIENT_NS" "$BINARY" -c "$ROOT/client.json" >"$ROOT/current-client.log" 2>&1 & CLIENT_PID=$!
    wait_forwarding
    if [[ $family == 4 ]]; then SERVER_IP=10.206.0.1;CLIENT_IP=10.206.0.2;else SERVER_IP=fd42:206::1;CLIENT_IP=fd42:206::2;fi
    ip netns exec "$CLIENT_NS" ping "-$family" -c 1 -W 3 "$SERVER_IP" >/dev/null
    # The inner relay must bind the selected TUN address, never a wildcard/public address.
    ip netns exec "$SERVER_NS" python3 - "$family" "$SERVER_IP" <<'PY'
import ipaddress,subprocess,sys
rows=subprocess.check_output(['ss','-Hltn'],text=True).splitlines()
expected=ipaddress.ip_address(sys.argv[2]);matches=[]
for row in rows:
 fields=row.split()
 if len(fields)<5:continue
 endpoint=fields[3]
 if endpoint.endswith(':47475'):
  host=endpoint[:-6].strip('[]');assert ipaddress.ip_address(host)==expected,row;matches.append(row)
assert matches,'inner relay listener is missing'
print('inner IPv'+sys.argv[1]+' relay binds only '+sys.argv[2]+':47475')
PY
    for rejection in rogue wrong-pin; do
        if [[ $rejection == rogue ]];then pattern='peer key is not authorized';else pattern='peer handshake authentication failed';fi
        before=$(grep -c "$pattern" "$ROOT/current-server.log" || true)
        ip netns exec "$CLIENT_NS" "$BINARY" -c "$ROOT/$rejection.json" >"$ROOT/current-$rejection.log" 2>&1 & REJECT_PID=$!
        rejected=0
        for _ in {1..40};do
            after=$(grep -c "$pattern" "$ROOT/current-server.log" || true)
            if (( after > before ));then rejected=1;break;fi
            sleep 0.1
        done
        kill "$REJECT_PID";wait "$REJECT_PID" 2>/dev/null || true;REJECT_PID=''
        [[ $rejected == 1 ]] || { cat "$ROOT/current-server.log" "$ROOT/current-$rejection.log" >&2;exit 1; }
        printf 'inner IPv%s %s identity rejection observed\n' "$family" "$rejection"
    done
    for phase in initial restart; do
        if [[ $phase == restart ]];then
            kill "$SERVER_PID";wait "$SERVER_PID" 2>/dev/null || true;SERVER_PID=''
            ip netns exec "$SERVER_NS" "$BINARY" -c "$ROOT/server.json" >>"$ROOT/current-server.log" 2>&1 & SERVER_PID=$!
            wait_forwarding
        fi
        ip netns exec "$SERVER_NS" python3 - "$family" "$CLIENT_IP" "$ROOT" "$phase" <<'PY'
import ipaddress,pathlib,socket,subprocess,sys,threading
family,peer,root,phase=sys.argv[1:];root=pathlib.Path(root);target='127.0.0.1' if family=='4' else '::1'
def exact(s,n):
 out=bytearray()
 while len(out)<n:
  data=s.recv(n-len(out));assert data,'unexpected EOF';out.extend(data)
 return bytes(out)
def bulk(s):
 s.settimeout(30);data=bytes(i%251 for i in range(1048577));errors=[]
 def upload():
  try:s.sendall(data);s.shutdown(socket.SHUT_WR)
  except BaseException as error:errors.append(error)
 sender=threading.Thread(target=upload);sender.start();got=bytearray()
 while True:
  part=s.recv(16384)
  if not part:break
  got.extend(part)
 sender.join(30);assert not sender.is_alive();assert not errors,errors;assert got==data,len(got);s.close()
def socks(port):
 s=socket.create_connection(('127.0.0.1',28083),5);s.settimeout(5);s.sendall(b'\x05\x01\0');assert exact(s,2)==b'\x05\0'
 addr=ipaddress.ip_address(target);s.sendall(bytes([5,1,0,1 if addr.version==4 else 4])+addr.packed+port.to_bytes(2,'big'))
 reply=exact(s,10);assert reply[0]==5 and reply[3]==1,reply
 return s,reply[1]
ping=subprocess.Popen(['ping','-'+family,'-c','6','-i','0.2','-W','2',peer],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 bulk(socket.create_connection(('127.0.0.1',28080),5))
 u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(5)
 for _ in range(4):
  for n in (0,1,512,1300):
   data=bytes(i%251 for i in range(n));u.sendto(data,('127.0.0.1',28081));got,_=u.recvfrom(16384);assert got==data,n
 u.close()
 s,status=socks(25556);assert status==0,status;bulk(s)
 denied=socket.create_connection(('127.0.0.1',28082),5);denied.settimeout(5);denied.sendall(b'denied')
 try:got=denied.recv(16)
 except ConnectionResetError:got=b''
 assert not got;denied.close()
 denied,status=socks(25557);assert status==2,status;denied.close()
 assert not (root/'denied-contact').exists(),'denied target received an actual connection'
 out,err=ping.communicate(timeout=15);assert ping.returncode==0,(out,err)
finally:
 if ping.poll() is None:ping.terminate();ping.wait(timeout=3)
print('inner IPv'+family+' '+phase+': simultaneous ICMP, 1048577-byte TCP/SOCKS half-close, 16 UDP datagrams, and target denial passed')
PY
    done
    kill "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID"
    wait "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID" 2>/dev/null || true
    SERVER_PID='';CLIENT_PID='';ECHO_PID=''
    if ip -n "$SERVER_NS" link show ezfwd0 >/dev/null 2>&1 || ip -n "$CLIENT_NS" link show ezfwd0 >/dev/null 2>&1;then
        printf 'Combined TUN forwarding interface leaked\n' >&2;exit 1
    fi
    for name in server client echo rogue wrong-pin;do cp "$ROOT/current-$name.log" "$ROOT/tun-forwarding-ip$family-$name.log";done
    printf 'inner IPv%s server restart and owned TUN teardown passed\n' "$family"
done
printf 'Raw TUN plus forwarding matrix passed (IPv4 and IPv6)\n'
