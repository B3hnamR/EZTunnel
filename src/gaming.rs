//! Negotiated unreliable UDP channels with Noise-bound keys and stable flow IDs.
//! The ordinary reliable mux is unchanged; disabled configurations create no socket.
use anyhow::{Result, Context, ensure};
use serde::{Serialize, Deserialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::{TcpListener,TcpStream,UdpSocket},io::{AsyncReadExt,AsyncWriteExt},sync::{mpsc,Mutex,Semaphore,OwnedSemaphorePermit},time::{Instant,timeout}};
use snow::{Builder, HandshakeState, StatelessTransportState};

const DOMAIN:&[u8]=b"eztunnel/open-source/direct-gaming/negotiated-migration/v1";
const HEADER:usize=28;
const TAG:usize=16;
const MAX_PACKET:usize=1400;
const QUEUE:usize=32;

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(default,deny_unknown_fields)]
pub struct Options {
    pub control_address:Option<String>,
    pub udp_bind:Option<SocketAddr>,
    pub advertise:Option<SocketAddr>,
    pub migrate:bool,
    pub mtu:usize,
    pub renewal_sec:u64,
    pub max_flows:usize,
}
impl Default for Options {fn default()->Self {Self {control_address:None,udp_bind:None,advertise:None,migrate:true,mtu:1200,renewal_sec:300,max_flows:1024}}}
impl Options {
    pub fn enabled(&self)->bool {self.control_address.is_some()}
    pub fn validate(&self)->Result<()> {
        ensure!((256..=MAX_PACKET).contains(&self.mtu),"gaming mtu must be256..1400");
        ensure!((5..=300).contains(&self.renewal_sec),"gaming renewal_sec must be5..300");
        ensure!((1..=4096).contains(&self.max_flows),"gaming max_flows must be1..4096");
        if let Some(address)=&self.control_address {let addr:SocketAddr=address.parse().context("gaming control_address requires IP:port")?;ensure!(addr.port()!=0,"gaming control port must be nonzero");ensure!(self.udp_bind.is_some(),"gaming needs explicit udp_bind");}
        if let Some(addr)=self.advertise {ensure!(addr.port()!=0 && !addr.ip().is_unspecified(),"gaming advertise must be a reachable IP:port");}
        Ok(())
    }
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum Message {
    Probe([u8;16]),
    ProbeAck([u8;16]),
    Data {flow:[u8;16],generation:u64,sequence:u64,target:String,payload:Vec<u8>},
    Close {flow:[u8;16],generation:u64},
    Fragment {id:u64,index:u8,count:u8,bytes:Vec<u8>},
}
impl Message {
    fn encode(&self)->Result<Vec<u8>> {
        let mut bytes=Vec::new();
        match self {
            Self::Probe(value)|Self::ProbeAck(value)=>{bytes.push(if matches!(self,Self::Probe(_)){1}else{2});bytes.extend_from_slice(value);}
            Self::Data {flow,generation,sequence,target,payload}=>{
                ensure!(target.len()<=1024,"gaming target too long");bytes.push(3);bytes.extend_from_slice(flow);bytes.extend_from_slice(&generation.to_be_bytes());bytes.extend_from_slice(&sequence.to_be_bytes());bytes.extend_from_slice(&(target.len() as u16).to_be_bytes());bytes.extend_from_slice(target.as_bytes());bytes.extend_from_slice(payload);
            }
            Self::Close {flow,generation}=>{bytes.push(4);bytes.extend_from_slice(flow);bytes.extend_from_slice(&generation.to_be_bytes());}
            Self::Fragment{id,index,count,bytes:part}=>{ensure!(*count>0 && *count<=128 && index<count && !part.is_empty(),"invalid gaming fragment");bytes.push(5);bytes.extend_from_slice(&id.to_be_bytes());bytes.push(*index);bytes.push(*count);bytes.extend_from_slice(part);}
        }
        Ok(bytes)
    }
    fn decode(bytes:&[u8])->Result<Self> {
        ensure!(!bytes.is_empty(),"empty gaming message");
        match bytes[0] {
            1|2=>{ensure!(bytes.len()==17,"gaming probe length");let value=bytes[1..17].try_into().unwrap();Ok(if bytes[0]==1{Self::Probe(value)}else{Self::ProbeAck(value)})}
            3=>{
                ensure!(bytes.len()>=35,"short gaming data");let size=u16::from_be_bytes(bytes[33..35].try_into().unwrap()) as usize;
                ensure!(size<=1024 && bytes.len()>=35+size,"gaming target length");
                Ok(Self::Data {flow:bytes[1..17].try_into().unwrap(),generation:u64::from_be_bytes(bytes[17..25].try_into().unwrap()),sequence:u64::from_be_bytes(bytes[25..33].try_into().unwrap()),target:std::str::from_utf8(&bytes[35..35+size])?.to_owned(),payload:bytes[35+size..].to_vec()})
            }
            4=>{ensure!(bytes.len()==25,"gaming close length");Ok(Self::Close {flow:bytes[1..17].try_into().unwrap(),generation:u64::from_be_bytes(bytes[17..25].try_into().unwrap())})}
            5=>{ensure!(bytes.len()>11 && bytes[10]>0 && bytes[10]<=128 && bytes[9]<bytes[10],"invalid gaming fragment");Ok(Self::Fragment{id:u64::from_be_bytes(bytes[1..9].try_into().unwrap()),index:bytes[9],count:bytes[10],bytes:bytes[11..].to_vec()})}
            _=>anyhow::bail!("unknown gaming message"),
        }
    }
}

#[derive(Default)]
pub struct Replay {high:u64,bits:[u64;16],initialized:bool}
impl Replay {
    pub fn seen(&self,n:u64)->bool {if !self.initialized||n>self.high{return false;}let distance=self.high-n;distance>=1024||self.bits[distance as usize/64]&(1u64<<(distance%64))!=0}
    pub fn commit(&mut self,n:u64)->bool {
        if self.seen(n){return false;}
        if !self.initialized {self.initialized=true;self.high=n;}
        if n>self.high {let distance=(n-self.high).min(1024) as usize;let mut next=[0;16];for bit in 0..1024-distance{if self.bits[bit/64]&(1u64<<(bit%64))!=0{let new=bit+distance;next[new/64]|=1u64<<(new%64);}}self.bits=next;self.high=n;}
        let bit=(self.high-n) as usize;self.bits[bit/64]|=1u64<<(bit%64);true
    }
}

pub struct Codec {
    cipher:StatelessTransportState,
    id:[u8;16],
    counter:u64,
    replay:Replay,
    created:Instant,
    mtu:usize,
}
impl Codec {
    fn new(handshake:HandshakeState,mtu:usize)->Result<Self> {
        let id=handshake.get_handshake_hash()[..16].try_into().unwrap();
        let cipher=crate::session_crypto::stateless(handshake,3)?.state;
        Ok(Self{cipher,id,counter:0,replay:Replay::default(),created:Instant::now(),mtu})
    }
    pub fn encode(&mut self,message:&Message)->Result<Vec<u8>> {
        ensure!(self.created.elapsed()<Duration::from_secs(360),"gaming session expired");
        ensure!(self.counter<u64::MAX,"gaming counter exhausted");
        let plain=message.encode()?;ensure!(HEADER+TAG+plain.len()<=self.mtu,"gaming datagram exceeds negotiated MTU");
        let mut output=vec![0;HEADER+TAG+plain.len()];output[..4].copy_from_slice(b"EZG1");output[4..20].copy_from_slice(&self.id);output[20..28].copy_from_slice(&self.counter.to_be_bytes());
        let size=self.cipher.write_message(self.counter,&plain,&mut output[HEADER..])?;output.truncate(HEADER+size);self.counter+=1;Ok(output)
    }
    pub fn decode(&mut self,bytes:&[u8])->Result<Message> {
        ensure!(self.created.elapsed()<Duration::from_secs(360),"gaming session expired");
        ensure!((HEADER+TAG+1..=self.mtu).contains(&bytes.len()) && &bytes[..4]==b"EZG1" && bytes[4..20]==self.id,"gaming channel/length mismatch");
        let counter=u64::from_be_bytes(bytes[20..28].try_into().unwrap());ensure!(!self.replay.seen(counter),"replayed gaming datagram");
        let mut plain=vec![0;bytes.len()-HEADER];let size=self.cipher.read_message(counter,&bytes[HEADER..],&mut plain)?;
        let message=Message::decode(&plain[..size])?;
        // Neither malformed nor forged packets move the replay window.
        ensure!(self.replay.commit(counter),"replayed gaming datagram");Ok(message)
    }
}

fn random<const N:usize>()->Result<[u8;N]>{let mut bytes=[0;N];rustls::crypto::ring::default_provider().secure_random.fill(&mut bytes).map_err(|_|anyhow::anyhow!("gaming randomness unavailable"))?;Ok(bytes)}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {version:u8,direct:bool,migration:bool,mtu:usize,address:SocketAddr}

async fn write_handshake(stream:&mut TcpStream,bytes:&[u8])->Result<()> {ensure!(bytes.len()<=2048,"gaming handshake size");stream.write_u16(bytes.len() as u16).await?;stream.write_all(bytes).await?;Ok(())}
async fn read_handshake(stream:&mut TcpStream)->Result<Vec<u8>> {let size=stream.read_u16().await? as usize;ensure!((1..=2048).contains(&size),"gaming handshake length");let mut bytes=vec![0;size];stream.read_exact(&mut bytes).await?;Ok(bytes)}

async fn handshake(mut stream:TcpStream,private:&[u8;32],peer:Option<[u8;32]>,allowed:&[[u8;32]],options:&Options,advertise:SocketAddr)->Result<(Codec,SocketAddr,[u8;32],bool,TcpStream)> {
    stream.set_nodelay(true)?;
    let mut builder=Builder::new(crate::transport::NOISE_PATTERN.parse()?).local_private_key(private)?.prologue(DOMAIN)?;
    if let Some(peer)=&peer{builder=builder.remote_public_key(peer)?;}
    let mut state=if peer.is_some(){builder.build_initiator()?}else{builder.build_responder()?};
    let local=serde_json::to_vec(&Hello{version:1,direct:true,migration:options.migrate,mtu:options.mtu,address:advertise})?;
    let mut wire=[0;2048];let mut plain=[0;2048];
    let remote=if peer.is_some(){
        let size=state.write_message(&local,&mut wire)?;write_handshake(&mut stream,&wire[..size]).await?;
        let response=read_handshake(&mut stream).await?;let size=state.read_message(&response,&mut plain)?;serde_json::from_slice::<Hello>(&plain[..size])?
    }else{
        let request=read_handshake(&mut stream).await?;let size=state.read_message(&request,&mut plain)?;
        let hello=serde_json::from_slice::<Hello>(&plain[..size])?;
        let identity=state.get_remote_static().context("gaming peer identity missing")?;
        ensure!(allowed.iter().any(|key|key.as_slice()==identity),"gaming peer identity not allowed");
        let size=state.write_message(&local,&mut wire)?;write_handshake(&mut stream,&wire[..size]).await?;hello
    };
    ensure!(remote.version==1 && remote.direct && (256..=MAX_PACKET).contains(&remote.mtu),"unsupported gaming capabilities");
    ensure!(remote.address.port()!=0 && !remote.address.ip().is_unspecified() && remote.address.ip()==stream.peer_addr()?.ip(),"gaming address must match authenticated control peer IP");
    let identity=state.get_remote_static().context("gaming peer key")?.try_into().unwrap();
    let codec=Codec::new(state,options.mtu.min(remote.mtu))?;
    Ok((codec,remote.address,identity,options.migrate&&remote.migration,stream))
}

struct Channel {
    codec:Mutex<Codec>, address:SocketAddr, peer:[u8;32], migrate:bool,
    generation:u64,challenge:[u8;16],ready:std::sync::atomic::AtomicBool,created:Instant,
    fragments:Mutex<HashMap<u64,Fragments>>,
}
struct Fragments{created:Instant,parts:Vec<Option<Vec<u8>>>,bytes:usize}

/// V05: how long a freshly accepted channel may stay unproved (challenge unanswered).
const CHANNEL_PROOF: Duration = Duration::from_secs(30);

/// V05: makes room for a new, still unproved channel of `peer`. An unproved channel never
/// displaces a ready one: it supersedes only older unproved channels of the same peer, and
/// at most the two newest ready channels of that peer are kept.
fn admit_channel(channels:&mut HashMap<[u8;16],Arc<Channel>>,peer:[u8;32]) {
    let ready=|c:&Arc<Channel>|c.ready.load(std::sync::atomic::Ordering::Acquire);
    channels.retain(|_,c|c.peer!=peer||ready(c));
    let mut same=channels.iter().filter(|(_,c)|c.peer==peer).map(|(id,c)|(*id,c.generation)).collect::<Vec<_>>();
    same.sort_by_key(|(_,generation)|*generation);
    for(old,_)in same.into_iter().rev().skip(2){channels.remove(&old);}
}
struct Flow {
    generation:u64,replay:Replay,touched:Instant,target:String,
    address:SocketAddr,
    instance:[u8;16],
    sender:mpsc::Sender<Queued>,
}
struct Queued{bytes:Vec<u8>,_permit:OwnedSemaphorePermit}
struct Origin {sender:mpsc::Sender<Queued>,touched:Instant,replay:Replay,peer:Option<[u8;32]>,generation:u64,address:Option<SocketAddr>}
pub struct Hub {
    socket:tokio::sync::watch::Sender<Arc<UdpSocket>>,options:Options,
    rebind:Arc<tokio::sync::Notify>,
    advertised:std::sync::RwLock<SocketAddr>,
    channels:Mutex<HashMap<[u8;16],Arc<Channel>>>,
    flows:Mutex<HashMap<([u8;32],[u8;16]),Flow>>,
    origins:Mutex<HashMap<[u8;16],Origin>>,
    tombstones:Mutex<HashMap<([u8;32],[u8;16]),Instant>>,
    queued_bytes:Arc<Semaphore>,
    sequence:std::sync::atomic::AtomicU64,
    generation:std::sync::atomic::AtomicU64,
    tasks:std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl Drop for Hub {fn drop(&mut self){for task in self.tasks.get_mut().unwrap_or_else(|e|e.into_inner()).drain(..){task.abort();}}}

impl Hub {
    pub async fn start(config:&crate::config::Config)->Result<Arc<Self>> {
        use crate::config::Mode;
        let options=config.gaming.clone();options.validate()?;
        let socket=Arc::new(UdpSocket::bind(options.udp_bind.context("gaming udp_bind")?).await?);
        let advertise=options.advertise.unwrap_or(socket.local_addr()?);
        ensure!(!advertise.ip().is_unspecified(),"gaming needs explicit advertise when udp_bind is unspecified");
        let private=config.private_key()?;
        let allowed=config.peer_public_keys.iter().map(|key|crate::config::decode_key(key)).collect::<Result<Vec<_>>>()?;
        let peer=if config.mode==Mode::Client {
            let path=config.paths.first().context("gaming client requires configured path")?;
            Some(crate::config::decode_key(&path.server_public_key)?)
        }else{None};
        let targets=config.allowed_targets.clone();
        let idle=Duration::from_secs(config.timeouts.udp_idle_sec);
        let listener=if config.mode==Mode::Server {Some(TcpListener::bind(options.control_address.as_ref().context("gaming control address")?).await?)}else{None};
        let(socket,_)=tokio::sync::watch::channel(socket);
        let hub=Arc::new(Self{socket,options:options.clone(),rebind:Arc::new(tokio::sync::Notify::new()),advertised:std::sync::RwLock::new(advertise),channels:Mutex::new(HashMap::new()),flows:Mutex::new(HashMap::new()),origins:Mutex::new(HashMap::new()),tombstones:Mutex::new(HashMap::new()),queued_bytes:Arc::new(Semaphore::new(16*1024*1024)),sequence:0.into(),generation:1.into(),tasks:std::sync::Mutex::new(Vec::new())});
        let weak=Arc::downgrade(&hub);
        let control=tokio::spawn(async move {
            loop {
                let stream=if let Some(listener)=&listener {listener.accept().await.map(|(s,_)|s)}else{TcpStream::connect(options.control_address.as_ref().unwrap()).await};
                let Ok(stream)=stream else {tokio::time::sleep(Duration::from_secs(1)).await;continue;};
                let Some(hub)=weak.upgrade()else{break;};let advertise=*hub.advertised.read().unwrap_or_else(|e|e.into_inner());drop(hub);
                match timeout(Duration::from_secs(5),handshake(stream,&private,peer,&allowed,&options,advertise)).await {
                    Ok(Ok((codec,address,identity,migrate,mut control)))=>{
                        let Some(hub)=weak.upgrade()else{break;};
                        let channel=Arc::new(Channel {codec:Mutex::new(codec),address,peer:identity,migrate,
                            generation:hub.generation.fetch_add(1,std::sync::atomic::Ordering::Relaxed),challenge:match random(){Ok(v)=>v,Err(_)=>break},ready:false.into(),created:Instant::now(),fragments:Mutex::new(HashMap::new())});
                        let id=channel.codec.lock().await.id;
                        {let mut channels=hub.channels.lock().await;channels.retain(|_,c|c.created.elapsed()<Duration::from_secs(360));
                            admit_channel(&mut channels,identity);
                            if channels.len()>=16 {drop(channels);drop(hub);continue;}
                            channels.insert(id,channel.clone());}
                        let _=hub.transmit(&channel,&Message::Probe(channel.challenge)).await;
                        drop(hub);
                        // A separate accepted channel replaces no flow/socket until its
                        // challenge succeeds. The old channel overlaps until key expiry.
                        let mut byte=[0;1];
                        let duration=Duration::from_secs(options.renewal_sec);
                        let renew=tokio::time::sleep(duration);tokio::pin!(renew);
                        // V05: a replayed first flight cannot answer the challenge under the fresh
                        // keys; it must not hold this accept loop for the whole renewal period.
                        let proof=tokio::time::sleep(CHANNEL_PROOF.min(duration));tokio::pin!(proof);
                        loop {
                            let Some(hub)=weak.upgrade()else{return;};
                            let rebind=hub.rebind.clone();drop(hub);
                            let notified=rebind.notified();tokio::pin!(notified);
                            tokio::select! {
                                _=&mut renew=>break,
                                _=&mut proof, if !channel.ready.load(std::sync::atomic::Ordering::Acquire)=>{
                                    if let Some(hub)=weak.upgrade(){hub.channels.lock().await.remove(&id);}
                                    tracing::debug!("gaming channel did not answer its challenge; closing it");
                                    break;
                                }
                                _=&mut notified=>break,
                                _=control.read(&mut byte)=>break,
                                _=tokio::time::sleep(Duration::from_millis(250))=>{
                                    let Some(hub)=weak.upgrade()else{return;};
                                    if !channel.ready.load(std::sync::atomic::Ordering::Acquire){let _=hub.transmit(&channel,&Message::Probe(channel.challenge)).await;}
                                }
                            }
                        }
                    }
                    Ok(Err(error))=>tracing::debug!(%error,"gaming capabilities/identity handshake rejected"),
                    Err(_)=>tracing::debug!("gaming capabilities/identity handshake timed out"),
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        let weak=Arc::downgrade(&hub);let mut socket_updates=hub.socket.subscribe();
        let receiver=tokio::spawn(async move {
            let mut bytes=[0;MAX_PACKET+1];
            loop {
                let socket=socket_updates.borrow_and_update().clone();
                let result=tokio::select!{result=socket.recv_from(&mut bytes)=>result,changed=socket_updates.changed()=>{if changed.is_err(){break;}continue;}};
                let Ok((length,source))=result else {break;};
                if length<HEADER+TAG+1 || length>MAX_PACKET || &bytes[..4]!=b"EZG1" {continue;}
                let Some(hub)=weak.upgrade()else{break;};
                let id:[u8;16]=bytes[4..20].try_into().unwrap();
                let channel=hub.channels.lock().await.get(&id).cloned();let Some(channel)=channel else{continue;};
                if source!=channel.address{continue;}
                let decoded=channel.codec.lock().await.decode(&bytes[..length]);
                let Ok(mut message)=decoded else{crate::transport_metrics::GAMING_REJECTED.fetch_add(1,std::sync::atomic::Ordering::Relaxed);continue;};
                crate::transport_metrics::GAMING_RX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
                if let Message::Fragment{id,index,count,bytes:part}=message {
                    let mut pending=channel.fragments.lock().await;pending.retain(|_,parts|parts.created.elapsed()<Duration::from_secs(2));
                    if pending.len()>=16 && !pending.contains_key(&id){continue;}
                    let parts=pending.entry(id).or_insert_with(||Fragments{created:Instant::now(),parts:vec![None;count as usize],bytes:0});
                    if parts.parts.len()!=count as usize || parts.parts[index as usize].is_some() || parts.bytes+part.len()>17_500 {continue;}
                    parts.bytes+=part.len();parts.parts[index as usize]=Some(part);
                    if parts.parts.iter().any(Option::is_none){continue;}
                    let parts=pending.remove(&id).expect("fragment set exists");
                    let bytes=parts.parts.into_iter().flatten().flatten().collect::<Vec<_>>();
                    let Ok(decoded)=Message::decode(&bytes)else{continue;};
                    if matches!(decoded,Message::Fragment{..}){continue;}
                    crate::transport_metrics::GAMING_FRAGMENTS.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
                    message=decoded;
                }
                match message {
                    Message::Probe(value)=>{let _=hub.transmit(&channel,&Message::ProbeAck(value)).await;}
                    Message::ProbeAck(value) if value==channel.challenge=>{
                        if !channel.ready.swap(true,std::sync::atomic::Ordering::AcqRel){crate::transport_metrics::GAMING_CHANNELS.fetch_add(1,std::sync::atomic::Ordering::Relaxed);tracing::info!(peer=%channel.address,generation=channel.generation,migration=channel.migrate,"authenticated gaming datagram path validated");}
                    }
                    // Inbound AEAD+fixed negotiated address is authenticated even
                    // while our own reverse-path challenge is still in flight.
                    // Requiring symmetric probe completion drops rollover data.
                    Message::Data{flow,generation,sequence,target,payload}=>{
                        if config_role_is_origin(peer) {
                            if !target.is_empty(){continue;}
                            let sender={let mut origins=hub.origins.lock().await;origins.get_mut(&flow).and_then(|origin|{
                                if origin.peer!=Some(channel.peer)||generation!=origin.generation||!origin.replay.commit(sequence){return None;}
                                origin.touched=Instant::now();Some(origin.sender.clone())})};
                            if let Some(sender)=sender {
                                if let Ok(permit)=hub.queued_bytes.clone().try_acquire_many_owned(payload.len().max(1) as u32){let _=sender.try_send(Queued{bytes:payload,_permit:permit});}
                            }
                        }else{
                            if let Err(error)=hub.deliver(channel.clone(),flow,generation,sequence,target,payload,&targets,idle).await {tracing::debug!(%error,"gaming flow packet rejected");}
                        }
                    }
                    Message::Close{flow,generation}=>hub.close_flow(channel.peer,flow,generation).await,
                    _=>{}
                }
            }
        });
        hub.tasks.lock().unwrap_or_else(|e|e.into_inner()).extend([control,receiver]);
        Ok(hub)
    }
    async fn transmit(&self,channel:&Channel,message:&Message)->Result<()> {
        let socket=self.socket.borrow().clone();
        let mut codec=channel.codec.lock().await;
        let plain=message.encode()?;
        ensure!(plain.len()<=17_500,"gaming message exceeds bounded datagram size");
        if HEADER+TAG+plain.len()<=codec.mtu {
            let bytes=codec.encode(message)?;socket.send_to(&bytes,channel.address).await?;
            crate::transport_metrics::GAMING_TX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        }else {
            ensure!(!matches!(message,Message::Fragment{..}),"nested gaming fragment");
            let size=codec.mtu-HEADER-TAG-11;
            let count=plain.len().div_ceil(size);ensure!(count<=128,"gaming fragment count exceeded");
            let id=codec.counter;
            for(index,part)in plain.chunks(size).enumerate(){let bytes=codec.encode(&Message::Fragment{id,index:index as u8,count:count as u8,bytes:part.to_vec()})?;socket.send_to(&bytes,channel.address).await?;
                crate::transport_metrics::GAMING_TX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
                // Releasing the executor after a small batch lets the peer drain
                // its UDP receive queue under the same CPU budget; no ACK/retry.
                if index%4==3 {tokio::task::yield_now().await;}}
        }
        Ok(())
    }
    async fn latest(&self,peer:Option<[u8;32]>)->Option<Arc<Channel>> {
        self.channels.lock().await.values().filter(|channel|peer.is_none_or(|p|p==channel.peer)&&channel.ready.load(std::sync::atomic::Ordering::Acquire)&&channel.created.elapsed()<Duration::from_secs(350)).max_by_key(|c|c.generation).cloned()
    }
    pub async fn register(&self)->Result<([u8;16],mpsc::Receiver<Vec<u8>>)> {
        let mut origins=self.origins.lock().await;origins.retain(|_,origin|!origin.sender.is_closed()&&origin.touched.elapsed()<Duration::from_secs(3600));
        ensure!(origins.len()<self.options.max_flows,"gaming origin flow limit");
        let flow=random()?;let(tx,mut queue)=mpsc::channel::<Queued>(QUEUE);
        let(out,rx)=mpsc::channel(1);
        origins.insert(flow,Origin{sender:tx,touched:Instant::now(),replay:Replay::default(),peer:None,generation:0,address:None});
        // One outside-caller packet is unbudgeted; all queued datagrams retain
        // a permit until accepted by the bounded per-flow consumer.
        let task=tokio::spawn(async move{loop {tokio::select!{
            _=out.closed()=>break,
            packet=queue.recv()=>{let Some(packet)=packet else{break;};if out.send(packet.bytes).await.is_err(){break;}}
        }}});
        let mut tasks=self.tasks.lock().unwrap_or_else(|e|e.into_inner());tasks.retain(|task|!task.is_finished());tasks.push(task);
        Ok((flow,rx))
    }
    pub async fn unregister(&self,flow:[u8;16]) {
        self.origins.lock().await.remove(&flow);
        if let Some(channel)=self.latest(None).await{let _=self.transmit(&channel,&Message::Close{flow,generation:channel.generation}).await;}
    }
    pub async fn send(&self,flow:[u8;16],target:&str,payload:&[u8])->Result<bool> {
        let Some(channel)=self.latest(None).await else {return Ok(false);};
        {let mut origins=self.origins.lock().await;let origin=origins.get_mut(&flow).context("unknown gaming origin flow")?;
            ensure!(origin.peer.is_none_or(|peer|peer==channel.peer),"gaming flow cannot migrate to a different authenticated identity");
            ensure!(origin.generation==0 || origin.address==Some(channel.address) || channel.migrate,"gaming migration was not negotiated");
            origin.peer=Some(channel.peer);origin.generation=channel.generation;origin.address=Some(channel.address);}
        let message=Message::Data{flow,generation:channel.generation,sequence:self.sequence.fetch_add(1,std::sync::atomic::Ordering::Relaxed),target:target.to_owned(),payload:payload.to_vec()};
        ensure!(payload.len()<=crate::wire::DATA_SIZE,"gaming datagram exceeds stream payload limit");
        self.transmit(&channel,&message).await?;
        if let Some(origin)=self.origins.lock().await.get_mut(&flow){origin.touched=Instant::now();}
        Ok(true)
    }
    pub async fn usable(&self)->bool {self.latest(None).await.is_some()}
    /// Explicit local path change. Keep flow IDs/target sockets, but require new
    /// control authentication and return-path validation before sending data.
    pub async fn rebind(&self,bind:SocketAddr,advertise:Option<SocketAddr>)->Result<SocketAddr> {
        ensure!(self.options.migrate,"gaming migration is disabled");
        let socket=Arc::new(UdpSocket::bind(bind).await?);let local=socket.local_addr()?;
        let advertised=advertise.unwrap_or(local);
        ensure!(!advertised.ip().is_unspecified()&&advertised.port()!=0,"gaming rebind requires reachable advertised endpoint");
        *self.advertised.write().unwrap_or_else(|e|e.into_inner())=advertised;
        self.socket.send_replace(socket);
        for channel in self.channels.lock().await.values(){channel.ready.store(false,std::sync::atomic::Ordering::Release);}
        self.rebind.notify_one();Ok(local)
    }
    pub fn fits(&self,target:&str,size:usize)->bool {HEADER+TAG+35+target.len()+size<=self.options.mtu}
    /// C13: an authenticated Close retires the flow even when its first Data has not
    /// arrived yet, so a reordered earlier Data cannot create the flow afterwards. A
    /// lower-generation Close never removes a newer live flow.
    async fn close_flow(&self,peer:[u8;32],flow:[u8;16],generation:u64) {
        let mut flows=self.flows.lock().await;
        if flows.get(&(peer,flow)).is_none_or(|entry|generation>=entry.generation){
            flows.remove(&(peer,flow));drop(flows);self.retire((peer,flow)).await;
        }
    }
    async fn retire(&self,key:([u8;32],[u8;16])) {
        let mut tombstones=self.tombstones.lock().await;
        tombstones.retain(|_,time|time.elapsed()<Duration::from_secs(361));
        // Admission reserves enough tombstone slots for all live flows; do not
        // evict live-window tombstones to make stale authenticated packets valid.
        if tombstones.len()<self.options.max_flows*4 {tombstones.insert(key,Instant::now());}
    }
    async fn deliver(self:&Arc<Self>,channel:Arc<Channel>,flow:[u8;16],generation:u64,sequence:u64,target:String,payload:Vec<u8>,allowed:&[String],idle:Duration)->Result<()> {
        ensure!(!target.is_empty()&&allowed.iter().any(|entry|crate::engine::target_allowed(entry,&target)),"gaming target not allowed");
        ensure!(generation>0,"invalid gaming generation");
        let key=(channel.peer,flow);
        {
            let mut tombstones=self.tombstones.lock().await;tombstones.retain(|_,time|time.elapsed()<Duration::from_secs(361));
            ensure!(!tombstones.contains_key(&key),"closed gaming flow");
            ensure!(tombstones.len()<self.options.max_flows*3,"gaming retired flow admission budget");
        }
        let permit=self.queued_bytes.clone().try_acquire_many_owned(payload.len().max(1) as u32).context("gaming aggregate queue byte budget")?;
        let mut flows=self.flows.lock().await;
        // The owned task enforces idle time. Removing a live sender here races
        // its asynchronous cleanup and can recreate a target socket mid-flow.
        flows.retain(|_,entry|!entry.sender.is_closed());
        if let Some(entry)=flows.get_mut(&key) {
            ensure!(entry.target==target,"gaming flow target changed");
            ensure!(generation>=entry.generation,"stale gaming generation");
            ensure!(channel.address==entry.address||channel.migrate,"gaming migration not mutually enabled");
            ensure!(entry.replay.commit(sequence),"duplicate migrated gaming datagram");
            if generation>entry.generation {crate::transport_metrics::GAMING_MIGRATIONS.fetch_add(1,std::sync::atomic::Ordering::Relaxed);}
            entry.generation=generation;entry.address=channel.address;entry.touched=Instant::now();let _=entry.sender.try_send(Queued{bytes:payload,_permit:permit});return Ok(());
        }
        ensure!(flows.len()<self.options.max_flows,"gaming target flow limit");
        // Target validation precedes socket creation; bounded DNS/connect outside
        // the packet receiver lock is handled by the owned per-flow task.
        let(tx,mut rx)=mpsc::channel::<Queued>(QUEUE);let mut replay=Replay::default();replay.commit(sequence);
        let instance=random()?;
        flows.insert(key,Flow{generation,replay,touched:Instant::now(),target:target.clone(),address:channel.address,instance,sender:tx.clone()});drop(flows);
        tx.try_send(Queued{bytes:payload,_permit:permit}).map_err(|_|anyhow::anyhow!("gaming initial queue"))?;
        let weak=Arc::downgrade(self);let peer=channel.peer;
        let task=tokio::spawn(async move {
            let result=async {
                let address=timeout(Duration::from_secs(5),tokio::net::lookup_host(&target)).await??.next().context("gaming target address")?;
                let socket=UdpSocket::bind(if address.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"}).await?;socket.connect(address).await?;
                let mut bytes=[0;65536];
                loop {
                    let Some(hub)=weak.upgrade()else{break;};
                    let deadline={let flows=hub.flows.lock().await;let Some(entry)=flows.get(&key).filter(|entry|entry.instance==instance)else{break;};entry.touched+idle};
                    drop(hub);
                    tokio::select! {
                        packet=rx.recv()=>{let Some(packet)=packet else{break;};socket.send(&packet.bytes).await?;}
                        result=socket.recv(&mut bytes)=>{
                            let size=result?;let Some(hub)=weak.upgrade()else{break;};let Some(channel)=hub.latest(Some(peer)).await else{continue;};
                            let generation={let mut flows=hub.flows.lock().await;let Some(entry)=flows.get_mut(&key).filter(|entry|entry.instance==instance)else{break;};entry.touched=Instant::now();entry.generation};
                            let message=Message::Data{flow,generation,sequence:hub.sequence.fetch_add(1,std::sync::atomic::Ordering::Relaxed),target:String::new(),payload:bytes[..size].to_vec()};
                            let _=hub.transmit(&channel,&message).await;
                        }
                        _=tokio::time::sleep_until(deadline)=>break,
                    }
                }
                Ok::<_,anyhow::Error>(())
            }.await;
            if let Err(error)=result{tracing::debug!(%error,"gaming UDP target ended");}
            if let Some(hub)=weak.upgrade(){
                let removed={let mut flows=hub.flows.lock().await;if flows.get(&key).is_some_and(|entry|entry.instance==instance){flows.remove(&key);true}else{false}};
                if removed{hub.retire(key).await;}
            }
        });
        let mut tasks=self.tasks.lock().unwrap_or_else(|e|e.into_inner());tasks.retain(|task|!task.is_finished());tasks.push(task);
        Ok(())
    }
}

fn config_role_is_origin(peer:Option<[u8;32]>)->bool {peer.is_none()}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn message_codec_preserves_zero_length_udp_and_bounds_untrusted_targets()->Result<()> {
        let message=Message::Data{flow:[1;16],generation:2,sequence:3,target:"127.0.0.1:1234".into(),payload:vec![]};assert_eq!(Message::decode(&message.encode()?)?,message);
        for n in 0..35 {assert!(Message::decode(&vec![3;n]).is_err());}
        assert!(Message::decode(&[7]).is_err());Ok(())
    }
    #[test]
    fn malformed_and_reordered_fragment_and_replay_inputs_are_bounded()->Result<()> {
        let mut replay=Replay::default();assert!(replay.commit(2000));assert!(replay.commit(1999));assert!(!replay.commit(1999));assert!(!replay.commit(975));assert!(replay.commit(u64::MAX-1));assert!(!replay.commit(2000));
        for size in 0..64 {for tag in 0..8 {let mut packet=vec![0;size];if size>0{packet[0]=tag;}let _=Message::decode(&packet);}}
        for count in [0,129,255] {assert!(Message::Fragment{id:1,index:0,count,bytes:vec![1]}.encode().is_err());}
        assert!(Message::Fragment{id:1,index:2,count:2,bytes:vec![1]}.encode().is_err());
        assert!(Message::Data{flow:[0;16],generation:1,sequence:1,target:"x".repeat(1025),payload:vec![]}.encode().is_err());Ok(())
    }
    #[tokio::test]
    async fn handshake_negotiates_mtu_identity_and_rejects_replay_and_forgery()->Result<()> {
        let server=Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let client=Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let listener=TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;
        let options=Options::default();let allowed=[client.public.try_into().unwrap()];
        let task=tokio::spawn(async move{let(s,_)=listener.accept().await?;handshake(s,&server.private.try_into().unwrap(),None,&allowed,&options,"127.0.0.1:34567".parse()?).await});
        let (mut a,_,_,_,_)=handshake(TcpStream::connect(addr).await?,&client.private.try_into().unwrap(),Some(server.public.try_into().unwrap()),&[],&Options::default(),"127.0.0.1:34568".parse()?).await?;
        let (mut b,_,_,_,_)=task.await??;
        let message=Message::Probe([7;16]);let packet=a.encode(&message)?;let mut forged=packet.clone();*forged.last_mut().unwrap()^=1;
        assert!(b.decode(&forged).is_err());assert_eq!(b.decode(&packet)?,message);assert!(b.decode(&packet).is_err());
        let reply=b.encode(&Message::ProbeAck([7;16]))?;assert_eq!(a.decode(&reply)?,Message::ProbeAck([7;16]));Ok(())
    }

    #[tokio::test]
    async fn closed_flow_and_allocation_limits_refuse_stale_authenticated_recreation()->Result<()> {
        let key=crate::tunnel_key::TunnelKey::generate()?.display();
        let directory=tempfile::tempdir()?;let path=directory.path().join("config.json");
        let control=TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"mode":"server","tunnel_key":key,"listeners":[{"addr":"127.0.0.1:25550"}],
            "gaming":{"control_address":control.to_string(),"udp_bind":"127.0.0.1:0","max_flows":1}}))?)?;
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600))?;}
        let config=crate::config::Config::load(&path)?;let hub=Hub::start(&config).await?;
        let(flow,_rx)=hub.register().await?;assert!(hub.register().await.is_err());hub.unregister(flow).await;
        assert!(hub.register().await.is_ok());
        let peer=[9;32];hub.retire((peer,[2;16])).await;
        assert!(hub.tombstones.lock().await.contains_key(&(peer,[2;16])));
        let budget=hub.queued_bytes.clone().try_acquire_many_owned(16*1024*1024)?;
        assert!(hub.queued_bytes.clone().try_acquire_owned().is_err());drop(budget);
        assert_eq!(hub.queued_bytes.available_permits(),16*1024*1024);Ok(())
    }

    /// V05: replayed (never-ready) channels cannot push out a ready channel of the same peer.
    #[tokio::test]
    async fn unproved_channels_never_displace_a_ready_channel()->Result<()> {
        let server=Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let client=Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let listener=TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;
        let allowed=[client.public.clone().try_into().unwrap()];
        let task=tokio::spawn(async move{let mut codecs=Vec::new();for _ in 0..5{let(s,_)=listener.accept().await?;codecs.push(handshake(s,&server.private.clone().try_into().unwrap(),None,&allowed,&Options::default(),"127.0.0.1:34571".parse()?).await?.0);}anyhow::Ok(codecs)});
        let mut clients=Vec::new();
        for _ in 0..5{clients.push(handshake(TcpStream::connect(addr).await?,&client.private.clone().try_into().unwrap(),Some(server.public.clone().try_into().unwrap()),&[],&Options::default(),"127.0.0.1:34572".parse()?).await?);}
        let codecs=task.await??;
        let peer:[u8;32]=client.public.clone().try_into().unwrap();
        let mut generation=0;
        let mut channel=|codec:Codec,ready:bool|{generation+=1;Arc::new(Channel{codec:Mutex::new(codec),address:"127.0.0.1:34572".parse().unwrap(),peer,migrate:false,generation,challenge:[0;16],
            ready:std::sync::atomic::AtomicBool::new(ready),created:Instant::now(),fragments:Mutex::new(HashMap::new())})};
        let mut codecs=codecs.into_iter();
        let mut channels:HashMap<[u8;16],Arc<Channel>>=HashMap::new();
        let ready=channel(codecs.next().unwrap(),true);channels.insert([1;16],ready);
        for (n,codec) in codecs.enumerate() {
            admit_channel(&mut channels,peer);
            channels.insert([10+n as u8;16],channel(codec,false));
            assert!(channels.contains_key(&[1;16]),"replay {n} displaced the ready channel");
            assert_eq!(channels.values().filter(|c|!c.ready.load(std::sync::atomic::Ordering::Acquire)).count(),1,"only the newest unproved channel is kept");
        }
        drop(clients);Ok(())
    }

    /// C13: Close arriving before the flow's first Data still blocks that Data.
    #[tokio::test]
    async fn close_before_first_data_records_a_tombstone_that_refuses_the_late_data()->Result<()> {
        let key=crate::tunnel_key::TunnelKey::generate()?.display();
        let directory=tempfile::tempdir()?;let path=directory.path().join("config.json");
        let control=TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"mode":"server","tunnel_key":key,"listeners":[{"addr":"127.0.0.1:25551"}],
            "gaming":{"control_address":control.to_string(),"udp_bind":"127.0.0.1:0","max_flows":4}}))?)?;
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600))?;}
        let config=crate::config::Config::load(&path)?;let hub=Hub::start(&config).await?;
        let server=Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let client=Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let listener=TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;
        let allowed=[client.public.clone().try_into().unwrap()];
        let task=tokio::spawn(async move{let(s,_)=listener.accept().await?;handshake(s,&server.private.try_into().unwrap(),None,&allowed,&Options::default(),"127.0.0.1:34569".parse()?).await});
        let _client_side=handshake(TcpStream::connect(addr).await?,&client.private.try_into().unwrap(),Some(server.public.try_into().unwrap()),&[],&Options::default(),"127.0.0.1:34570".parse()?).await?;
        let (codec,_,_,_,_)=task.await??;
        let peer:[u8;32]=client.public.try_into().unwrap();
        let channel=Arc::new(Channel{codec:Mutex::new(codec),address:"127.0.0.1:34570".parse()?,peer,migrate:false,generation:1,challenge:[0;16],
            ready:std::sync::atomic::AtomicBool::new(true),created:Instant::now(),fragments:Mutex::new(HashMap::new())});
        let allowed_targets=["127.0.0.1:*".to_string()];
        // Absent flow: Close first, then the earlier Data.
        hub.close_flow(peer,[5;16],1).await;
        assert!(hub.tombstones.lock().await.contains_key(&(peer,[5;16])));
        let error=hub.deliver(channel.clone(),[5;16],1,1,"127.0.0.1:9".into(),vec![1],&allowed_targets,Duration::from_secs(5)).await.unwrap_err();
        assert!(format!("{error:#}").contains("closed gaming flow"),"{error:#}");
        assert!(!hub.flows.lock().await.contains_key(&(peer,[5;16])),"no destination flow may be created");
        // Live flow: a lower-generation Close leaves the newer flow alone; an equal one retires it.
        hub.deliver(channel.clone(),[6;16],3,1,"127.0.0.1:9".into(),vec![1],&allowed_targets,Duration::from_secs(5)).await?;
        hub.close_flow(peer,[6;16],2).await;
        assert!(hub.flows.lock().await.contains_key(&(peer,[6;16])),"stale Close removed a newer flow");
        assert!(!hub.tombstones.lock().await.contains_key(&(peer,[6;16])));
        hub.close_flow(peer,[6;16],3).await;
        assert!(!hub.flows.lock().await.contains_key(&(peer,[6;16])));
        assert!(hub.tombstones.lock().await.contains_key(&(peer,[6;16])));
        Ok(())
    }
}
