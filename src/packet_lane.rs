//! Optional authenticated TCP packet path below KCP/FEC, not a replacement mux.
use anyhow::{Result, Context, ensure};
use serde::{Deserialize, Serialize};
use snow::{Builder, TransportState};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{mpsc, Mutex, Semaphore}, time::timeout};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"eztunnel/open-source/fec-packet-lane/v1";
const MAX_PACKET: usize = 2048;
const QUEUE: usize = 256;
const HANDSHAKE: usize = 256;

#[derive(Clone)]
pub struct Key(Zeroizing<[u8;32]>);
impl Key { pub(crate) fn new(key:Zeroizing<[u8;32]>)->Self { Self(key) } }
impl std::fmt::Debug for Key {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("PacketLaneKey(REDACTED)")} }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    pub address: Option<String>,
    pub idle_ms: u64,
    pub handshake_sec: u64,
}
impl Default for Options {fn default()->Self {Self {address:None,idle_ms:1000,handshake_sec:5}}}
impl Options {
    pub fn validate(&self)->Result<()> {
        ensure!((100..=30_000).contains(&self.idle_ms),"TCP fallback idle_ms must be100..30000");
        ensure!((1..=30).contains(&self.handshake_sec),"TCP fallback handshake_sec must be1..30");
        if let Some(addr)=&self.address {let endpoint:SocketAddr=addr.parse().context("TCP fallback requires explicit IP:port")?; ensure!(endpoint.port()!=0,"TCP fallback port must be nonzero");}
        Ok(())
    }
}

pub struct Lane {
    outbound: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    connected: std::sync::atomic::AtomicBool,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    cancellation:Arc<tokio::sync::Notify>,
    generation:std::sync::atomic::AtomicU64,
}
impl Drop for Lane {fn drop(&mut self){if let Some(task)=self.task.get_mut().unwrap_or_else(|e|e.into_inner()).take(){task.abort();}}}

async fn write_message(stream:&mut TcpStream,bytes:&[u8])->Result<()> {
    ensure!(bytes.len()<=HANDSHAKE,"lane handshake too large");
    stream.write_u16(bytes.len() as u16).await?;stream.write_all(bytes).await?;Ok(())
}
async fn read_message(stream:&mut TcpStream)->Result<Vec<u8>> {
    let size=stream.read_u16().await? as usize;ensure!((1..=HANDSHAKE).contains(&size),"lane handshake length");
    let mut bytes=vec![0;size];stream.read_exact(&mut bytes).await?;Ok(bytes)
}
async fn handshake(mut stream:TcpStream,key:&Key,initiator:bool)->Result<(TcpStream,TransportState)> {
    stream.set_nodelay(true)?;
    let builder=Builder::new("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse()?).psk(0,&key.0)?.prologue(DOMAIN)?;
    let mut state=if initiator {builder.build_initiator()?} else {builder.build_responder()?};
    let mut output=[0;HANDSHAKE];let mut plain=[0;HANDSHAKE];
    if initiator {
        let n=state.write_message(&[],&mut output)?;write_message(&mut stream,&output[..n]).await?;
        let bytes=read_message(&mut stream).await?;ensure!(state.read_message(&bytes,&mut plain)?==0,"unexpected lane payload");
    } else {
        let bytes=read_message(&mut stream).await?;ensure!(state.read_message(&bytes,&mut plain)?==0,"unexpected lane payload");
        let n=state.write_message(&[],&mut output)?;write_message(&mut stream,&output[..n]).await?;
    }
    Ok((stream,state.into_transport_mode()?))
}

/// V09: how long an answering lane may wait for the first record under the fresh session
/// keys. A replayed first flight completes the NNpsk0 handshake but can never send one.
const PROOF: Duration = Duration::from_secs(30);

async fn session(stream:TcpStream, state:TransportState,tx:&mpsc::Sender<Vec<u8>>,rx:&mut mpsc::Receiver<Vec<u8>>,proof:Option<&(dyn Fn() + Sync)>)->Result<()> {
    let proved=std::sync::atomic::AtomicBool::new(proof.is_none());
    let (mut reader,mut writer)=stream.into_split();
    let state=Arc::new(std::sync::Mutex::new(state));
    let receive_state=state.clone();
    let read=async {
        let mut encrypted=[0;MAX_PACKET+16];let mut plain=[0;MAX_PACKET];
        let mut records=0u64;
        loop {
            let n=reader.read_u16().await? as usize;
            ensure!((17..=MAX_PACKET+16).contains(&n),"lane record length");
            reader.read_exact(&mut encrypted[..n]).await?;
            let n={let mut state=receive_state.lock().unwrap_or_else(|e|e.into_inner());let size=state.read_message(&encrypted[..n],&mut plain)?;
                records+=1;if records%(1<<20)==0{state.rekey_incoming();}size};
            ensure!(n>0,"empty packet");
            if !proved.swap(true,std::sync::atomic::Ordering::AcqRel)&&let Some(proof)=proof{proof();}
            tx.send(plain[..n].to_vec()).await.context("lane receiver closed")?;
            crate::transport_metrics::LANE_RX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        }
        #[allow(unreachable_code)] Ok::<(),anyhow::Error>(())
    };
    let write=async {
        let mut encrypted=[0;MAX_PACKET+16];
        let mut records=0u64;
        while let Some(packet)=rx.recv().await {
            ensure!((1..=MAX_PACKET).contains(&packet.len()),"lane packet length");
            let n={let mut state=state.lock().unwrap_or_else(|e|e.into_inner());let size=state.write_message(&packet,&mut encrypted)?;
                records+=1;if records%(1<<20)==0{state.rekey_outgoing();}size};
            writer.write_u16(n as u16).await?;writer.write_all(&encrypted[..n]).await?;
            crate::transport_metrics::LANE_TX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        }
        Ok::<(),anyhow::Error>(())
    };
    // If any partial read/write is canceled, discard the entire lane and Noise state.
    let unproved=async {
        tokio::time::sleep(PROOF).await;
        if proved.load(std::sync::atomic::Ordering::Acquire) {std::future::pending::<()>().await;}
    };
    tokio::select!{result=read=>result,result=write=>result,_=unproved=>anyhow::bail!("lane peer sent nothing under the fresh session keys"),_=tokio::time::sleep(Duration::from_secs(300))=>Ok(())}
}

impl Lane {
    pub async fn open(options:&Options,key:Key,server:bool)->Result<Arc<Self>> {
        let address:SocketAddr=options.address.as_ref().context("missing lane address")?.parse()?;
        let listener=if server {Some(TcpListener::bind(address).await.context("bind isolated TCP fallback listener")?)} else {None};
        let (outbound,mut packets)=mpsc::channel(QUEUE);let (tx,incoming)=mpsc::channel(QUEUE);
        let lane=Arc::new(Self{outbound,incoming:Mutex::new(incoming),connected:false.into(),task:std::sync::Mutex::new(None),cancellation:Arc::new(tokio::sync::Notify::new()),generation:0.into()});
        let weak=Arc::downgrade(&lane);let options=options.clone();
        let task=tokio::spawn(async move {
            let admission=Semaphore::new(1);
            loop {
                let stream=if let Some(listener)=&listener {listener.accept().await.map(|(s,_)|s)} else {TcpStream::connect(address).await};
                let Ok(stream)=stream else {tokio::time::sleep(Duration::from_secs(1)).await;continue;};
                let _permit=admission.acquire().await.expect("lane admission open");
                let result=timeout(Duration::from_secs(options.handshake_sec),handshake(stream,&key,!server)).await;
                match result {
                    Ok(Ok((stream,state)))=>{
                        crate::transport_metrics::LANE_SESSIONS.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
                        let Some(lane)=weak.upgrade() else {break;};
                        lane.generation.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
                        // V09: the dialing side knows the answer is fresh (its own ephemeral key);
                        // the answering side publishes the lane only after the first authenticated
                        // record, so local packets are never sent into a replayed first flight.
                        if !server {lane.connected.store(true,std::sync::atomic::Ordering::Release);}
                        drop(lane);
                        let Some(lane)=weak.upgrade()else{break;};let cancellation=lane.cancellation.clone();drop(lane);
                        let publish=weak.clone();
                        let mark=move||{if let Some(lane)=publish.upgrade(){lane.connected.store(true,std::sync::atomic::Ordering::Release);}};
                        let proof:Option<&(dyn Fn()+Sync)>=if server {Some(&mark)} else {None};
                        let result=tokio::select!{result=session(stream,state,&tx,&mut packets,proof)=>result,_=cancellation.notified()=>Ok(())};
                        if let Some(lane)=weak.upgrade(){lane.connected.store(false,std::sync::atomic::Ordering::Release);}
                        if let Err(error)=result {tracing::debug!(%error,"packet lane reconnecting");}
                    }
                    _=>{tracing::debug!("packet lane handshake rejected or timed out");tokio::time::sleep(Duration::from_millis(100)).await;},
                }
                // Discard stale queued packets; KCP safely retransmits unacknowledged data.
                while packets.try_recv().is_ok(){}
                tokio::time::sleep(Duration::from_millis(250)).await;
                if weak.strong_count()==0 {break;}
            }
        });
        *lane.task.lock().unwrap_or_else(|e|e.into_inner())=Some(task);
        Ok(lane)
    }
    pub fn connected(&self)->bool {self.connected.load(std::sync::atomic::Ordering::Acquire)}
    pub async fn send(&self,bytes:&[u8])->std::io::Result<usize> {
        if !(1..=MAX_PACKET).contains(&bytes.len()){return Err(std::io::ErrorKind::InvalidInput.into());}
        self.outbound.send(bytes.to_vec()).await.map_err(|_|std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(bytes.len())
    }
    pub async fn recv(&self)->std::io::Result<Vec<u8>> {self.incoming.lock().await.recv().await.ok_or_else(||std::io::ErrorKind::UnexpectedEof.into())}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn lane_authenticates_packet_boundaries_and_rejects_wrong_key()->Result<()> {
        let listener=TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;
        let key=Key::new(Zeroizing::new([23;32]));let server_key=key.clone();
        let server=tokio::spawn(async move {
            let (s,_)=listener.accept().await?;let (s,state)=handshake(s,&server_key,false).await?;
            let (tx,mut rx)=mpsc::channel(4);let (out,incoming)=mpsc::channel(4);let mut incoming=incoming;
            let work=tokio::spawn(async move {session(s,state,&out,&mut rx,None).await});
            for n in [1,512,2048] {let p=incoming.recv().await.context("packet")?;ensure!(p==vec![42;n],"packet mismatch");tx.send(p).await?;}
            tokio::time::sleep(Duration::from_millis(20)).await;work.abort();Ok::<_,anyhow::Error>(())
        });
        let (s,state)=handshake(TcpStream::connect(addr).await?,&key,true).await?;
        let (tx,mut rx)=mpsc::channel(4);let (out,mut incoming)=mpsc::channel(4);
        let work=tokio::spawn(async move {session(s,state,&out,&mut rx,None).await});
        for n in [1,512,2048] {tx.send(vec![42;n]).await?;ensure!(timeout(Duration::from_secs(2),incoming.recv()).await?.context("echo")?==vec![42;n],"echo mismatch");}
        work.abort();server.await??;
        let listener=TcpListener::bind(addr).await?;let server=tokio::spawn(async move {let(s,_)=listener.accept().await?;handshake(s,&Key::new(Zeroizing::new([1;32])),false).await});
        assert!(timeout(Duration::from_secs(2),handshake(TcpStream::connect(addr).await?,&key,true)).await?.is_err());
        assert!(server.await?.is_err());Ok(())
    }
    #[tokio::test]
    async fn lane_reconnects_after_owned_transport_cut_with_queues_bounded()->Result<()> {
        let addr=TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let options=Options{address:Some(addr.to_string()),..Options::default()};let key=Key::new(Zeroizing::new([62;32]));
        let server=Lane::open(&options,key.clone(),true).await?;let client=Lane::open(&options,key,false).await?;
        for _ in 0..100 {if client.connected(){break;}tokio::time::sleep(Duration::from_millis(20)).await;}
        ensure!(client.connected(),"lane never connected");
        ensure!(!server.connected(),"the answering side waits for a record under the fresh keys");
        client.send(b"before").await?;ensure!(timeout(Duration::from_secs(2),server.recv()).await??==b"before","before packet");
        ensure!(server.connected(),"the first authenticated record publishes the answering side");
        let generation=client.generation.load(std::sync::atomic::Ordering::Relaxed);
        client.cancellation.notify_one();
        for _ in 0..150 {if client.generation.load(std::sync::atomic::Ordering::Relaxed)>generation&&client.connected(){break;}tokio::time::sleep(Duration::from_millis(20)).await;}
        ensure!(client.generation.load(std::sync::atomic::Ordering::Relaxed)>generation,"lane did not reauthenticate");
        client.send(b"after").await?;ensure!(timeout(Duration::from_secs(2),server.recv()).await??==b"after","after packet");
        assert!(client.send(&vec![0;MAX_PACKET+1]).await.is_err());Ok(())
    }

    /// V09: a recorded first flight replayed on a new connection gets a handshake answer but
    /// can send nothing under the fresh keys, so the answering lane is never published to the
    /// packet path while it holds the accept loop.
    #[tokio::test]
    async fn a_replayed_first_flight_is_not_published_as_a_connected_lane()->Result<()> {
        let addr=TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let options=Options{address:Some(addr.to_string()),..Options::default()};let key=Key::new(Zeroizing::new([71;32]));
        // Record one genuine first flight; the replay actor keeps only these bytes.
        let builder=Builder::new("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse()?).psk(0,&key.0)?.prologue(DOMAIN)?;
        let mut initiator=builder.build_initiator()?;let mut first=[0;HANDSHAKE];let n=initiator.write_message(&[],&mut first)?;
        let recorded=first[..n].to_vec();drop(initiator);
        let server=Lane::open(&options,key,true).await?;
        let mut replay=None;
        for _ in 0..50 {if let Ok(stream)=TcpStream::connect(addr).await {replay=Some(stream);break;} tokio::time::sleep(Duration::from_millis(20)).await;}
        let mut replay=replay.context("connect to lane")?;
        write_message(&mut replay,&recorded).await?;
        let answer=timeout(Duration::from_secs(2),read_message(&mut replay)).await??;
        ensure!(!answer.is_empty(),"the responder answers the replayed flight");
        tokio::time::sleep(Duration::from_millis(500)).await;
        ensure!(!server.connected(),"a replayed first flight must not publish the lane");
        drop(replay);Ok(())
    }
}
