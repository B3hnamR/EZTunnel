//! Authenticated adaptive port selection. Packet contents retain inner Noise security.
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::HashMap, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub const OVERHEAD:usize=56;
const DOMAIN:&[u8]=b"eztunnel/raw-port-hop/v1\0";

#[derive(Clone)]
pub struct Key(Zeroizing<[u8;32]>);
impl Key {pub(crate) fn new(bytes:Zeroizing<[u8;32]>)->Self{Self(bytes)}}
impl std::fmt::Debug for Key {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("PortHopKey(REDACTED)")}}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default,deny_unknown_fields)]
pub struct Options {
    pub enabled:bool,
    pub first_port:u16,
    pub last_port:u16,
    pub retry_ms:u64,
    #[serde(skip)]
    pub key:Option<Key>,
}
impl Default for Options {fn default()->Self {Self{enabled:false,first_port:40000,last_port:40063,retry_ms:1500,key:None}}}
impl Options {
    pub fn validate(&self)->Result<()> {
        ensure!(self.first_port>=1024 && self.last_port>=self.first_port && u32::from(self.last_port)-u32::from(self.first_port)<256,"raw hopping range must contain 1..256 nonprivileged ports");
        ensure!((250..=30_000).contains(&self.retry_ms),"raw hopping retry_ms must be250..30000");
        Ok(())
    }
    pub fn permits(&self,port:u16,base:u16)->bool {port==base || (self.first_port..=self.last_port).contains(&port)}
}

#[derive(Default)]
struct Replay {high:u64,bits:[u64;16],initialized:bool}
impl Replay {
    fn seen(&self,value:u64)->bool {
        if !self.initialized || value>self.high {return false;}
        let distance=self.high-value;
        distance>=1024 || self.bits[distance as usize/64] & (1u64<<(distance%64))!=0
    }
    fn accept(&mut self,value:u64)->bool {
        if self.seen(value){return false;}
        if !self.initialized {self.initialized=true;self.high=value;}
        if value>self.high {
            let shift=(value-self.high).min(1024) as usize;
            let mut next=[0;16];
            for bit in 0..1024-shift {if self.bits[bit/64] & (1u64<<(bit%64))!=0 {let n=bit+shift;next[n/64]|=1u64<<(n%64);}}
            self.bits=next;self.high=value;
        }
        let distance=(self.high-value) as usize;self.bits[distance/64]|=1u64<<(distance%64);true
    }
}

pub struct State {
    options:Options,
    boot:[u8;16],counter:u64,
    base:(u16,u16),selected:(u16,u16),
    last_good:Instant,last_attempt:Instant,attempt:u64,
    peers:HashMap<[u8;16],(Replay,Instant)>,
}
fn wall()->Result<u64>{Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())}
fn mac(key:&Key,bytes:&[u8])->Hmac<Sha256>{let mut mac=Hmac::<Sha256>::new_from_slice(&*key.0).expect("32-byte HMAC key");mac.update(DOMAIN);mac.update(bytes);mac}

impl State {
    pub fn new(options:Options,source:u16,destination:u16)->Result<Self> {
        options.validate()?;ensure!(options.key.is_some(),"raw port hopping requires tunnel_key");
        let mut boot=[0;16];rustls::crypto::ring::default_provider().secure_random.fill(&mut boot).map_err(|_|anyhow::anyhow!("port hopping randomness unavailable"))?;
        Ok(Self{options,boot,counter:0,base:(source,destination),selected:(source,destination),
            last_good:Instant::now(),last_attempt:Instant::now(),attempt:0,peers:HashMap::new()})
    }
    pub fn selected(&mut self)->(u16,u16) {
        let due=Duration::from_millis(self.options.retry_ms);
        if self.last_good.elapsed()>=due && self.last_attempt.elapsed()>=due {
            self.attempt=self.attempt.saturating_add(1);self.last_attempt=Instant::now();
            let mut input=self.boot.to_vec();input.extend_from_slice(&self.attempt.to_be_bytes());
            let bytes=mac(self.options.key.as_ref().expect("validated key"),&input).finalize().into_bytes();
            let count=u32::from(self.options.last_port)-u32::from(self.options.first_port)+1;
            let source=self.options.first_port+(u32::from_be_bytes(bytes[..4].try_into().unwrap())%count) as u16;
            // Periodic base-port probes permit a peer without successful hop state to rejoin.
            let destination=if self.attempt%4==0 {self.base.1} else {self.options.first_port+(u32::from_be_bytes(bytes[4..8].try_into().unwrap())%count) as u16};
            self.selected=(source,destination);
            crate::transport_metrics::HOP_CHANGES.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        }
        self.selected
    }
    pub fn wrap(&mut self,payload:&[u8])->Result<Vec<u8>> {
        ensure!(self.counter<u64::MAX,"port hopping nonce exhausted");
        let pair=self.selected();
        let mut bytes=Vec::with_capacity(payload.len()+OVERHEAD);
        bytes.extend_from_slice(b"EZH1");bytes.extend_from_slice(&self.boot);
        bytes.extend_from_slice(&self.counter.to_be_bytes());bytes.extend_from_slice(&wall()?.to_be_bytes());
        bytes.extend_from_slice(&pair.0.to_be_bytes());bytes.extend_from_slice(&pair.1.to_be_bytes());
        bytes.extend_from_slice(payload);
        let tag=mac(self.options.key.as_ref().unwrap(),&bytes).finalize().into_bytes();
        bytes.extend_from_slice(&tag[..16]);self.counter+=1;Ok(bytes)
    }
    pub fn unwrap<'a>(&mut self,bytes:&'a[u8],source:u16,destination:u16)->Result<&'a[u8]> {
        ensure!(bytes.len()>=OVERHEAD && &bytes[..4]==b"EZH1","invalid hopping envelope");
        ensure!(self.options.permits(source,self.base.1) && self.options.permits(destination,self.base.0),"hopping ports outside configured admission range");
        ensure!(u16::from_be_bytes(bytes[36..38].try_into().unwrap())==source && u16::from_be_bytes(bytes[38..40].try_into().unwrap())==destination,"hopping header/port mismatch");
        let timestamp=u64::from_be_bytes(bytes[28..36].try_into().unwrap());
        ensure!(wall()?.abs_diff(timestamp)<=30,"hopping packet outside time window");
        let end=bytes.len()-16;
        // verify_truncated_left performs a constant-time tag comparison.
        mac(self.options.key.as_ref().unwrap(),&bytes[..end]).verify_truncated_left(&bytes[end..]).context("hopping packet authentication failed")?;
        self.peers.retain(|_,(_,seen)|seen.elapsed()<Duration::from_secs(61));
        let boot=bytes[4..20].try_into().unwrap();
        ensure!(self.peers.contains_key(&boot)||self.peers.len()<64,"hopping peer replay table full");
        let (replay,seen)=self.peers.entry(boot).or_insert_with(||(Replay::default(),Instant::now()));
        ensure!(replay.accept(u64::from_be_bytes(bytes[20..28].try_into().unwrap())),"replayed hopping packet");
        *seen=Instant::now();self.selected=(destination,source);self.last_good=Instant::now();
        crate::transport_metrics::HOP_RX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        Ok(&bytes[40..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair()->Result<(State,State)> {let options=Options{enabled:true,key:Some(Key::new(Zeroizing::new([11;32]))),..Options::default()};Ok((State::new(options.clone(),24444,24443)?,State::new(options,24443,24444)?))}
    #[tokio::test(start_paused=true)]
    async fn stalled_path_changes_ports_and_only_authenticated_reply_updates_selection()->Result<()> {
        let(mut a,mut b)=pair()?;
        tokio::time::advance(Duration::from_secs(2)).await;
        let packet=a.wrap(b"data")?;let ports=a.selected();assert_ne!(ports,(24444,24443));
        assert_eq!(b.unwrap(&packet,ports.0,ports.1)?,b"data");assert_eq!(b.selected(),(ports.1,ports.0));
        assert!(b.unwrap(&packet,ports.0,ports.1).is_err());
        let mut forged=a.wrap(b"x")?;forged[40]^=1;
        assert!(b.unwrap(&forged,ports.0,ports.1).is_err());
        let reply=b.wrap(b"reply")?;assert_eq!(a.unwrap(&reply,ports.1,ports.0)?,b"reply");Ok(())
    }
    #[test]
    fn replay_window_reordering_and_large_counter_advances_are_bounded(){
        let mut r=Replay::default();assert!(r.accept(5));assert!(r.accept(3));assert!(!r.accept(3));assert!(r.accept(2048));assert!(!r.accept(5));assert!(r.accept(2047));
    }
}
