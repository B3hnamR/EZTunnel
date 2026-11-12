//! Explicit Mirage v2 policy. Network addresses are not peer credentials.
use crate::raw_packet::{RawOptions, RawProfile};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use hmac::{Hmac,Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AdmissionKey(Zeroizing<[u8;32]>);
impl AdmissionKey{pub(crate) fn new(bytes:Zeroizing<[u8;32]>)->Self{Self(bytes)}}
impl std::fmt::Debug for AdmissionKey{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("MirageAdmissionKey(REDACTED)")}}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MirageOptions {
    pub uplink: Option<RawProfile>,
    pub downlink: Option<RawProfile>,
    pub allow_real_source: bool,
    pub source_pool: Vec<Ipv4Addr>,
    /// Empty means the configured real peer, not every source.
    pub expected_sources: Vec<Ipv4Addr>,
    #[serde(skip)]
    pub admission_key:Option<AdmissionKey>,
    pub echo_mode:EchoMode,
    pub ttl:Option<u8>,
    pub dscp:Option<u8>,
    pub padding_max:u16,
    pub fake_tls:bool,
    pub source_port_range:Option<[u16;2]>,
    pub redundancy:Option<Redundancy>,
}
#[derive(Debug,Clone,Copy,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redundancy{pub data:u8,pub parity:u8}
#[derive(Debug,Clone,Copy,Default,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
pub enum EchoMode {#[default]Split,Requests,Replies}

pub const ENVELOPE_OVERHEAD:usize=62;
pub struct Envelope {
    key:AdmissionKey,tx:RawProfile,rx:RawProfile,boot:[u8;16],counter:u64,
    peers:std::collections::HashMap<[u8;16],(crate::gaming::Replay,tokio::time::Instant)>,
    contract:u64,
}
fn profile_id(profile:RawProfile)->u8 {match profile{RawProfile::Tcp=>1,RawProfile::Udp=>2,RawProfile::Icmp=>3,RawProfile::Gre=>4,RawProfile::Ipip=>5,RawProfile::Bip=>6,RawProfile::Icmpv6=>7,RawProfile::Raw=>8,RawProfile::Dns=>9}}
fn timestamp()->Result<u64>{Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())}
fn signature(key:&AdmissionKey,bytes:&[u8])->Hmac<Sha256>{let mut mac=Hmac::<Sha256>::new_from_slice(&*key.0).expect("32-byte key");mac.update(b"eztunnel/mirage/v2/admission\0");mac.update(bytes);mac}
impl Envelope {
    pub fn new(key:AdmissionKey,tx:RawProfile,rx:RawProfile)->Result<Self>{
        let mut boot=[0;16];rustls::crypto::ring::default_provider().secure_random.fill(&mut boot).map_err(|_|anyhow::anyhow!("Mirage randomness unavailable"))?;
        Ok(Self{key,tx,rx,boot,counter:0,peers:Default::default(),contract:0})
    }
    pub fn with_options(mut self,options:&MirageOptions)->Result<Self>{
        let bytes=serde_json::to_vec(&(options.padding_max,options.fake_tls,options.redundancy.map(|fec|(fec.data,fec.parity)),options.source_port_range,match options.echo_mode{EchoMode::Split=>0,EchoMode::Requests=>1,EchoMode::Replies=>2}))?;
        self.contract=u64::from_be_bytes(blake3::hash(&bytes).as_bytes()[..8].try_into().unwrap());Ok(self)
    }
    pub fn encode(&mut self,payload:&[u8])->Result<Vec<u8>> {
        ensure!(self.counter<u64::MAX,"Mirage packet counter exhausted");
        let mut bytes=Vec::with_capacity(payload.len()+ENVELOPE_OVERHEAD);
        bytes.extend_from_slice(b"EZM2");bytes.extend_from_slice(&[profile_id(self.tx),profile_id(self.rx)]);
        bytes.extend_from_slice(&self.boot);bytes.extend_from_slice(&self.counter.to_be_bytes());bytes.extend_from_slice(&timestamp()?.to_be_bytes());bytes.extend_from_slice(&self.contract.to_be_bytes());bytes.extend_from_slice(payload);
        let tag=signature(&self.key,&bytes).finalize().into_bytes();bytes.extend_from_slice(&tag[..16]);self.counter+=1;Ok(bytes)
    }
    pub fn decode<'a>(&mut self,bytes:&'a[u8])->Result<&'a[u8]>{
        ensure!(bytes.len()>=ENVELOPE_OVERHEAD&&&bytes[..4]==b"EZM2","not a Mirage v2 packet");
        let end=bytes.len()-16;
        signature(&self.key,&bytes[..end]).verify_truncated_left(&bytes[end..]).map_err(|_|anyhow::anyhow!("Mirage admission authentication failed"))?;
        ensure!(bytes[4]==profile_id(self.rx)&&bytes[5]==profile_id(self.tx),"authenticated Mirage profile mismatch: peer directions do not match local uplink/downlink");
        ensure!(bytes[38..46]==self.contract.to_be_bytes(),"authenticated Mirage option contract mismatch (echo/shaping/port-range/redundancy)");
        ensure!(timestamp()?.abs_diff(u64::from_be_bytes(bytes[30..38].try_into().unwrap()))<=30,"Mirage packet time outside the 30-second window");
        self.peers.retain(|_,(_,seen)|seen.elapsed()<std::time::Duration::from_secs(61));
        let boot=bytes[6..22].try_into().unwrap();
        ensure!(self.peers.contains_key(&boot)||self.peers.len()<64,"Mirage replay boot table full");
        let(replay,seen)=self.peers.entry(boot).or_insert_with(||(crate::gaming::Replay::default(),tokio::time::Instant::now()));
        ensure!(replay.commit(u64::from_be_bytes(bytes[22..30].try_into().unwrap())),"replayed Mirage packet");*seen=tokio::time::Instant::now();Ok(&bytes[46..end])
    }
}
impl MirageOptions {
    pub fn profiles(&self, fallback:RawProfile,server:bool)->(RawProfile,RawProfile) {
        let up=self.uplink.unwrap_or(fallback);let down=self.downlink.unwrap_or(fallback);
        if server {(down,up)}else{(up,down)}
    }
    pub fn validate(&self,raw:&RawOptions)->Result<()> {
        ensure!(raw.mirage_acknowledgement.as_deref()==Some("experimental-v2"),"Mirage v2 requires experimental-v2 acknowledgement");
        ensure!(raw.spoof_dst_ip.is_none(),"Mirage v2 routes to real peer_ip; spoof_dst_ip is a legacy destination override, not receive-source admission");
        ensure!(!raw.proto58_mode,"use explicit bip or icmpv6 profile, not legacy proto58_mode, with Mirage v2");
        ensure!(self.source_pool.len()<=64&&self.expected_sources.len()<=64,"Mirage address sets are limited to64 entries");
        ensure!(self.source_pool.is_empty()||raw.spoof_src_ip.is_none(),"choose source_pool or spoof_src_ip, not both");
        ensure!(self.ttl.is_none_or(|ttl|ttl>0),"Mirage TTL must be1..255");
        ensure!(self.dscp.is_none_or(|dscp|dscp<=63),"Mirage DSCP must be0..63");
        ensure!(self.padding_max<=256,"Mirage padding_max must be0..256");
        if let Some(fec)=self.redundancy{crate::spoof_fec::Encoder::new(fec.data,fec.parity)?;}
        if let Some([first,last])=self.source_port_range{ensure!(first>=1024&&last>=first&&u32::from(last)-u32::from(first)<256,"Mirage source_port_range must contain 1..256 nonprivileged ports");ensure!(!raw.hopping.enabled,"source shuffle and adaptive hopping have different ownership");}
        ensure!(self.allow_real_source||raw.spoof_src_ip.is_some()||!self.source_pool.is_empty(),"Mirage requires explicit source or allow_real_source acknowledgement");
        for ip in self.source_pool.iter().chain(self.expected_sources.iter()) {
            ensure!(!ip.is_unspecified()&&!ip.is_multicast()&&!ip.is_broadcast()&&!ip.is_loopback(),"Mirage address sets require non-loopback unicast IPv4");
        }
        let profiles=self.profiles(raw.profile,false);
        ensure!([profiles.0,profiles.1].iter().all(|p|matches!(p,RawProfile::Tcp|RawProfile::Udp|RawProfile::Icmp|RawProfile::Icmpv6|RawProfile::Gre|RawProfile::Ipip|RawProfile::Bip)),"Mirage v2 supports tcp,udp,icmp,icmpv6,gre,ipip,bip");
        ensure!(!raw.hopping.enabled,"Mirage v2 source/admission ownership is separate from legacy adaptive port hopping; disable raw.hopping");
        Ok(())
    }
}
/// Cosmetic shaping is covered by outer admission authentication, not actualTLS.
pub fn shape(payload:&[u8],options:&MirageOptions)->Result<Vec<u8>> {
    let pad=if options.padding_max>0 {u16::from_be_bytes(random::<2>()?)%(options.padding_max+1)}else{0};
    let mut bytes=Vec::with_capacity(payload.len()+usize::from(pad)+7);
    if options.fake_tls {bytes.extend_from_slice(&[0x17,0x03,0x03]);bytes.extend_from_slice(&((payload.len()+usize::from(pad)+if options.padding_max>0{2}else{0})as u16).to_be_bytes());}
    if options.padding_max>0 {bytes.extend_from_slice(&pad.to_be_bytes());}
    bytes.extend_from_slice(payload);let start=bytes.len();bytes.resize(start+usize::from(pad),0);
    if pad>0 {rustls::crypto::ring::default_provider().secure_random.fill(&mut bytes[start..]).map_err(|_|anyhow::anyhow!("Mirage padding randomness"))?;}
    Ok(bytes)
}
pub fn unshape<'a>(bytes:&'a[u8],options:&MirageOptions)->Result<&'a[u8]>{
    let mut bytes=bytes;
    if options.fake_tls {ensure!(bytes.len()>=5&&bytes[..3]==[0x17,0x03,0x03]&&usize::from(u16::from_be_bytes(bytes[3..5].try_into().unwrap()))==bytes.len()-5,"Mirage fake TLS record mismatch");bytes=&bytes[5..];}
    if options.padding_max>0 {ensure!(bytes.len()>=2,"short Mirage padding header");let pad=usize::from(u16::from_be_bytes(bytes[..2].try_into().unwrap()));ensure!(pad<=usize::from(options.padding_max)&&bytes.len()>=2+pad,"invalid Mirage padding length");bytes=&bytes[2..bytes.len()-pad];}
    Ok(bytes)
}
fn random<const N:usize>()->Result<[u8;N]>{let mut bytes=[0;N];rustls::crypto::ring::default_provider().secure_random.fill(&mut bytes).map_err(|_|anyhow::anyhow!("Mirage randomness unavailable"))?;Ok(bytes)}
pub fn shuffled_port(range:[u16;2])->Result<u16>{let value=u32::from_be_bytes(random::<4>()?);Ok(range[0]+(value%(u32::from(range[1])-u32::from(range[0])+1))as u16)}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directions_and_legacy_destination_are_unambiguous(){
        let mut raw=RawOptions{peer_ip:"192.0.2.2".parse().unwrap(),mirage_acknowledgement:Some("experimental-v2".into()),..RawOptions::default()};
        let spec=MirageOptions{uplink:Some(RawProfile::Icmp),downlink:Some(RawProfile::Udp),allow_real_source:true,..MirageOptions::default()};
        assert_eq!(spec.profiles(RawProfile::Tcp,true),(RawProfile::Udp,RawProfile::Icmp));
        assert_eq!(spec.profiles(RawProfile::Tcp,false),(RawProfile::Icmp,RawProfile::Udp));
        assert!(spec.validate(&raw).is_ok());raw.spoof_dst_ip=Some(raw.peer_ip);assert!(spec.validate(&raw).is_err());
    }
    #[test]
    fn profile_contract_is_authenticated_and_forgery_does_not_poison_replay()->Result<()> {
        let key=AdmissionKey::new(Zeroizing::new([19;32]));
        let mut a=Envelope::new(key.clone(),RawProfile::Icmp,RawProfile::Udp)?;
        let mut b=Envelope::new(key.clone(),RawProfile::Udp,RawProfile::Icmp)?;
        let packet=a.encode(b"data")?;assert_eq!(packet.len(),4+ENVELOPE_OVERHEAD);
        let mut forged=packet.clone();forged[22..30].copy_from_slice(&u64::MAX.to_be_bytes());assert!(b.decode(&forged).is_err());
        assert_eq!(b.decode(&packet)?,b"data");assert!(b.decode(&packet).is_err());
        let mut mismatch=Envelope::new(key,RawProfile::Tcp,RawProfile::Icmp)?;
        let error=mismatch.decode(&a.encode(b"x")?).unwrap_err().to_string();assert!(error.contains("profile mismatch"));Ok(())
    }
    #[test]
    fn shaping_is_bounded_and_roundtrips_all_padding_and_fake_tls_combinations()->Result<()> {
        for padding in [0,1,64,256] {for tls in [false,true] {
            let spec=MirageOptions{padding_max:padding,fake_tls:tls,..MirageOptions::default()};
            for size in [0,1,1200] {let payload=vec![19;size];for _ in 0..16 {let bytes=shape(&payload,&spec)?;assert_eq!(unshape(&bytes,&spec)?,payload);assert!(bytes.len()<=size+usize::from(padding)+if padding>0{2}else{0}+if tls{5}else{0});}}
        }}
        let spec=MirageOptions{padding_max:64,fake_tls:true,..MirageOptions::default()};assert!(unshape(&[0;16],&spec).is_err());Ok(())
    }
}
