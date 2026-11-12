//! Guided Mirage test sessions. The invitation is a short-lived bearer secret.
//! Ordinary tunnel and manual tester protocols are unchanged.
use anyhow::{Context, Result, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::{net::{Ipv4Addr, SocketAddr}, path::{Path, PathBuf}, time::Duration};
use tokio::{net::TcpListener, time::{Instant, timeout}};
use crate::{config::Mode, raw_packet::{RawOptions, RawProfile}, spoof_test::{Row, Settings}, transport::{SecureReader, SecureWriter}, tunnel_key::TunnelKey, wire::Frame};

const DOMAIN:&[u8]=b"eztunnel/mirage/guided-test/v1";
const PREFIX:&str="ezm-test1-";
const CONTROL:u32=u32::MAX-1;
pub const MAX_AGE:u64=600;

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub enum Depth {Quick,Extended}
impl Depth {
    pub fn attempts(self)->u16{match self{Self::Quick=>5,Self::Extended=>20}}
    pub fn label(self)->&'static str{match self{Self::Quick=>"Quick reachability sample (5 probes)",Self::Extended=>"Extended reachability sample (20 probes)"}}
}

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version:u8,pub session:String,pub key:String,pub created_at:u64,pub expires_at:u64,
    pub iran:Ipv4Addr,pub foreign:Ipv4Addr,pub control_port:u16,pub raw_port:u16,
    pub foreign_sources:Vec<Ipv4Addr>,pub iran_sources:Vec<Ipv4Addr>,
    pub profiles:Vec<RawProfile>,pub depth:Depth,
}
impl std::fmt::Debug for Invitation {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.debug_struct("Invitation").field("session",&self.session).field("key",&"REDACTED").field("expires_at",&self.expires_at).finish()}
}
pub fn now()->Result<u64>{Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())}
fn unicast(ip:Ipv4Addr)->bool{!ip.is_unspecified()&&!ip.is_loopback()&&!ip.is_multicast()&&!ip.is_broadcast()}
pub fn parse_sources(text:&str)->Result<Vec<Ipv4Addr>> {
    ensure!(text.len()<=8192,"source list too long");
    let mut ips=Vec::new();
    for text in text.split(|c:char|c==','||c==';'||c.is_whitespace()).filter(|v|!v.is_empty()) {
        let ip:Ipv4Addr=text.parse().context("enter explicit IPv4 addresses separated by commas or spaces, not CIDR ranges")?;
        ensure!(unicast(ip),"source IPs must be unicast IPv4, not loopback/multicast/unspecified");
        if !ips.contains(&ip){ips.push(ip);}
        ensure!(ips.len()<=64,"at most 64 unique source IPs per direction");
    }
    ensure!(!ips.is_empty(),"enter at least one source IPv4");Ok(ips)
}
impl Invitation {
    pub fn new(iran:Ipv4Addr,foreign:Ipv4Addr,foreign_sources:Vec<Ipv4Addr>,iran_sources:Vec<Ipv4Addr>,profiles:Vec<RawProfile>,depth:Depth,control_port:u16,raw_port:u16)->Result<Self>{
        let created_at=now()?;
        let key=TunnelKey::generate()?.display();
        let mut identifier=[0;12];rustls::crypto::ring::default_provider().secure_random.fill(&mut identifier).map_err(|_|anyhow::anyhow!("test session randomness"))?;
        let session=hex::encode(identifier);
        let invitation=Self{version:1,session,key,created_at,expires_at:created_at+MAX_AGE,iran,foreign,foreign_sources,iran_sources,profiles,depth,control_port,raw_port};
        invitation.validate(created_at)?;Ok(invitation)
    }
    pub fn validate(&self,time:u64)->Result<()> {
        ensure!(self.version==1,"this Mirage invitation needs a compatible EZTunnel version");
        ensure!(self.session.len()==24&&self.session.bytes().all(|b|b.is_ascii_hexdigit()),"invalid test session identifier");
        TunnelKey::parse(&self.key).context("invitation contains an invalid temporary key")?;
        ensure!(self.created_at<=time.saturating_add(30)&&self.expires_at>time&&self.expires_at.checked_sub(self.created_at)==Some(MAX_AGE),"test invitation expired or its clock window is invalid; start a new test");
        ensure!(unicast(self.iran)&&unicast(self.foreign)&&self.iran!=self.foreign,"test must name two different real unicast IPv4 addresses");
        ensure!(self.control_port>=1024&&self.raw_port>=1024&&self.raw_port<u16::MAX&&self.control_port!=self.raw_port&&self.control_port!=self.raw_port+1,"invalid or overlapping test ports");
        ensure!(!self.foreign_sources.is_empty()&&self.foreign_sources.len()<=64&&self.iran_sources.len()<=64,"invalid per-direction candidate limit");
        for sources in [&self.foreign_sources,&self.iran_sources]{let mut seen=std::collections::HashSet::new();for ip in sources{ensure!(unicast(*ip)&&seen.insert(*ip),"invalid or repeated invitation source IP");}}
        ensure!(!self.profiles.is_empty()&&self.profiles.len()<=7,"choose 1..7 profiles");
        let mut seen=std::collections::HashSet::new();
        for profile in &self.profiles{ensure!(matches!(profile,RawProfile::Tcp|RawProfile::Udp|RawProfile::Icmp|RawProfile::Icmpv6|RawProfile::Gre|RawProfile::Ipip|RawProfile::Bip)&&seen.insert(format!("{profile:?}")),"invalid or repeated test profile");}
        // Both phases together fit the bounded overall run deadline even at
        // maximum candidates/profiles/extended sample size.
        Ok(())
    }
    pub fn encode(&self)->Result<String>{
        self.validate(now()?)?;let mut bytes=serde_json::to_vec(self)?;
        let checksum=blake3::hash(&bytes);bytes.extend_from_slice(&checksum.as_bytes()[..8]);
        Ok(format!("{PREFIX}{}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)))
    }
    pub fn decode(text:&str,time:u64)->Result<Self>{
        ensure!(text.len()<=32768,"test invitation is too long");
        let text=text.chars().filter(|c|!c.is_whitespace()).collect::<String>();
        let body=text.strip_prefix(PREFIX).context("this is not a Mirage test invitation (ezm-test1-)")?;
        let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).context("damaged test invitation; copy the whole code again")?;
        ensure!(bytes.len()>8&&bytes.len()<=16384,"invalid test invitation length");
        let(payload,check)=bytes.split_at(bytes.len()-8);ensure!(&blake3::hash(payload).as_bytes()[..8]==check,"damaged test invitation; copy it again");
        let invitation:Self=serde_json::from_slice(payload).context("unsupported or damaged Mirage invitation")?;
        invitation.validate(time)?;Ok(invitation)
    }
    pub fn settings(&self,iran_side:bool,reverse:bool)->Settings{
        Settings{tunnel_key:self.key.clone(),raw:RawOptions{local_ip:Some(if iran_side{self.iran}else{self.foreign}),peer_ip:if iran_side{self.foreign}else{self.iran},l4_port:self.raw_port,tcp_flags:"r".into(),..RawOptions::default()},
            candidates:if reverse{self.iran_sources.clone()}else{self.foreign_sources.clone()},profiles:self.profiles.clone(),attempts:self.depth.attempts(),delay_ms:150,receive_ms:if self.depth==Depth::Quick{1500}else{4000}}
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Report {
    pub session:String,pub created_at:u64,pub finished:bool,pub depth:Depth,
    pub iran:Ipv4Addr,pub foreign:Ipv4Addr,pub raw_port:u16,
    pub iran_bound:Vec<Row>,pub foreign_bound:Vec<Row>,pub error:Option<String>,
}
impl Report {
    fn new(invite:&Invitation)->Self{Self{session:invite.session.clone(),created_at:invite.created_at,finished:false,depth:invite.depth,iran:invite.iran,foreign:invite.foreign,raw_port:invite.raw_port,iran_bound:Vec::new(),foreign_bound:Vec::new(),error:None}}
    pub fn ranked(rows:&[Row])->Vec<usize>{
        let mut indices=(0..rows.len()).collect::<Vec<_>>();
        indices.sort_by(|a,b|{
            let(a,b)=(&rows[*a],&rows[*b]);
            (a.stage!="authenticated-interface-admission").cmp(&(b.stage!="authenticated-interface-admission"))
                .then_with(||a.error.is_some().cmp(&b.error.is_some())).then_with(||a.loss_percent.total_cmp(&b.loss_percent))
                .then_with(||a.raw_reply_loss_percent.total_cmp(&b.raw_reply_loss_percent))
                .then_with(||a.rtt_p95_ms.unwrap_or(f64::INFINITY).total_cmp(&b.rtt_p95_ms.unwrap_or(f64::INFINITY)))
        });indices
    }
}

pub fn write_private(path:&Path,value:&impl Serialize)->Result<()> {
    use std::io::Write;
    let parent=path.parent().context("private state needs parent directory")?;
    if let Ok(meta)=std::fs::symlink_metadata(parent){ensure!(meta.is_dir()&&!meta.file_type().is_symlink(),"private state directory cannot be a symlink");}
    else{
        #[cfg(unix)]{use std::os::unix::fs::DirBuilderExt;std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;}
        #[cfg(not(unix))]{std::fs::create_dir_all(parent)?;}
    }
    if let Ok(meta)=std::fs::symlink_metadata(path){ensure!(meta.is_file()&&!meta.file_type().is_symlink(),"private state file cannot be a symlink");}
    let mut nonce=[0;8];rustls::crypto::ring::default_provider().secure_random.fill(&mut nonce).map_err(|_|anyhow::anyhow!("private state randomness"))?;
    let temporary=parent.join(format!(".{}-{}.tmp",path.file_name().context("state file name")?.to_string_lossy(),hex::encode(nonce)));
    let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
    let mut file=options.open(&temporary)?;
    let result=(||->Result<()>{file.write_all(&serde_json::to_vec_pretty(value)?)?;file.sync_all()?;std::fs::rename(&temporary,path)?;Ok(())})();
    if result.is_err(){let _=std::fs::remove_file(&temporary);}result
}
pub fn read_private<T:serde::de::DeserializeOwned>(path:&Path)->Result<T>{
    use std::io::Read;
    let mut options=std::fs::OpenOptions::new();options.read(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.custom_flags(libc::O_NOFOLLOW);}
    let mut file=options.open(path)?;let meta=file.metadata()?;ensure!(meta.is_file()&&meta.len()<=2*1024*1024,"invalid private state file");
    #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;ensure!(meta.permissions().mode()&0o077==0,"private state must not be readable by other users");}
    let mut bytes=Vec::new();file.by_ref().take(2*1024*1024+1).read_to_end(&mut bytes)?;ensure!(bytes.len()<=2*1024*1024,"state file too large");Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Serialize,Deserialize)]
#[serde(tag="type",deny_unknown_fields)]
enum Message {Start{session:String},Accepted,Row{reverse:bool,row:Row},End{reverse:bool,count:usize},Done}
async fn send(writer:&mut SecureWriter,message:&Message)->Result<()>{writer.send(&Frame::Data{id:CONTROL,data:serde_json::to_vec(message)?}).await}
async fn receive(reader:&mut SecureReader)->Result<Message>{let frame=timeout(Duration::from_secs(30),reader.recv()).await??;let Frame::Data{id,data}=frame else{anyhow::bail!("unexpected guided test frame")};ensure!(id==CONTROL&&data.len()<=4096,"invalid guided session framing");Ok(serde_json::from_slice(&data)?)}
async fn share(writer:&mut SecureWriter,reverse:bool,rows:&[Row])->Result<()>{for row in rows{send(writer,&Message::Row{reverse,row:row.clone()}).await?;}send(writer,&Message::End{reverse,count:rows.len()}).await}
async fn collect(reader:&mut SecureReader,reverse:bool,settings:&Settings,report:&mut Report,path:&Path,progress:&mut dyn FnMut(bool,&Row))->Result<()> {
    let mut rows=Vec::new();
    loop{match receive(reader).await?{
        Message::Row{reverse:direction,row}=>{
            ensure!(direction==reverse&&rows.len()<settings.candidates.len()*settings.profiles.len(),"guided result count/direction mismatch");
            ensure!(settings.candidates.contains(&row.source)&&settings.profiles.contains(&row.profile)&&usize::from(row.sent)<=usize::from(settings.attempts)&&row.received<=usize::from(row.sent)&&row.raw_reply_received<=usize::from(row.sent),"invalid guided result scope");
            ensure!(row.loss_percent.is_finite()&&(0.0..=100.0).contains(&row.loss_percent)&&row.raw_reply_loss_percent.is_finite()&&(0.0..=100.0).contains(&row.raw_reply_loss_percent),"invalid result loss");
            ensure!(!rows.iter().any(|old:&Row|old.source==row.source&&old.profile==row.profile),"duplicate guided result");
            ensure!(row.rtt_median_ms.is_none_or(|value|value.is_finite()&&(0.0..=10000.0).contains(&value))&&row.rtt_p95_ms.is_none_or(|value|value.is_finite()&&(0.0..=10000.0).contains(&value)),"invalid result latency");
            let expected_loss=100.0*(f64::from(row.sent)-row.received as f64)/f64::from(row.sent.max(1));
            ensure!(row.sent==0&&row.error.is_some()||(row.sent==settings.attempts&&(row.loss_percent-expected_loss).abs()<1e-7),"result loss/count inconsistency");
            progress(reverse,&row);rows.push(row);if reverse{report.foreign_bound=rows.clone();}else{report.iran_bound=rows.clone();}write_private(path,report)?;
        }
        Message::End{reverse:direction,count}=>{ensure!(direction==reverse&&count==rows.len()&&count==settings.candidates.len()*settings.profiles.len(),"incomplete guided results");return Ok(());}
        _=>anyhow::bail!("unexpected guided result message"),
    }}
}

/// How long a joiner that completed the handshake has to send its encrypted Start.
const START_WAIT:Duration=Duration::from_secs(10);

/// V11: waits for the joining peer. A connection from another address, a failed handshake, or
/// a handshake that is not followed by a valid encrypted Start (for example a replayed first
/// flight, which the responder cannot tell apart until the Start arrives) is dropped and the host
/// keeps waiting until the invitation expires. Only an authenticated Start for this session wins.
async fn admit_start(listener:&TcpListener,peer:std::net::IpAddr,key:&TunnelKey,session:&str,until:Instant,start_wait:Duration)->Result<(SecureReader,SecureWriter)>{
    let(private,allowed)=(key.private_key(Mode::Server),[key.public_key(Mode::Client)?]);
    loop{
        let(socket,remote)=timeout(until.saturating_duration_since(Instant::now()),listener.accept()).await.context("invitation expired while waiting for peer")??;
        if remote.ip()!=peer{continue;}
        let Ok(connection)=crate::transport::accept_control(socket,&private,&allowed,Duration::from_secs(5),DOMAIN).await else{ensure!(Instant::now()<until,"invitation expired");continue;};
        let(mut reader,writer)=connection.split();
        let wait=start_wait.min(until.saturating_duration_since(Instant::now()));
        match timeout(wait,receive(&mut reader)).await{
            Ok(Ok(Message::Start{session:chosen}))=>{ensure!(chosen==session,"joining peer selected a different test session");return Ok((reader,writer));}
            _=>{ensure!(Instant::now()<until,"invitation expired before peer start");continue;}
        }
    }
}

pub async fn host(listener:TcpListener,invite:Invitation,state:&Path,progress:&mut dyn FnMut(bool,&Row))->Result<Report>{
    invite.validate(now()?)?;
    ensure!(!state.with_extension("consumed").exists(),"test invitation was already used; start a new session");
    let key=TunnelKey::parse(&invite.key)?;
    let remaining=invite.expires_at.saturating_sub(now()?);let until=Instant::now()+Duration::from_secs(remaining);
    let(mut reader,mut writer)=admit_start(&listener,std::net::IpAddr::V4(invite.foreign),&key,&invite.session,until,START_WAIT).await?;
    invite.validate(now()?)?;
    // Consume only after the encrypted application Start proves possession of
    // completed transport keys, not merely a replayable first Noise message.
    let consumed=state.with_extension("consumed");let mut create=std::fs::OpenOptions::new();create.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;create.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
    create.open(consumed).context("test invitation was already used; start a new session")?;
    send(&mut writer,&Message::Accepted).await?;
    let mut report=Report::new(&invite);write_private(state,&report)?;
    let outcome=timeout(Duration::from_secs(5400),async {
        let settings=invite.settings(true,false);
        crate::spoof_test::receive_connected_progress(&mut reader,&mut writer,&settings,&mut |row|{
            progress(false,row);report.iran_bound.push(row.clone());let _=write_private(state,&report);
        }).await?;
        collect(&mut reader,false,&settings,&mut report,state,progress).await?;
        if !invite.iran_sources.is_empty(){
            let settings=invite.settings(true,true);let partial=state.with_extension("reverse.partial.json");
            let rows=crate::spoof_test::run_connected(&mut reader,&mut writer,&settings,&partial,&mut |row|{progress(true,row);report.foreign_bound.push(row.clone());let _=write_private(state,&report);}).await?;
            share(&mut writer,true,&rows).await?;report.foreign_bound=rows;write_private(state,&report)?;
        }
        ensure!(matches!(receive(&mut reader).await?,Message::Done),"guided session did not finish");send(&mut writer,&Message::Done).await?;
        Ok::<(),anyhow::Error>(())
    }).await.context("guided session time limit").and_then(|result|result);
    if let Err(error)=outcome{report.error=Some(format!("{error:#}"));write_private(state,&report)?;return Err(error);}
    report.finished=true;write_private(state,&report)?;Ok(report)
}

pub async fn join(invite:Invitation,state:&Path,progress:&mut dyn FnMut(bool,&Row))->Result<Report>{
    invite.validate(now()?)?;let key=TunnelKey::parse(&invite.key)?;
    ensure!(!state.exists(),"this guided session already has local results; create a new invitation instead of overwriting it");
    let until=Instant::now()+Duration::from_secs(invite.expires_at.saturating_sub(now()?));
    let mut connection=None;
    while Instant::now()<until{
        match crate::transport::connect_control(&SocketAddr::from((invite.iran,invite.control_port)).to_string(),&key.private_key(Mode::Client),&key.public_key(Mode::Server)?,Duration::from_secs(5),DOMAIN).await{Ok(value)=>{connection=Some(value);break;},Err(_)=>tokio::time::sleep(Duration::from_millis(500)).await}
    }
    let(mut reader,mut writer)=connection.context("peer unavailable or invitation expired; check its listening address and firewall, then start a new session")?.split();
    invite.validate(now()?)?;send(&mut writer,&Message::Start{session:invite.session.clone()}).await?;
    let accepted=timeout(until.saturating_duration_since(Instant::now()),receive(&mut reader)).await.context("invitation expired before acceptance")??;
    invite.validate(now()?)?;
    ensure!(matches!(accepted,Message::Accepted),"peer rejected this test session");
    let mut report=Report::new(&invite);write_private(state,&report)?;
    let outcome=timeout(Duration::from_secs(5400),async{
        let settings=invite.settings(false,false);let partial=state.with_extension("iran.partial.json");
        let rows=crate::spoof_test::run_connected(&mut reader,&mut writer,&settings,&partial,&mut |row|{progress(false,row);report.iran_bound.push(row.clone());let _=write_private(state,&report);}).await?;
        share(&mut writer,false,&rows).await?;report.iran_bound=rows;write_private(state,&report)?;
        if !invite.iran_sources.is_empty(){
            let settings=invite.settings(false,true);crate::spoof_test::receive_connected_progress(&mut reader,&mut writer,&settings,&mut |row|{
                progress(true,row);report.foreign_bound.push(row.clone());let _=write_private(state,&report);
            }).await?;
            collect(&mut reader,true,&settings,&mut report,state,progress).await?;
        }
        send(&mut writer,&Message::Done).await?;ensure!(matches!(receive(&mut reader).await?,Message::Done),"peer did not acknowledge completion");Ok::<(),anyhow::Error>(())
    }).await.context("guided session time limit").and_then(|result|result);
    if let Err(error)=outcome{report.error=Some(format!("{error:#}"));write_private(state,&report)?;return Err(error);}
    report.finished=true;write_private(state,&report)?;Ok(report)
}

pub fn report_path(directory:&Path,session:&str)->Result<PathBuf>{ensure!(session.len()==24&&session.bytes().all(|b|b.is_ascii_hexdigit()),"invalid saved session name");Ok(directory.join(format!("{session}.report.json")))}

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupBundle {pub version:u8,pub expires_at:u64,pub config:serde_json::Value}
impl std::fmt::Debug for SetupBundle{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("MirageSetupBundle(REDACTED)")}}
impl SetupBundle {
    pub fn new(config:serde_json::Value)->Result<Self>{let value=Self{version:1,expires_at:now()?+86400,config};value.validate(now()?)?;Ok(value)}
    pub fn validate(&self,time:u64)->Result<()> {
        ensure!(self.version==1&&self.expires_at>time&&self.expires_at<=time.saturating_add(86430),"Mirage setup code expired or unsupported; create a new one");
        let key=self.config["tunnel_key"].as_str().context("setup needs a tunnel key")?;TunnelKey::parse(key)?;
        let server=match self.config["mode"].as_str(){Some("server")=>true,Some("client")=>false,_=>anyhow::bail!("setup role missing")};
        let entries=self.config[if server{"listeners"}else{"paths"}].as_array().context("setup entry missing")?;
        ensure!(entries.len()==1&&entries[0]["transport"]=="mirage"&&entries[0]["raw"]["mirage"].is_object(),"setup is not a single Mirage v2 tunnel");
        let raw:&serde_json::Value=&entries[0]["raw"];
        let options:RawOptions=serde_json::from_value(raw.clone())?;options.validate()?;
        ensure!(options.peer_mac.is_none()&&options.gateway_ip.is_none()&&options.interface.is_none(),"peer setup may not import local interface, gateway or MAC overrides");
        ensure!(raw["mirage_acknowledgement"]=="experimental-v2"&&raw["mirage"].is_object(),"setup must use explicit Mirage v2 settings");
        let allowed_top=["mode","tunnel_key","wire_version","listeners","paths","socks5","allowed_targets","tun","worker_threads","heartbeat_sec","dead_timeout_sec","max_connections","timeouts","stream_window","stats_interval_sec"];
        let object=self.config.as_object().context("setup configuration must be an object")?;
        ensure!(object.keys().all(|name|allowed_top.contains(&name.as_str())),"setup contains unsupported global settings; import plain local configuration manually instead");
        let allowed_entry=["addr","transport","maps","raw","fec","connection_pool","retry_interval","dial_timeout","weight"];
        ensure!(entries[0].as_object().context("setup entry object")?.keys().all(|name|allowed_entry.contains(&name.as_str())),"setup contains unsupported entry settings");
        let mut parsed:crate::config::Config=serde_json::from_value(self.config.clone()).context("setup configuration structure")?;
        parsed.prepare()?;parsed.validate()?;
        // Import cannot inject arbitrary file paths or another extension endpoint.
        ensure!(self.config.get("private_key_file").is_none()&&self.config.get("gaming").is_none(),"unexpected setup file/extension field");
        ensure!(entries[0].get("tls").is_none()&&entries[0].get("tls_cert").is_none()&&entries[0].get("tls_key").is_none(),"unexpected TLS files in Mirage setup");
        ensure!(entries[0]["fec"]["tcp_fallback"]["address"].is_null(),"a peer setup code may not introduce an independent TCP fallback listener/destination; configure it explicitly on this host");
        Ok(())
    }
    pub fn encode(&self)->Result<String>{self.validate(now()?)?;let mut bytes=serde_json::to_vec(self)?;ensure!(bytes.len()<=24000,"setup code too large");let digest=blake3::hash(&bytes);bytes.extend_from_slice(&digest.as_bytes()[..8]);Ok(format!("ezm-setup1-{}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)))}
    pub fn decode(text:&str,time:u64)->Result<Self>{ensure!(text.len()<=40000,"setup code too long");let text=text.chars().filter(|c|!c.is_whitespace()).collect::<String>();let body=text.strip_prefix("ezm-setup1-").context("expected Mirage peer setup code ezm-setup1-")?;let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body)?;ensure!(bytes.len()>8&&bytes.len()<=24008,"setup code length");let(payload,digest)=bytes.split_at(bytes.len()-8);ensure!(&blake3::hash(payload).as_bytes()[..8]==digest,"damaged setup code");let bundle:Self=serde_json::from_slice(payload)?;bundle.validate(time)?;Ok(bundle)}
}

#[cfg(test)]mod tests{
    use super::*;
    /// V11: a connection that completes the handshake but never sends Start (what a replayed
    /// first flight looks like to the responder) and a garbage connection do not end the host;
    /// the genuine joiner's Start is then admitted, and a wrong session is still refused.
    #[tokio::test]
    async fn a_stalled_or_replayed_handshake_does_not_end_the_guided_host()->Result<()> {
        use tokio::io::AsyncWriteExt;
        let key=TunnelKey::generate()?;let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?.to_string();
        let peer:std::net::IpAddr="127.0.0.1".parse()?;
        let admitting={let key=TunnelKey::parse(&key.display())?;tokio::spawn(async move{
            admit_start(&listener,peer,&key,"aaaaaaaaaaaaaaaaaaaaaaaa",Instant::now()+Duration::from_secs(20),Duration::from_millis(500)).await.map(|_|())
        })};
        let mut garbage=tokio::net::TcpStream::connect(&address).await?;garbage.write_all(&[0x55;96]).await?;drop(garbage);
        let stalled=crate::transport::connect_control(&address,&key.private_key(Mode::Client),&key.public_key(Mode::Server)?,Duration::from_secs(5),DOMAIN).await?;
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(!admitting.is_finished(),"a stalled handshake ended the host");
        let(_reader,mut writer)=crate::transport::connect_control(&address,&key.private_key(Mode::Client),&key.public_key(Mode::Server)?,Duration::from_secs(5),DOMAIN).await?.split();
        send(&mut writer,&Message::Start{session:"aaaaaaaaaaaaaaaaaaaaaaaa".into()}).await?;
        timeout(Duration::from_secs(5),admitting).await???;
        drop(stalled);
        // A key holder naming another session is refused, not silently retried.
        let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?.to_string();
        let refusing={let key=TunnelKey::parse(&key.display())?;tokio::spawn(async move{
            admit_start(&listener,peer,&key,"aaaaaaaaaaaaaaaaaaaaaaaa",Instant::now()+Duration::from_secs(20),Duration::from_millis(500)).await.map(|_|())
        })};
        let(_reader,mut writer)=crate::transport::connect_control(&address,&key.private_key(Mode::Client),&key.public_key(Mode::Server)?,Duration::from_secs(5),DOMAIN).await?.split();
        send(&mut writer,&Message::Start{session:"bbbbbbbbbbbbbbbbbbbbbbbb".into()}).await?;
        let error=timeout(Duration::from_secs(5),refusing).await??.unwrap_err();
        assert!(format!("{error:#}").contains("different test session"),"{error:#}");
        Ok(())
    }
    fn invitation()->Result<Invitation>{Invitation::new("192.0.2.1".parse()?,"192.0.2.2".parse()?,parse_sources("198.51.100.1,198.51.100.1;198.51.100.2")?,vec!["192.0.2.1".parse()?],vec![RawProfile::Udp,RawProfile::Icmp],Depth::Quick,45001,45002)}
    #[test]fn codes_expire_validate_scope_and_never_debug_the_bearer_key()->Result<()>{
        let invite=invitation()?;assert_eq!(invite.foreign_sources.len(),2);let code=invite.encode()?;
        assert_eq!(Invitation::decode(&code,invite.created_at)?.session,invite.session);
        assert!(Invitation::decode(&code,invite.expires_at).is_err());assert!(!format!("{invite:?}").contains(&invite.key));
        let mut invalid=invite.clone();invalid.iran=invalid.foreign;assert!(invalid.validate(invite.created_at).is_err());invalid=invite.clone();invalid.expires_at+=1;assert!(invalid.validate(invite.created_at).is_err());
        assert!(parse_sources("198.51.100.0/24").is_err());assert!(Invitation::decode(&"x".repeat(40000),invite.created_at).is_err());
        let mut damaged=code.into_bytes();let n=damaged.len()-4;damaged[n]=if damaged[n]==b'A'{b'B'}else{b'A'};assert!(Invitation::decode(std::str::from_utf8(&damaged)?,invite.created_at).is_err());Ok(())
    }
    #[test]fn private_storage_rejects_symlinks_and_reports_have_no_key()->Result<()>{
        let directory=tempfile::tempdir()?;let invite=invitation()?;let path=report_path(directory.path(),&invite.session)?;
        #[cfg(unix)]let parent_mode={use std::os::unix::fs::PermissionsExt;std::fs::metadata(directory.path())?.permissions().mode()};
        let report=Report::new(&invite);write_private(&path,&report)?;let read:Report=read_private(&path)?;assert_eq!(read.session,invite.session);assert!(!std::fs::read_to_string(&path)?.contains(&invite.key));
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;assert_eq!(std::fs::metadata(directory.path())?.permissions().mode(),parent_mode,"writing state must not chmod existing parent directories");}
        #[cfg(unix)]{let link=directory.path().join("link");std::os::unix::fs::symlink(&path,&link)?;assert!(write_private(&link,&report).is_err());assert!(read_private::<Report>(&link).is_err());}
        Ok(())
    }
    #[test]fn peer_setup_code_expires_and_rejects_file_injection()->Result<()> {
        let invite=invitation()?;
        let config=serde_json::json!({"mode":"client","tunnel_key":TunnelKey::generate()?.display(),"wire_version":3,
            "paths":[{"addr":"192.0.2.1:45670","transport":"mirage","raw":{"profile":"udp","local_ip":"192.0.2.2","peer_ip":"192.0.2.1","l4_port":45670,"mirage_acknowledgement":"experimental-v2",
            "mirage":{"uplink":"udp","downlink":"icmp","source_pool":["198.51.100.1"],"expected_sources":["192.0.2.1"],"echo_mode":"replies"}}}],"allowed_targets":["127.0.0.1:443"]});
        let bundle=SetupBundle::new(config)?;let code=bundle.encode()?;assert!(SetupBundle::decode(&code,now()?).is_ok());assert!(SetupBundle::decode(&code,bundle.expires_at).is_err());
        assert_ne!(bundle.config["tunnel_key"].as_str(),Some(invite.key.as_str()));
        let mut bad=bundle.clone();bad.config["private_key_file"]="/root/secret".into();assert!(bad.validate(now()?).is_err());
        bad=bundle.clone();bad.config["paths"][0]["tls_key"]="/root/key".into();assert!(bad.validate(now()?).is_err());
        // V08: a peer setup code may not add its own TCP fallback endpoint.
        bad=bundle.clone();bad.config["paths"][0]["fec"]=serde_json::json!({"tcp_fallback":{"address":"203.0.113.9:4433"}});
        let error=bad.validate(now()?).unwrap_err();
        assert!(format!("{error:#}").contains("TCP fallback"),"{error:#}");Ok(())
    }
}
