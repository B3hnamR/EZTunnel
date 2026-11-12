//! Bounded two-endpoint source/profile tester. Explicit addresses only; no discovery.
use anyhow::{Result, Context, ensure};
use serde::{Serialize,Deserialize};
use std::{collections::BTreeSet,net::{Ipv4Addr,SocketAddr},path::Path,time::Duration};
use tokio::{net::TcpListener,time::{Instant,timeout}};
use crate::{config::Mode,raw_packet::{RawOptions,RawProfile},spoof::{MirageOptions,EchoMode},transport::{SecureReader,SecureWriter},wire::Frame};

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub tunnel_key:String,
    pub raw:RawOptions,
    pub candidates:Vec<Ipv4Addr>,
    pub profiles:Vec<RawProfile>,
    #[serde(default="attempts")]pub attempts:u16,
    #[serde(default="delay")]pub delay_ms:u64,
    #[serde(default="deadline")]pub receive_ms:u64,
}
fn attempts()->u16{5}fn delay()->u64{150}fn deadline()->u64{2500}
impl Settings {
    pub fn load(path:&Path)->Result<Self>{
        let metadata=std::fs::symlink_metadata(path)?;ensure!(metadata.is_file()&&!metadata.file_type().is_symlink(),"tester settings must be a regular file, not symlink");
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;ensure!(metadata.permissions().mode()&0o077==0,"tester settings must have mode 0600 or 0400");}
        ensure!(metadata.len()<=64*1024,"tester settings file exceeds 64 KiB");
        let settings:Self=serde_json::from_slice(&std::fs::read(path)?)?;
        crate::tunnel_key::TunnelKey::parse(&settings.tunnel_key)?;
        ensure!(!settings.candidates.is_empty()&&settings.candidates.len()<=64,"tester needs 1..64 explicit candidate IPs");
        ensure!(settings.raw.local_ip.is_some(),"tester needs explicit REAL local_ip");
        ensure!(!settings.raw.peer_ip.is_unspecified()&&!settings.raw.peer_ip.is_multicast()&&!settings.raw.peer_ip.is_loopback(),"tester needs explicit REAL peer_ip");
        ensure!(!settings.profiles.is_empty()&&settings.profiles.len()<=7,"tester needs 1..7 explicit profiles");
        ensure!((1..=20).contains(&settings.attempts)&&(50..=5000).contains(&settings.delay_ms),"tester attempts 1..20, delay_ms 50..5000");
        ensure!((500..=10000).contains(&settings.receive_ms),"tester receive_ms500..10000");
        ensure!(settings.profiles.iter().all(|profile|matches!(profile,RawProfile::Tcp|RawProfile::Udp|RawProfile::Icmp|RawProfile::Icmpv6|RawProfile::Gre|RawProfile::Ipip|RawProfile::Bip)),"unsupported tester profile");
        for ip in &settings.candidates{ensure!(!ip.is_unspecified()&&!ip.is_multicast()&&!ip.is_broadcast()&&!ip.is_loopback(),"candidate must be explicit unicastIPv4");}
        Ok(settings)
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    /// V12: a wrong-address connection and a connection that fails authentication do not
    /// end the listener; the later genuine peer is admitted.
    #[tokio::test]
    async fn bad_or_foreign_connections_do_not_end_the_tester_listener()->Result<()> {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
        let peer:std::net::IpAddr="127.0.0.1".parse()?;
        let admitting=tokio::spawn(async move{
            admit_first(&listener,peer,Instant::now()+Duration::from_secs(10),|mut socket:tokio::net::TcpStream|async move{
                let mut word=[0u8;4];socket.read_exact(&mut word).await?;ensure!(&word==b"good","authentication failed");Ok(word)
            }).await
        });
        // From another loopback address: ignored without consuming the listener.
        let foreign=tokio::net::TcpSocket::new_v4()?;foreign.bind("127.0.0.2:0".parse()?)?;
        let mut foreign=foreign.connect(address).await?;foreign.write_all(b"good").await?;
        // From the peer address but failing authentication.
        let mut bad=tokio::net::TcpStream::connect(address).await?;bad.write_all(b"evil").await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!admitting.is_finished(),"a bad connection ended the listener");
        let mut good=tokio::net::TcpStream::connect(address).await?;good.write_all(b"good").await?;
        let admitted=timeout(Duration::from_secs(5),admitting).await???;
        assert_eq!(&admitted,b"good");
        // Nothing arrives before the deadline: a clean timeout error, not a hang.
        let quiet=TcpListener::bind("127.0.0.1:0").await?;
        let result=admit_first(&quiet,peer,Instant::now()+Duration::from_millis(200),|_socket|async{Ok(())}).await;
        assert!(format!("{:#}",result.unwrap_err()).contains("deadline expired"));
        Ok(())
    }
    #[test]
    fn settings_are_private_bounded_and_results_replace_atomically()->Result<()> {
        let directory=tempfile::tempdir()?;let path=directory.path().join("settings.json");
        let key=crate::tunnel_key::TunnelKey::generate()?.display();
        let mut value=serde_json::json!({"tunnel_key":key,"raw":{"local_ip":"192.0.2.1","peer_ip":"192.0.2.2","l4_port":45670},"candidates":["198.51.100.1"],"profiles":["icmp"]});
        std::fs::write(&path,serde_json::to_vec(&value)?)?;
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600))?;}
        assert!(Settings::load(&path).is_ok());value["attempts"]=21.into();std::fs::write(&path,serde_json::to_vec(&value)?)?;assert!(Settings::load(&path).is_err());
        let output=directory.path().join("results.json");write_results(&output,&[])?;assert_eq!(std::fs::read_to_string(&output)?,"[]");
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;assert_eq!(std::fs::metadata(&output)?.permissions().mode()&0o777,0o600);
            let linked=directory.path().join("linked");std::os::unix::fs::symlink(&output,&linked)?;assert!(write_results(&linked,&[]).is_err());}
        Ok(())
    }
}
#[derive(Serialize,Deserialize)]
#[serde(tag="type",deny_unknown_fields)]
enum Control {
    Prepare{profile:RawProfile,source:Ipv4Addr,attempts:u16,receive_ms:u64,run:[u8;16]},
    Ready,
    Result{seen:Vec<u16>,window_ms:u64},
    Error{message:String},
    Finish,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Row {
    pub source:Ipv4Addr,pub profile:RawProfile,pub direction:String,pub sent:u16,pub received:usize,
    pub loss_percent:f64,pub stage:String,pub error:Option<String>,
    pub raw_reply_received:usize,
    pub raw_reply_loss_percent:f64,
    pub rtt_median_ms:Option<f64>,pub rtt_p95_ms:Option<f64>,
}
fn write_results(output:&Path,rows:&[Row])->Result<()> {
    use std::io::Write;
    let directory=output.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or_else(||Path::new("."));
    ensure!(directory.is_dir(),"tester output parent directory does not exist");
    if let Ok(metadata)=std::fs::symlink_metadata(output){ensure!(metadata.is_file()&&!metadata.file_type().is_symlink(),"tester output cannot replace a symlink or nonregular file");}
    let mut bytes=[0;8];rustls::crypto::ring::default_provider().secure_random.fill(&mut bytes).map_err(|_|anyhow::anyhow!("tester result randomness"))?;
    let temporary=directory.join(format!(".eztunnel-spooftest-{}.tmp",hex::encode(bytes)));
    let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
    let mut file=options.open(&temporary)?;
    let result=(||->Result<()>{file.write_all(&serde_json::to_vec_pretty(rows)?)?;file.sync_all()?;std::fs::rename(&temporary,output)?;Ok(())})();
    if result.is_err(){let _=std::fs::remove_file(&temporary);}
    result
}
async fn send(writer:&mut SecureWriter,sequence:u32,message:&Control)->Result<()>{writer.send(&Frame::Data{id:sequence,data:serde_json::to_vec(message)?}).await}
async fn recv(reader:&mut SecureReader,sequence:u32)->Result<Control>{
    let frame=timeout(Duration::from_secs(30),reader.recv()).await??;
    let Frame::Data{id,data}=frame else{anyhow::bail!("unexpected tester control frame")};ensure!(id==sequence&&data.len()<=4096,"tester control framing");Ok(serde_json::from_slice(&data)?)
}
fn raw(template:&RawOptions,source:Option<Ipv4Addr>,expected:Ipv4Addr,profile:RawProfile)->RawOptions {
    let mut raw=template.clone();raw.profile=profile;raw.spoof_src_ip=source;raw.spoof_dst_ip=None;raw.proto58_mode=false;raw.hopping.enabled=false;
    raw.tcp_flags="r".into(); // RST probes cannot provoke a reset response to the forged source.
    raw.mirage_acknowledgement=Some("experimental-v2".into());
    raw.mirage=Some(MirageOptions{uplink:Some(profile),downlink:Some(profile),allow_real_source:source.is_none(),expected_sources:vec![expected],echo_mode:EchoMode::Replies,..MirageOptions::default()});raw
}
fn admission(raw:&mut RawOptions,key:&crate::tunnel_key::TunnelKey){raw.mirage.as_mut().unwrap().admission_key=Some(crate::spoof::AdmissionKey::new(key.mirage_key()));}

pub async fn listen(bind:SocketAddr,settings:Settings)->Result<()> {
    let key=crate::tunnel_key::TunnelKey::parse(&settings.tunnel_key)?;
    let private=key.private_key(Mode::Server);let allowed=[key.public_key(Mode::Client)?];
    let listener=TcpListener::bind(bind).await?;
    eprintln!("Spoof tester control listening at {bind}; no host firewall or route changes");
    // One explicit authenticated run, then exit. No long-lived public daemon.
    let until=Instant::now()+Duration::from_secs(300);
    let connection=admit_first(&listener,std::net::IpAddr::V4(settings.raw.peer_ip),until,|socket|crate::transport::accept_checker(socket,&private,&allowed,Duration::from_secs(5))).await?;
    let(mut reader,mut writer)=connection.split();
    receive_connected(&mut reader,&mut writer,&settings).await
}

/// V12: the first connection that comes from the configured peer and authenticates wins.
/// Connections from other addresses, or that fail authentication, are dropped and the
/// listener keeps waiting until the overall deadline.
async fn admit_first<T,F,Fut>(listener:&TcpListener,peer:std::net::IpAddr,until:Instant,mut admit:F)->Result<T>
where F:FnMut(tokio::net::TcpStream)->Fut,Fut:std::future::Future<Output=Result<T>>{
    loop{
        let(socket,remote)=timeout(until.saturating_duration_since(Instant::now()),listener.accept()).await.context("tester listener join deadline expired")??;
        if remote.ip()!=peer{continue;}
        match admit(socket).await{Ok(connection)=>return Ok(connection),Err(_)=>{ensure!(Instant::now()<until,"tester listener join deadline expired");}}
    }
}

pub(crate) async fn receive_connected(reader:&mut SecureReader,writer:&mut SecureWriter,settings:&Settings)->Result<()> {
    receive_connected_progress(reader,writer,settings,&mut |_|{}).await
}
pub(crate) async fn receive_connected_progress(reader:&mut SecureReader,writer:&mut SecureWriter,settings:&Settings,progress:&mut dyn FnMut(&Row))->Result<()> {
    let key=crate::tunnel_key::TunnelKey::parse(&settings.tunnel_key)?;
    let mut sequence=1u32;let deadline=Instant::now()+Duration::from_secs(5400);
    loop {
        ensure!(sequence<=449&&Instant::now()<deadline,"tester session operation/time budget exhausted");
        match recv(reader,sequence).await? {
            Control::Finish=>return Ok(()),
            Control::Prepare{profile,source,attempts,receive_ms,run}=>{
                ensure!(settings.candidates.contains(&source)&&settings.profiles.contains(&profile),"peer requested candidate/profile not explicitly allowed by receiver settings");
                ensure!(attempts>0&&attempts<=settings.attempts&&receive_ms<=10000,"peer probe bounds");
                let mut options=raw(&settings.raw,None,source,profile);admission(&mut options,&key);
                let socket=match crate::raw_socket::RawSocket::bind_fec(&options,true).await {
                    Ok(socket)=>socket,Err(error)=>{send(writer,sequence,&Control::Error{message:format!("{error:#}")}).await?;sequence+=1;continue;}
                };
                send(writer,sequence,&Control::Ready).await?;
                let mut seen=BTreeSet::new();let until=Instant::now()+Duration::from_millis(receive_ms);let mut bytes=[0;2048];
                loop {
                    let received=tokio::select!{result=socket.recv(&mut bytes)=>result,_=tokio::time::sleep_until(until)=>break};
                    let count=received?;
                    if count!=22||&bytes[..4]!=b"EZP2"||bytes[4..20]!=run{continue;}
                    let index=u16::from_be_bytes(bytes[20..22].try_into().unwrap());if index<attempts&&seen.insert(index){
                        // Always reply toward the configured REAL peer, not the
                        // packet's forged source; one bounded response per probe.
                        socket.send(&bytes[..count]).await?;
                    }
                }
                let received=seen.len();
                send(writer,sequence,&Control::Result{seen:seen.into_iter().collect(),window_ms:receive_ms}).await?;
                // Receiving-side progress is explicitly one-way; only the
                // sender's final shared row can supply return-path RTT.
                progress(&Row{source,profile,direction:format!("{} -> {}",settings.raw.peer_ip,settings.raw.local_ip.map(|ip|ip.to_string()).unwrap_or_default()),
                    sent:attempts,received,loss_percent:100.0*(f64::from(attempts)-received as f64)/f64::from(attempts),stage:"receiving-case-complete-awaiting-sender-report".into(),error:None,
                    raw_reply_received:0,raw_reply_loss_percent:100.0,rtt_median_ms:None,rtt_p95_ms:None});
            }
            _=>anyhow::bail!("expected tester prepare/finish"),
        }
        sequence=sequence.checked_add(1).context("tester sequence exhausted")?;
    }
}

pub async fn run(peer:SocketAddr,settings:Settings,output:&Path)->Result<Vec<Row>> {
    ensure!(peer.ip()==std::net::IpAddr::V4(settings.raw.peer_ip),"tester destination must be configured real peer_ip");
    let key=crate::tunnel_key::TunnelKey::parse(&settings.tunnel_key)?;
    let connection=crate::transport::connect_checker(&peer.to_string(),&key.private_key(Mode::Client),&key.public_key(Mode::Server)?,Duration::from_secs(5)).await?;
    let(mut reader,mut writer)=connection.split();
    run_connected(&mut reader,&mut writer,&settings,output,&mut |row|{if let Ok(text)=serde_json::to_string(row){println!("{text}");}}).await
}

pub(crate) async fn run_connected(reader:&mut SecureReader,writer:&mut SecureWriter,settings:&Settings,output:&Path,progress:&mut dyn FnMut(&Row))->Result<Vec<Row>> {
    let key=crate::tunnel_key::TunnelKey::parse(&settings.tunnel_key)?;
    let mut rows=Vec::new();let mut sequence=1;
    write_results(output,&rows)?;
    for source in &settings.candidates {for profile in &settings.profiles {
        // Complete route/ARP/socket/filter setup before the receiver starts its
        // measurement clock. This preserves the existing control protocol.
        let mut options=raw(&settings.raw,Some(*source),settings.raw.peer_ip,*profile);admission(&mut options,&key);
        let socket=crate::raw_socket::RawSocket::bind_fec(&options,false).await?;
        let mut run=[0;16];rustls::crypto::ring::default_provider().secure_random.fill(&mut run).map_err(|_|anyhow::anyhow!("tester randomness"))?;
        let window=settings.receive_ms.max(settings.attempts as u64*settings.delay_ms+500);
        ensure!(window<=10000,"probe schedule exceeds the 10-second window");
        send(writer,sequence,&Control::Prepare{profile:*profile,source:*source,attempts:settings.attempts,receive_ms:window,run}).await?;
        let mut row=Row{source:*source,profile:*profile,direction:format!("{} -> {}",settings.raw.local_ip.map(|v|v.to_string()).unwrap_or_default(),settings.raw.peer_ip),sent:0,received:0,loss_percent:100.0,stage:"authenticated-interface-admission".into(),error:None,raw_reply_received:0,raw_reply_loss_percent:100.0,rtt_median_ms:None,rtt_p95_ms:None};
        match recv(reader,sequence).await? {
            Control::Ready=>{
                let(started,mut buffer)=(Instant::now(),[0;2048]);let mut times=vec![None;settings.attempts as usize];let mut replied=BTreeSet::new();let mut rtts=Vec::new();
                let until=started+Duration::from_millis(window);let mut next=started;
                loop {
                    tokio::select! {
                        _=tokio::time::sleep_until(until)=>break,
                        _=tokio::time::sleep_until(next),if row.sent<settings.attempts=>{
                            let index=row.sent;let mut packet=b"EZP2".to_vec();packet.extend_from_slice(&run);packet.extend_from_slice(&index.to_be_bytes());
                            times[index as usize]=Some(Instant::now());socket.send(&packet).await?;row.sent+=1;next+=Duration::from_millis(settings.delay_ms);
                        }
                        incoming=socket.recv(&mut buffer)=>{
                            let size=incoming?;
                            if size!=22||&buffer[..4]!=b"EZP2"||buffer[4..20]!=run{continue;}
                            let index=u16::from_be_bytes(buffer[20..22].try_into().unwrap());
                            if let Some(Some(sent))=times.get(index as usize){if replied.insert(index){rtts.push(sent.elapsed().as_secs_f64()*1000.0);}}
                        }
                    }
                }
                row.raw_reply_received=replied.len();row.raw_reply_loss_percent=100.0*(f64::from(row.sent)-replied.len()as f64)/f64::from(row.sent.max(1));
                rtts.sort_by(f64::total_cmp);if !rtts.is_empty(){row.rtt_median_ms=Some(rtts[rtts.len()/2]);row.rtt_p95_ms=Some(rtts[((rtts.len()-1)*95)/100]);}
                match recv(reader,sequence).await? {Control::Result{seen,..}=>{
                    ensure!(seen.len()<=usize::from(row.sent)&&seen.iter().all(|index|*index<row.sent)&&seen.iter().copied().collect::<BTreeSet<_>>().len()==seen.len(),"invalid authenticated tester receipt indices");
                    row.received=seen.len();row.loss_percent=100.0*(f64::from(row.sent)-row.received as f64)/f64::from(row.sent.max(1));},Control::Error{message}=>row.error=Some(message),_=>anyhow::bail!("expected tester result")}
            }
            Control::Error{message}=>row.error=Some(message),_=>anyhow::bail!("expected tester ready"),
        }
        progress(&row);rows.push(row);
        write_results(output,&rows)?;
        sequence+=1;
    }}
    send(writer,sequence,&Control::Finish).await?;Ok(rows)
}
