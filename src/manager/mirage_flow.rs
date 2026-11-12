//! Guided Mirage task flow. Private session state is automatic; no manual JSON.
use super::{ui,store::Store};
use crate::{raw_packet::RawProfile,spoof_session::{self,Depth,Invitation,Report}};
use anyhow::{Context,Result,ensure};
use std::{net::Ipv4Addr,path::{Path,PathBuf}};

fn directory(store:&Store)->PathBuf{store.root().join("mirage-tests")}
// A failed connection can leave a log but no report. Preserve it and give each
// attempt its own exclusively created file rather than blocking the next join.
fn worker_log(report:&Path)->Result<(PathBuf,std::fs::File)>{
    let name=report.file_name().context("Missing test report filename")?.to_string_lossy();
    for _ in 0..8{
        let mut id=[0u8;8];
        rustls::crypto::ring::default_provider().secure_random.fill(&mut id).map_err(|_|anyhow::anyhow!("Generate test worker log identifier"))?;
        let path=report.with_file_name(format!("{name}.{}.worker.log",hex::encode(id)));
        let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
        #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
        match options.open(&path){
            Ok(file)=>return Ok((path,file)),
            Err(error) if error.kind()==std::io::ErrorKind::AlreadyExists=>continue,
            Err(error)=>return Err(error).context("Create private test worker log"),
        }
    }
    anyhow::bail!("Could not allocate a fresh test worker log; prior logs were preserved")
}
fn ipv4(prompt:&str,default:Option<&str>)->Result<Ipv4Addr>{
    Ok(ui::ask(prompt,default,|value:&String|super::plan::unicast_ipv4(value).map(|_|()).map_err(|e|e.to_string()))?.parse()?)
}
fn detected_local(peer:Ipv4Addr)->Option<Ipv4Addr>{
    let socket=std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)).ok()?;
    socket.connect((peer,9)).ok()?;match socket.local_addr().ok()?.ip(){std::net::IpAddr::V4(ip)=>Some(ip),_=>None}
}
fn free_ports()->Result<(u16,u16)>{
    let tcp=std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED,0))?;
    let control=tcp.local_addr()?.port();
    for _ in 0..20{
        let udp=std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0))?;let raw=udp.local_addr()?.port();
        if raw>=1024&&raw<u16::MAX&&raw!=control&&raw+1!=control{return Ok((control,raw));}
    }
    anyhow::bail!("could not find separate free test ports")
}
fn profile_name(profile:RawProfile)->&'static str{match profile{RawProfile::Tcp=>"TCP",RawProfile::Udp=>"UDP",RawProfile::Icmp=>"ICMP",RawProfile::Icmpv6=>"Echo 58",RawProfile::Gre=>"GRE",RawProfile::Ipip=>"IPIP",RawProfile::Bip=>"BIP",RawProfile::Raw=>"RAW",RawProfile::Dns=>"DNS"}}
fn profiles()->Result<Vec<RawProfile>>{
    let choices=["TCP, UDP and ICMP  common starting point","All seven profiles","Choose one profile"].map(str::to_string);
    match ui::choose_required("Which packet types should we test?",&choices,0)?{
        0=>Ok(vec![RawProfile::Tcp,RawProfile::Udp,RawProfile::Icmp]),
        1=>Ok(vec![RawProfile::Tcp,RawProfile::Udp,RawProfile::Icmp,RawProfile::Gre,RawProfile::Ipip,RawProfile::Bip,RawProfile::Icmpv6]),
        _=>{let list=[RawProfile::Tcp,RawProfile::Udp,RawProfile::Icmp,RawProfile::Gre,RawProfile::Ipip,RawProfile::Bip,RawProfile::Icmpv6];let names=list.iter().map(|p|profile_name(*p).to_string()).collect::<Vec<_>>();Ok(vec![list[ui::choose_required("Packet type",&names,0)?]])}
    }
}

pub(super) fn menu(store:&Store)->Result<()> {
    loop{
        ui::banner("Mirage source tests");
        ui::note("Find which source IPs reach Iran. Choose the packet types; EZTunnel coordinates both servers and saves the results.");
        let choices=["Start on Iran  enter the source IPs you want to test","Join on Foreign  paste the temporary invitation","Saved results  compare or create a tunnel","Import peer tunnel setup  paste ezm-setup1 code","Advanced / manual tester","Back"].map(str::to_string);
        let action=ui::choose("Mirage",&choices,0)?;
        let result=match action{Some(0)=>start(store),Some(1)=>join(store),Some(2)=>saved(store),Some(3)=>import_setup(store),Some(4)=>super::mirage::manual_tester(),_=>return Ok(())};
        if let Err(error)=result{if !ui::is_back(&error){ui::fail(&format!("{error:#}"));ui::pause();}}
    }
}

fn import_setup(store:&Store)->Result<()> {
    let text=ui::paste("Mirage peer setup code",|value:&String|spoof_session::SetupBundle::decode(value,spoof_session::now().unwrap_or(u64::MAX)).map(|_|()).map_err(|e|e.to_string()),|text|format!("Peer setup code accepted ({} chars)",text.chars().count()))?;
    let bundle=spoof_session::SetupBundle::decode(&text,spoof_session::now()?)?;
    import_bundle(store,bundle).map(|_|())
}
pub(super) fn import_bundle(store:&Store,mut bundle:spoof_session::SetupBundle)->Result<Option<String>> {
    bundle.validate(spoof_session::now()?)?;
    if !super::mirage::consent()?{return Ok(None);}
    if bundle.config["tun"].is_object(){bundle.config["tun"]["name"]=super::wizard::free_tun_name(store).into();}
    super::plan::check(&bundle.config)?;
    let server=bundle.config["mode"]=="server";let key=if server{"listeners"}else{"paths"};let entry=&bundle.config[key][0];
    let mut preview=vec![format!("Role: {}",if server{"Iran"}else{"Foreign"}),format!("Real peer: {}",entry["raw"]["peer_ip"]),
        format!("Local IP: {}; carrier port: {}",entry["raw"]["local_ip"],entry["raw"]["l4_port"]),
        format!("Uplink: {}; downlink: {}",entry["raw"]["mirage"]["uplink"],entry["raw"]["mirage"]["downlink"]),
        format!("This server sends as: {}",entry["raw"]["mirage"]["source_pool"]),format!("Expected peer sources: {}",entry["raw"]["mirage"]["expected_sources"]),
        "Choose Save and start, or Save only, after reviewing these settings.".into()];
    if server {
        if let Some(maps)=entry["maps"].as_array(){for map in maps{preview.push(format!("Forward {} {} -> {}",map["type"],map["bind"],map["target"]));}}
        if let Some(bind)=bundle.config["socks5"].as_str(){preview.push(format!("SOCKS listener: {bind}"));}
    }else{preview.push(format!("Allowed target addresses: {}",bundle.config["allowed_targets"]));}
    if bundle.config["tun"].is_object(){preview.push(format!("TUN interface/IP configuration: {}",bundle.config["tun"]));}
    ui::boxed("Peer tunnel preview",&preview);
    let name=ui::ask("Name for this tunnel",Some("mirage"),|value:&String|{
        super::plan::check_name(value).map_err(|e|e.to_string())?;
        if store.exists(value){Err("a tunnel with this name exists".into())}else{Ok(())}
    })?;
    let Some(action)=super::setup::choose(store)?else{return Ok(None);};
    super::setup::save(store,&name,&bundle.config,action)?;
    ui::pause();Ok(Some(name))
}
fn start(store:&Store)->Result<()> {
    let draft=ui::form(||{
        ui::heading("Start on Iran", "Enter the spoof sources Foreign will use when sending to Iran");
        let foreign=ipv4("Foreign server's REAL IPv4",None)?;
        let detected=detected_local(foreign).map(|ip|ip.to_string());
        let iran=ipv4("This Iran server's REAL IPv4",detected.as_deref())?;
        ui::note("Paste only source IPs you are permitted to use. Commas, spaces, semicolons and pasted line breaks are accepted; duplicates are removed.");
        let text=ui::paste_sources("Spoof IPs Foreign should send toward Iran",|value:&String|spoof_session::parse_sources(value).map(|_|()).map_err(|e|e.to_string()),|value|format!("{} unique spoof IPs accepted",spoof_session::parse_sources(value).map_or(0,|ips|ips.len())))?;
        let candidates=spoof_session::parse_sources(&text)?;
        let selected=profiles()?;
        let depth=if ui::choose_required("Test depth",&[Depth::Quick.label().into(),Depth::Extended.label().into()],0)?==0{Depth::Quick}else{Depth::Extended};
        let reverse=ui::confirm("Also test Iran -> Foreign?",true)?;
        let reverse_sources=if reverse{
            let text=ui::ask("Iran's outgoing sources ('real' keeps this server's real IP)",Some("real"),|value:&String|if value=="real"{Ok(())}else{spoof_session::parse_sources(value).map(|_|()).map_err(|e|e.to_string())})?;
            if text=="real"{vec![iran]}else{spoof_session::parse_sources(&text)?}
        }else{vec![]};
        Ok((iran,foreign,candidates,reverse_sources,selected,depth))
    })?;
    let(mut control,mut raw)=free_ports()?;
    if ui::choose_required("Test network ports",&["Choose unused ports automatically".into(),"Use specific reachable ports  if your firewall requires them".into()],0)?==1{
        control=ui::ask("Reachable TCP control port on Iran",Some(&control.to_string()),|v:&String|if v.parse::<u16>().is_ok_and(|n|n>=1024){Ok(())}else{Err("enter1024..65535".into())})?.parse()?;
        raw=ui::ask("Unused raw selector port on both servers",Some(&raw.to_string()),|v:&String|if v.parse::<u16>().is_ok_and(|n|(1024..65535).contains(&n)){Ok(())}else{Err("enter1024..65534".into())})?.parse()?;
    }
    let invite=Invitation::new(draft.0,draft.1,draft.2,draft.3,draft.4,draft.5,control,raw)?;
    ui::boxed("Test preview",&[
        format!("Foreign {} -> Iran {}",invite.foreign,invite.iran),
        format!("{} source IPs x {} profiles x {} probes",invite.foreign_sources.len(),invite.profiles.len(),invite.depth.attempts()),
        format!("Return direction: {} source IP(s)",invite.iran_sources.len()),
        format!("Temporary control TCP port {control}; raw selector {raw}"),
        "No tunnel is installed; firewall rules and routes are not changed.".into(),
    ]);
    ui::note("Automatic ports must already be reachable between these servers. If the peer cannot join, allow an appropriate port yourself or use Advanced/manual mode. EZTunnel will not change your firewall.");
    if !ui::confirm("Create the temporary invitation and wait for Foreign?",true)?{return Ok(());}
    worker(store,invite,true)
}
fn join(store:&Store)->Result<()> {
    ui::heading("Join on Foreign", "Paste the invitation displayed on Iran. It contains a temporary secret; share privately.");
    let text=ui::paste("Iran's test invitation",|value:&String|Invitation::decode(value,spoof_session::now().unwrap_or(u64::MAX)).map(|_|()).map_err(|e|e.to_string()),|text|format!("Test invitation accepted ({} chars)",text.chars().count()))?;
    let invite=Invitation::decode(&text,spoof_session::now()?)?;
    let expected=detected_local(invite.iran);
    ui::boxed("Confirm test scope",&[
        format!("This host should be Foreign {}",invite.foreign),format!("Iran: {}",invite.iran),
        format!("{} source IPs; {} profiles; {} probes per case",invite.foreign_sources.len(),invite.profiles.len(),invite.depth.attempts()),
        "Only these candidates and the named real peer will be tested. No service changes.".into(),
    ]);
    if expected.is_some_and(|ip|ip!=invite.foreign){ui::warn("The route-selected local IP differs from the invitation. NAT/public addresses may differ; verify the named host before continuing.");}
    if !ui::confirm("I permit these source IP tests on this server",false)?{return Ok(());}
    worker(store,invite,false)
}
fn worker(store:&Store,invite:Invitation,host:bool)->Result<()> {
    invite.validate(spoof_session::now()?)?;
    let path=directory(store).join(format!("{}.invitation.json",invite.session));
    let report=spoof_session::report_path(&directory(store),&invite.session)?;
    ensure!(!path.exists()&&!report.exists(),"this session already exists locally; start a fresh test or open its saved results");
    spoof_session::write_private(&path,&invite)?;
    struct Remove(std::path::PathBuf);impl Drop for Remove{fn drop(&mut self){let _=std::fs::remove_file(&self.0);}}
    let _secret=Remove(path.clone());
    if host{
        ui::heading("On the Foreign server", "Open Tools -> Mirage source tests -> Join on Foreign, then paste this code");
        eprintln!("\n{}\n",invite.encode()?);
        ui::warn("Secret invitation: valid for ten minutes and one run. Anyone holding it can impersonate this test peer. Do not post it publicly.");
        ui::note("Copy the complete ezm-test1- code now. On Foreign run 'sudo eztunnel spooftest menu', choose Join on Foreign, and paste it. Press Enter here after copying to open the live table; Foreign can retry while Iran starts listening.");
        ui::pause();
        invite.validate(spoof_session::now()?).map_err(|_|anyhow::anyhow!("The invitation expired while being copied. Start a new test; no listener was started."))?;
    }
    ui::note("Live checker: i shows Iran's invitation again, arrows select, Tab switches direction, d shows details, l shows logs, q asks to stop. One-way receipt is separate from final RTT.");
    let mut command=std::process::Command::new(std::env::current_exe()?);
    command.args(["spooftest",if host{"guided-host"}else{"guided-join"},"--invitation"]).arg(&path).arg("--output").arg(&report);
    let(log,file)=worker_log(&report)?;
    command.stdout(file.try_clone()?).stderr(file);
    let mut child=command.spawn()?;
    let outcome=ui::with_interrupt_for_children(||super::mirage_screen::watch(&mut child,&report,&log,&invite,host));
    if outcome.is_err(){let _=child.kill();let _=child.wait();}
    let status=outcome?;
    if !status.success(){ui::warn("Test stopped or could not finish. Completed rows remain saved; this is not a full pass.");}
    if report.exists(){show(store,&report)?;}else{ui::note("No results yet. Check peer reachability or create a new invitation.");ui::pause();}
    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn worker_log_retry_preserves_existing_logs()->Result<()>{
        let dir=tempfile::tempdir()?;
        let report=dir.path().join("session.report.json");
        let legacy=report.with_extension("worker.log");
        std::fs::write(&legacy,b"prior attempt")?;
        let(first,_)=worker_log(&report)?;
        let(second,_)=worker_log(&report)?;
        assert_ne!(first,second);
        assert_eq!(std::fs::read(legacy)?,b"prior attempt");
        assert!(!report.exists());
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(first)?.permissions().mode()&0o777,0o600);
        }
        Ok(())
    }
}
fn saved(store:&Store)->Result<()> {
    let directory=directory(store);
    let mut files=if directory.is_dir(){std::fs::read_dir(&directory)?.filter_map(|entry|entry.ok().map(|e|e.path())).filter(|path|path.file_name().is_some_and(|n|n.to_string_lossy().ends_with(".report.json"))).collect::<Vec<_>>()}else{vec![]};
    files.sort();files.reverse();
    if files.is_empty(){ui::note("No saved Mirage tests. Start on Iran or join from Foreign.");ui::pause();return Ok(());}
    let labels=files.iter().map(|path|match spoof_session::read_private::<Report>(path){Ok(report)=>format!("{}  {} -> {}  {} rows  {}",report.session,report.foreign,report.iran,report.iran_bound.len()+report.foreign_bound.len(),if report.finished{"complete sample"}else{"partial"}),Err(_)=>format!("{}  unreadable private report",path.file_name().unwrap().to_string_lossy())}).collect::<Vec<_>>();
    if let Some(index)=ui::choose("Saved tests",&labels,0)?{show(store,&files[index])?;}Ok(())
}
fn show(store:&Store,path:&Path)->Result<()> {
    let report:Report=spoof_session::read_private(path)?;
    ui::heading("Saved Mirage results",if report.finished{"Completed reachability sample; not a long-run stability guarantee"}else{"Partial run; do not interpret missing rows as successful"});
    if report.iran_bound.is_empty()&&report.foreign_bound.is_empty(){ui::note("No completed rows.");ui::pause();return Ok(());}
    if let Some((reverse,index))=super::mirage_screen::select(&report)?{
        let row=&if reverse{&report.foreign_bound}else{&report.iran_bound}[index];
        let actions=["Create a tunnel from this result","Retest this source/profile  extended sample, new invitation","Show both-direction details","Back"].map(str::to_string);
        match ui::choose("Result",&actions,0)?{
            Some(0)=>{
                ensure!(!reverse,"Select a Foreign -> Iran result to create a tunnel; the measured return path is chosen next.");
                ensure!(row.stage=="authenticated-interface-admission"&&row.error.is_none()&&row.received>0,"wait for a completed peer report before creating a tunnel from this result");
                super::wizard::from_mirage_result(store,&report,index)?;
            }
            Some(1)=>{
                ui::note("Start this retest on Iran. The other server must join with the new invitation; no SSH credentials or remote service changes are used.");
                if ui::confirm("This is the Iran server and I want to retest this source",false)?{
                    let(control,raw)=free_ports()?;
                    let returns=report.foreign_bound.iter().filter(|r|r.profile==row.profile&&r.error.is_none()&&r.received>0).map(|r|r.source).collect::<Vec<_>>();
                    let sources=if reverse {
                        report.iran_bound.iter().filter(|r|r.profile==row.profile&&r.error.is_none()&&r.received>0).map(|r|r.source).collect::<Vec<_>>()
                    }else{vec![row.source]};
                    ensure!(!sources.is_empty(),"No measured Foreign -> Iran source exists for this return profile. Start a new test with explicit candidates.");
                    let invite=Invitation::new(report.iran,report.foreign,sources,if reverse{vec![row.source]}else if returns.is_empty(){vec![report.iran]}else{returns},vec![row.profile],Depth::Extended,control,raw)?;
                    worker(store,invite,true)?;
                }
            }
            Some(2)=>{
                for(reverse,items)in [(false,&report.iran_bound),(true,&report.foreign_bound)]{
                    ui::heading(if reverse{"Iran -> Foreign"}else{"Foreign -> Iran"},"");
                    for index in Report::ranked(items){let item=&items[index];eprintln!("{} {:<8} received{}/{} return{}/{} p95{}",item.source,profile_name(item.profile),item.received,item.sent,item.raw_reply_received,item.sent,item.rtt_p95_ms.map(|v|format!("{v:.1}ms")).unwrap_or_else(||"-".into()));}
                }ui::pause();
            }
            _=>{}
        }
    }Ok(())
}
