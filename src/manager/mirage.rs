//! Consent must be local, not copied from a pairing code or inferred from defaults.
use super::{
    plan::{MiragePlan, unicast_ipv4},
    ui,
};
use anyhow::Result;
use std::net::Ipv4Addr;

pub(super) fn accepted(selection: Option<usize>) -> bool {
    selection == Some(0)
}
pub(super) fn consent() -> Result<bool> {
    ui::without_history(|| {
        ui::heading("Mirage - Experimental Transport", "");
        ui::warn(crate::mirage::DISCLAIMER);
        let labels = vec![crate::mirage::ACCEPT.into(), crate::mirage::BACK.into()];
        Ok(accepted(ui::choose("Acknowledgement", &labels, 1)?))
    })
}
fn optional_ip(prompt: &str, current: Option<Ipv4Addr>) -> Result<Option<Ipv4Addr>> {
    let initial = current.map_or("none".into(), |ip| ip.to_string());
    let text = ui::ask(prompt, Some(&initial), |t: &String| {
        if t == "none" {
            Ok(())
        } else {
            unicast_ipv4(t).map(|_| ()).map_err(|e| e.to_string())
        }
    })?;
    Ok(if text == "none" {
        None
    } else {
        Some(unicast_ipv4(&text)?)
    })
}
pub(super) fn settings(current: Option<&MiragePlan>) -> Result<MiragePlan> {
    if current.is_none_or(|plan|plan.advanced.is_some()) {
        let mut raw=serde_json::json!({"mirage":current.and_then(|p|p.advanced.clone())});
        advanced(&mut raw)?;
        return Ok(MiragePlan{spoof_src_ip:Ipv4Addr::UNSPECIFIED,spoof_dst_ip:None,gateway_ip:current.and_then(|p|p.gateway_ip),peer_mac:current.and_then(|p|p.peer_mac.clone()),advanced:Some(raw["mirage"].clone())});
    }
    legacy_settings(current)
}
pub(super) fn legacy_settings(current:Option<&MiragePlan>)->Result<MiragePlan>{
    ui::note(
        "These are this endpoint's settings only. The real peer IPv4 remains the routing target. No unspoofed fallback is used.",
    );
    let source = ui::ask(
        "Spoofed source IPv4 for this endpoint",
        current.map(|p| p.spoof_src_ip.to_string()).as_deref(),
        |t: &String| unicast_ipv4(t).map(|_| ()).map_err(|e| e.to_string()),
    )?;
    let mut result = MiragePlan {
        spoof_src_ip: unicast_ipv4(&source)?,
        advanced:None,
        spoof_dst_ip: current.and_then(|p| p.spoof_dst_ip),
        gateway_ip: current.and_then(|p| p.gateway_ip),
        peer_mac: current.and_then(|p| p.peer_mac.clone()),
    };
    if ui::confirm(
        "Configure advanced destination / next-hop overrides?",
        false,
    )? {
        result.spoof_dst_ip = optional_ip(
            "Spoofed destination IPv4 ('none' = real peer)",
            result.spoof_dst_ip,
        )?;
        result.gateway_ip = optional_ip(
            "Next-hop gateway IPv4 ('none' = routing table)",
            result.gateway_ip,
        )?;
        let text = ui::ask(
            "Next-hop MAC ('auto' = ARP resolution)",
            Some(result.peer_mac.as_deref().unwrap_or("auto")),
            |t: &String| {
                if t == "auto" {
                    Ok(())
                } else {
                    crate::raw_packet::parse_mac(t)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                }
            },
        )?;
        result.peer_mac = (text != "auto").then_some(text);
    }
    Ok(result)
}
pub(super) fn local_settings(
    interface: Option<&str>,
    local: Option<Ipv4Addr>,
) -> Result<(Option<String>, Option<Ipv4Addr>)> {
    let device = ui::ask(
        "Network interface ('auto' = route detection)",
        Some(interface.unwrap_or("auto")),
        |t: &String| {
            if t == "auto"
                || (1..=15).contains(&t.len())
                    && t.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                Ok(())
            } else {
                Err("enter an interface name or auto".into())
            }
        },
    )?;
    let local = optional_ip(
        "Real local IPv4 ('none' = detect, not the spoofed address)",
        local,
    )?;
    Ok(((device != "auto").then_some(device), local))
}

fn source_text(raw:&serde_json::Value)->String{
    if let Some(source)=raw["spoof_src_ip"].as_str(){return source.into();}
    let sources=raw["mirage"]["source_pool"].as_array().map(|values|values.iter().filter_map(|v|v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    if sources.is_empty(){"real".into()}else{sources}
}
fn receive_text(raw:&serde_json::Value)->String{
    let sources=raw["mirage"]["expected_sources"].as_array().map(|values|values.iter().filter_map(|v|v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    if sources.is_empty(){"peer".into()}else{sources}
}
fn apply_basic(raw:&mut serde_json::Value,up:&str,down:&str,source:&str,receive:&str)->Result<()> {
    let mut settings=raw["mirage"].as_object().cloned().unwrap_or_default();
    settings.insert("uplink".into(),up.into());settings.insert("downlink".into(),down.into());
    settings.insert("allow_real_source".into(),(source=="real").into());
    settings.insert("source_pool".into(),serde_json::to_value(if source=="real"{vec![]}else{parse_ip_list(source)?})?);
    settings.insert("expected_sources".into(),serde_json::to_value(if receive=="peer"{vec![]}else{parse_ip_list(receive)?})?);
    settings.entry("echo_mode").or_insert_with(||"replies".into());
    let raw=raw.as_object_mut().ok_or_else(||anyhow::anyhow!("raw settings must be an object"))?;
    raw.remove("spoof_src_ip");raw.remove("spoof_dst_ip");raw.remove("proto58_mode");
    raw.insert("mirage_acknowledgement".into(),"experimental-v2".into());raw.insert("mirage".into(),settings.into());Ok(())
}
pub(super) fn advanced(raw:&mut serde_json::Value)->Result<()> {
    ui::heading("Mirage setup", "Choose packet types and source IPs; advanced tuning stays optional");
    let mut draft=raw.clone();
    let profiles=["udp","tcp","icmp","gre","ipip","bip","icmpv6"].map(str::to_string);
    let current=draft["mirage"]["uplink"].as_str().unwrap_or("udp");
    let up=profiles[ui::choose_required("Foreign -> Iran packet type",&profiles,profiles.iter().position(|p|p==current).unwrap_or(0))?].clone();
    let current=draft["mirage"]["downlink"].as_str().unwrap_or(&up);
    let down=profiles[ui::choose_required("Iran -> Foreign packet type",&profiles,profiles.iter().position(|p|p==current).unwrap_or(0))?].clone();
    ui::note("Source addresses below belong to THIS endpoint. If you do not know which IPs work, cancel and use Tools -> Mirage source tests first.");
    let source=ui::ask("This server sends as ('real' or permitted spoof IPs)",Some(&source_text(&draft)),|v:&String|if v=="real"{Ok(())}else{parse_ip_list(v).map(|_|()).map_err(|e|e.to_string())})?;
    let receive=ui::ask("Other server sends as ('peer' or its selected spoof IPs)",Some(&receive_text(&draft)),|v:&String|if v=="peer"{Ok(())}else{parse_ip_list(v).map(|_|()).map_err(|e|e.to_string())})?;
    apply_basic(&mut draft,&up,&down,&source,&receive)?;
    loop{
        let choices=["Use these settings","Advanced tuning  optional; current values are preserved","Back"].map(str::to_string);
        match ui::choose("Mirage settings",&choices,0)?{
            Some(0)=>{*raw=draft;return Ok(());}
            Some(1)=>expert(&mut draft)?,_=>return Err(ui::Back.into()),
        }
    }
}
fn expert(raw:&mut serde_json::Value)->Result<()> {
    ui::heading("Mirage v2 - directional profiles", "Real destination, transmit source and receive source are separate");
    ui::note("Uplink means Foreign -> Iran; downlink means Iran -> Foreign, independent of physical dialing. Only use source addresses you are permitted to test. Profiles and IPs can succeed differently in each direction.");
    let profiles=["tcp","udp","icmp","icmpv6","gre","ipip","bip"].map(str::to_string);
    let choose=|prompt:&str,current:Option<&str>|->Result<String>{
        let index=profiles.iter().position(|v|Some(v.as_str())==current).unwrap_or(0);
        let selected=ui::choose_required(prompt,&profiles,index)?;Ok(profiles[selected].clone())
    };
    let up=choose("Uplink packet profile",raw["mirage"]["uplink"].as_str())?;
    let down=choose("Downlink packet profile",raw["mirage"]["downlink"].as_str())?;
    let source_default=source_text(raw);
    let pool=ui::ask("This endpoint's spoof source list ('real' = explicitly send real IP)",Some(&source_default),|value:&String|{
        if value=="real"{return Ok(());}
        parse_ip_list(value).map(|_|()).map_err(|e|e.to_string())
    })?;
    let receive_default=receive_text(raw);
    let receive=ui::ask("Expected incoming spoof source list ('peer' = real peer_ip)",Some(&receive_default),|value:&String|{
        if value=="peer"{return Ok(());}parse_ip_list(value).map(|_|()).map_err(|e|e.to_string())
    })?;
    let modes=["Split request/reply", "Requests both ways", "Replies both ways (no automatic echo reply)"].map(str::to_string);
    let echo_default=match raw["mirage"]["echo_mode"].as_str(){Some("split")=>0,Some("requests")=>1,_=>2};
    let echo=match ui::choose_required("Echo header mode",&modes,echo_default)?{0=>"split",1=>"requests",_=>"replies"};
    let padding_default=raw["mirage"]["padding_max"].as_u64().unwrap_or(0).to_string();
    let padding=ui::ask("Maximum random padding bytes (0..256)",Some(&padding_default),|value:&String|if value.parse::<u16>().is_ok_and(|n|n<=256){Ok(())}else{Err("enter0..256".into())})?.parse::<u16>()?;
    let tls=ui::confirm("Enable cosmetic fake TLS prefix? (not actual TLS)",raw["mirage"]["fake_tls"].as_bool().unwrap_or(false))?;
    let number=|label:&str,initial:&str,max:u16|->Result<u16>{Ok(ui::ask(label,Some(initial),move|value:&String|if value.parse::<u16>().is_ok_and(|n|n<=max){Ok(())}else{Err(format!("enter0..{max}"))})?.parse()?) };
    let ttl=number("Outer TTL (0 = existing default)",&raw["mirage"]["ttl"].as_u64().unwrap_or(0).to_string(),255)?;
    let dscp_default=raw["mirage"]["dscp"].as_u64().map(|v|v.to_string()).unwrap_or_else(||"default".into());
    let dscp=ui::ask("Outer DSCP ('default' = existing profile default, or0..63)",Some(&dscp_default),|value:&String|if value=="default"||value.parse::<u8>().is_ok_and(|n|n<=63){Ok(())}else{Err("enter default or0..63".into())})?;
    let range=if ui::confirm("Shuffle TCP/UDP source ports in a bounded range?",raw["mirage"]["source_port_range"].is_array())?{
        let first_default=raw["mirage"]["source_port_range"][0].as_u64().unwrap_or(41000).to_string();
        let first=ui::ask("First source port",Some(&first_default),|value:&String|if value.parse::<u16>().is_ok_and(|n|n>=1024){Ok(())}else{Err("enter1024..65535".into())})?.parse::<u16>()?;
        let last_default=raw["mirage"]["source_port_range"][1].as_u64().unwrap_or(u64::from(first.saturating_add(15))).to_string();
        let last=ui::ask("Last source port (at most 256 ports)",Some(&last_default),move|value:&String|if value.parse::<u16>().is_ok_and(|n|n>=first&&u32::from(n)-u32::from(first)<256){Ok(())}else{Err("enter bounded range".into())})?.parse::<u16>()?;
        Some([first,last])
    }else{None};
    let redundancy=if ui::confirm("Add extra datagram redundancy? (bandwidth cost; existing KCP/FEC stays enabled)",raw["mirage"]["redundancy"].is_object())?{
        let data_default=raw["mirage"]["redundancy"]["data"].as_u64().unwrap_or(6).to_string();
        let parity_default=raw["mirage"]["redundancy"]["parity"].as_u64().unwrap_or(2).to_string();
        let data=ui::ask("Data shards per group (1..16)",Some(&data_default),|value:&String|if value.parse::<u8>().is_ok_and(|n|(1..=16).contains(&n)){Ok(())}else{Err("enter1..16".into())})?.parse::<u8>()?;
        let parity=ui::ask("Repair shards per group (1..4)",Some(&parity_default),|value:&String|if value.parse::<u8>().is_ok_and(|n|(1..=4).contains(&n)){Ok(())}else{Err("enter1..4".into())})?.parse::<u8>()?;
        Some(crate::spoof::Redundancy{data,parity})
    }else{None};
    let object=raw.as_object_mut().ok_or_else(||anyhow::anyhow!("raw settings must be an object"))?;
    object.remove("spoof_src_ip");object.remove("spoof_dst_ip");object.remove("proto58_mode");
    object.insert("mirage_acknowledgement".into(),"experimental-v2".into());
    object.insert("mirage".into(),serde_json::json!({"uplink":up,"downlink":down,"allow_real_source":pool=="real",
        "source_pool":if pool=="real"{Vec::new()}else{parse_ip_list(&pool)?},
        "expected_sources":if receive=="peer"{Vec::new()}else{parse_ip_list(&receive)?},
        "echo_mode":echo,"padding_max":padding,"fake_tls":tls,"ttl":if ttl==0{None}else{Some(ttl as u8)},
        "dscp":if dscp=="default"{None}else{Some(dscp.parse::<u8>()?)},"source_port_range":range,"redundancy":redundancy}));
    Ok(())
}
fn parse_ip_list(value:&str)->Result<Vec<Ipv4Addr>>{
    crate::spoof_session::parse_sources(value)
}

pub(super) fn tester(store:&super::store::Store)->Result<()> {super::mirage_flow::menu(store)}

pub(super) fn manual_tester()->Result<()> {
    ui::banner("Directional spoof tester");
    ui::note("The settings file must contain an explicit candidate list, profiles, real peer/local IPs, and a shared tunnel key, mode 0600. It never adds firewall rules or scans a range. Run Listen on the receiving host first, then Send on the other host. Repeat with roles reversed to test each direction.");
    let choices=["Listen for one authenticated run","Send candidate/profile probes","Create private tester settings","Back"].map(str::to_string);
    let Some(choice)=ui::choose("Tester action",&choices,0)?else{return Ok(());};
    if choice==2{return tester_settings();}
    if choice>2{return Ok(());}
    let file=ui::ask("Private tester settings JSON path",None,|value:&String|if std::path::Path::new(value).is_file(){Ok(())}else{Err("file does not exist".into())})?;
    let endpoint=ui::ask(if choice==0{"Control listen IP:port"}else{"Receiving peer's control IP:port"},None,|value:&String|if value.parse::<std::net::SocketAddr>().is_ok(){Ok(())}else{Err("enter explicit IP:port".into())})?;
    let mut command=std::process::Command::new(std::env::current_exe()?);command.args(["spooftest",if choice==0{"listen"}else{"run"},"--config",&file,if choice==0{"--bind"}else{"--peer"},&endpoint]);
    if choice==1 {
        let output=ui::ask("Private JSON result path",Some("/root/eztunnel-spoof-results.json"),|value:&String|if !value.is_empty(){Ok(())}else{Err("enter path".into())})?;
        command.args(["--output",&output]);
    }
    ui::note("Results separate one-way authenticated receipt from raw return RTT. No receipt does not locate the provider/path drop. Use Ctrl+C to cancel.");
    let status=ui::with_interrupt_for_children(||command.status())?;
    if status.success(){ui::ok("Bounded spoof test completed");}else{ui::warn("Test ended with an error or cancellation; retain the partial result ledger");}
    ui::pause();Ok(())
}

fn tester_settings()->Result<()> {
    ui::heading("Private spoof tester settings", "Create a separate file on each endpoint; share the same tunnel key and candidate list");
    let address=|prompt:&str|ui::ask(prompt,None,|value:&String|unicast_ipv4(value).map(|_|()).map_err(|e|e.to_string()));
    let local=address("This server's REAL IPv4")?;let peer=address("The other server's REAL IPv4")?;
    let interface=ui::ask("Network interface ('auto' uses routing table)",Some("auto"),|value:&String|if value=="auto"||(1..=15).contains(&value.len())&&value.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)){Ok(())}else{Err("invalid interface".into())})?;
    let port=ui::ask("Unused raw probe port (1024..65534, same on both hosts)",Some("45670"),|value:&String|if value.parse::<u16>().is_ok_and(|n|(1024..65535).contains(&n)){Ok(())}else{Err("enter1024..65534".into())})?.parse::<u16>()?;
    let candidates=ui::ask("Explicit permitted candidate source IPv4 list (comma separated)",None,|value:&String|parse_ip_list(value).map(|_|()).map_err(|e|e.to_string()))?;
    let key=ui::ask("Shared tunnel key (generate with 'eztunnel key' if needed)",None,|value:&String|crate::tunnel_key::TunnelKey::parse(value).map(|_|()).map_err(|e|e.to_string()))?;
    let destination=ui::ask("Private output settings path (must not already exist)",Some("/root/eztunnel-spooftest.json"),|value:&String|if !value.is_empty()&&!std::path::Path::new(value).exists(){Ok(())}else{Err("choose a new file path".into())})?;
    let mut raw=serde_json::json!({"local_ip":local,"peer_ip":peer,"l4_port":port});
    if interface!="auto"{raw["interface"]=interface.into();}
    let value=serde_json::json!({"tunnel_key":key,"raw":raw,"candidates":parse_ip_list(&candidates)?,"profiles":["tcp","udp","icmp","icmpv6","gre","ipip","bip"],"attempts":5,"delay_ms":150,"receive_ms":2000});
    use std::io::Write;
    let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
    let mut file=options.open(&destination)?;file.write_all(&serde_json::to_vec_pretty(&value)?)?;file.sync_all()?;
    ui::ok("Private mode 0600 tester settings written; no tests or network changes started");ui::pause();Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_acceptance_proceeds() {
        assert!(accepted(Some(0)));
        assert!(!accepted(Some(1)));
        assert!(!accepted(None));
    }
    #[test]
    fn basic_edit_keeps_advanced_values_and_source_defaults()->Result<()> {
        let mut raw=serde_json::json!({"profile":"tcp","mirage":{"source_pool":["198.51.100.1"],"expected_sources":["192.0.2.2"],"echo_mode":"split","padding_max":64,"fake_tls":true,"ttl":93,"dscp":10,"source_port_range":[41000,41015],"redundancy":{"data":6,"parity":2}}});
        assert_eq!(source_text(&raw),"198.51.100.1");assert_eq!(receive_text(&raw),"192.0.2.2");
        let source=source_text(&raw);let receive=receive_text(&raw);
        let before=raw["mirage"].clone();apply_basic(&mut raw,"udp","icmp",&source,&receive)?;
        for field in ["source_pool","expected_sources","echo_mode","padding_max","fake_tls","ttl","dscp","source_port_range","redundancy"]{assert_eq!(raw["mirage"][field],before[field],"{field}");}
        assert_eq!(raw["mirage_acknowledgement"],"experimental-v2");Ok(())
    }
}
