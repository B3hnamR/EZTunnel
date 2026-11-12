//! Named timing modes for the KCP and FEC carriers.
//!
//! KCP resends and acknowledges on a timer. A short timer and "no delay" give the lowest latency
//! and use the most CPU; a longer timer is gentler on a weak server. Operators think in modes,
//! not in six numbers, so the manager offers four, with the values popular in Iran-side tunnel
//! tools, and writes them into the carrier's ordinary settings. Nothing here changes the wire:
//! each side may use a different mode.
//!
//! The program's own defaults already sit at the fast end (a 10 ms timer with no delay for
//! plain KCP), so "Default" leaves every field unset, and the three gentler modes are mainly for
//! servers that run out of CPU.
use crate::config::Transport;
use serde_json::{Map, Value};

/// A timing mode. `Default` writes nothing and keeps the program's own values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpeedMode {
    #[default]
    Default,
    Normal,
    Fast,
    Fast2,
    Fast3,
}

/// The values behind a mode.
struct Timing {
    nodelay: bool,
    interval_ms: u32,
    resend: u16,
    congestion_control: bool,
    write_delay: bool,
    ack_no_delay: bool,
}

impl SpeedMode {
    pub const ALL: [SpeedMode; 5] = [
        SpeedMode::Default,
        SpeedMode::Normal,
        SpeedMode::Fast,
        SpeedMode::Fast2,
        SpeedMode::Fast3,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SpeedMode::Default => "default",
            SpeedMode::Normal => "normal",
            SpeedMode::Fast => "fast",
            SpeedMode::Fast2 => "fast2",
            SpeedMode::Fast3 => "fast3",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            SpeedMode::Default => "the program's own values (already fast; recommended)",
            SpeedMode::Normal => "40 ms timer, batches writes: lowest CPU, highest latency",
            SpeedMode::Fast => "30 ms timer, batches writes: low CPU, good for most links",
            SpeedMode::Fast2 => "20 ms timer, no batching, immediate acks: faster, more CPU",
            SpeedMode::Fast3 => "10 ms timer, no batching, immediate acks: fastest, most CPU",
        }
    }

    fn timing(self) -> Option<Timing> {
        let (nodelay, interval_ms, write_delay, ack_no_delay) = match self {
            SpeedMode::Default => return None,
            SpeedMode::Normal => (false, 40, true, false),
            SpeedMode::Fast => (false, 30, true, false),
            SpeedMode::Fast2 => (true, 20, false, true),
            SpeedMode::Fast3 => (true, 10, false, true),
        };
        Some(Timing {
            nodelay,
            interval_ms,
            resend: 2,
            congestion_control: false,
            write_delay,
            ack_no_delay,
        })
    }
}

/// Which carrier object holds the timing fields, and whether it has the batching fields.
fn target(transport: Transport) -> Option<(&'static str, bool)> {
    match transport {
        Transport::Kcp => Some(("kcp", false)),
        Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage => {
            Some(("fec", true))
        }
        _ => None,
    }
}

/// Whether a carrier has timing modes.
pub fn applies(transport: Transport) -> bool {
    target(transport).is_some()
}

/// The timing fields of the carrier object (the batching ones exist only for FEC).
fn fields(batching: bool) -> &'static [&'static str] {
    if batching {
        &[
            "nodelay",
            "interval_ms",
            "resend",
            "congestion_control",
            "write_delay",
            "ack_no_delay",
        ]
    } else {
        &["nodelay", "interval_ms", "resend", "congestion_control"]
    }
}

/// The listener or path object of a configuration (the one the wizard writes).
fn entry_mut(config: &mut Value) -> Option<&mut Value> {
    let key = if config["mode"] == "server" {
        "listeners"
    } else {
        "paths"
    };
    config.get_mut(key)?.get_mut(0)
}

/// Writes `mode` into a configuration. `Default` removes the timing fields again.
pub fn apply_config(config: &mut Value, transport: Transport, mode: SpeedMode) {
    let Some((key, batching)) = target(transport) else {
        return;
    };
    let Some(entry) = entry_mut(config).and_then(Value::as_object_mut) else {
        return;
    };
    let mut object = match entry.remove(key) {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    for field in fields(batching) {
        object.remove(*field);
    }
    if let Some(timing) = mode.timing() {
        object.insert("nodelay".into(), timing.nodelay.into());
        object.insert("interval_ms".into(), timing.interval_ms.into());
        object.insert("resend".into(), timing.resend.into());
        object.insert(
            "congestion_control".into(),
            timing.congestion_control.into(),
        );
        if batching {
            object.insert("write_delay".into(), timing.write_delay.into());
            object.insert("ack_no_delay".into(), timing.ack_no_delay.into());
        }
    }
    if !object.is_empty() {
        entry.insert(key.into(), Value::Object(object));
    }
}

/// The mode a configuration is in: `Some(Default)` when no timing field is set, the named mode
/// when the fields match one exactly, and `None` for custom values.
pub fn detect(config: &Value, transport: Transport) -> Option<SpeedMode> {
    let (key, batching) = target(transport)?;
    let list = if config["mode"] == "server" {
        "listeners"
    } else {
        "paths"
    };
    let current = timing_fields(config[list][0].get(key), batching);
    if current.is_empty() {
        return Some(SpeedMode::Default);
    }
    SpeedMode::ALL
        .into_iter()
        .filter(|mode| *mode != SpeedMode::Default)
        .find(|mode| {
            let mut probe = Value::Object(Map::new());
            probe["mode"] = config["mode"].clone();
            probe[list] = Value::Array(vec![Value::Object(Map::new())]);
            apply_config(&mut probe, transport, *mode);
            timing_fields(probe[list][0].get(key), batching) == current
        })
}

/// Only the timing fields of a carrier object, so unrelated settings do not matter.
fn timing_fields(object: Option<&Value>, batching: bool) -> Map<String, Value> {
    let Some(object) = object.and_then(Value::as_object) else {
        return Map::new();
    };
    fields(batching)
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .map(|v| ((*field).to_string(), v.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn client(transport: &str) -> Value {
        json!({"mode": "client", "paths": [{"addr": "192.0.2.1:7000", "transport": transport}]})
    }

    #[test]
    fn only_kcp_and_fec_carriers_have_modes() {
        for transport in [
            Transport::Kcp,
            Transport::FecUdp,
            Transport::FecRaw,
            Transport::FecRawGaming,
        ] {
            assert!(applies(transport), "{transport:?}");
        }
        for transport in [
            Transport::Tcp,
            Transport::Wss,
            Transport::Xhttp,
            Transport::Tun,
        ] {
            assert!(!applies(transport), "{transport:?}");
        }
    }

    #[test]
    fn a_mode_writes_the_timing_fields_and_detect_reads_it_back() {
        for (transport, name) in [(Transport::FecUdp, "fec-udp"), (Transport::Kcp, "kcp")] {
            for mode in SpeedMode::ALL {
                let mut config = client(name);
                apply_config(&mut config, transport, mode);
                assert_eq!(detect(&config, transport), Some(mode), "{name} {mode:?}");
            }
        }
        let mut config = client("fec-udp");
        apply_config(&mut config, Transport::FecUdp, SpeedMode::Fast2);
        assert_eq!(
            config["paths"][0]["fec"],
            json!({"nodelay": true, "interval_ms": 20, "resend": 2,
                   "congestion_control": false, "write_delay": false, "ack_no_delay": true})
        );
    }

    #[test]
    fn plain_kcp_has_no_batching_fields_and_default_removes_everything_it_wrote() {
        let mut config = client("kcp");
        apply_config(&mut config, Transport::Kcp, SpeedMode::Normal);
        let object = config["paths"][0]["kcp"].as_object().unwrap();
        assert!(!object.contains_key("write_delay") && !object.contains_key("ack_no_delay"));
        assert_eq!(object["interval_ms"], 40);
        apply_config(&mut config, Transport::Kcp, SpeedMode::Default);
        assert!(config["paths"][0].get("kcp").is_none());
    }

    #[test]
    fn other_settings_in_the_carrier_object_survive_a_change_of_mode() {
        let mut config = client("fec-udp");
        config["paths"][0]["fec"] = json!({"mtu": 1200, "sndwnd": 4096});
        apply_config(&mut config, Transport::FecUdp, SpeedMode::Fast);
        apply_config(&mut config, Transport::FecUdp, SpeedMode::Fast3);
        // Unrelated fields do not hide the mode.
        assert_eq!(detect(&config, Transport::FecUdp), Some(SpeedMode::Fast3));
        assert_eq!(config["paths"][0]["fec"]["mtu"], 1200);
        assert_eq!(config["paths"][0]["fec"]["sndwnd"], 4096);
        apply_config(&mut config, Transport::FecUdp, SpeedMode::Default);
        assert_eq!(
            config["paths"][0]["fec"],
            json!({"mtu": 1200, "sndwnd": 4096})
        );
    }

    #[test]
    fn hand_edited_values_are_reported_as_custom_and_servers_use_their_listener() {
        let mut config = client("fec-udp");
        config["paths"][0]["fec"] = json!({"interval_ms": 25});
        assert_eq!(detect(&config, Transport::FecUdp), None);
        let mut server = json!({"mode": "server", "listeners": [{"addr": "0.0.0.0:7000",
                                "transport": "kcp"}]});
        apply_config(&mut server, Transport::Kcp, SpeedMode::Fast3);
        assert_eq!(server["listeners"][0]["kcp"]["interval_ms"], 10);
        assert_eq!(detect(&server, Transport::Kcp), Some(SpeedMode::Fast3));
        // A carrier without modes is left alone.
        let mut tcp = client("tcp");
        apply_config(&mut tcp, Transport::Tcp, SpeedMode::Fast3);
        assert_eq!(tcp, client("tcp"));
    }
}
