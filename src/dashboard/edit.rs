//! Editing a saved tunnel from the dashboard: its forwarded ports (Iran end), its traffic limit and
//! the numeric settings the terminal manager offers for it. Changes are applied to the
//! configuration the same way the manager applies them; saving checks the result like any save.
use crate::{
    manager::{
        manage::{current_ports, current_proxy, with_ports},
        plan::{self, Protocol, apply_setting, format_ports, parse_ports, read_setting},
        tune::settings_of,
    },
    settings::{Place, Setting},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

fn place_word(place: Place) -> &'static str {
    match place {
        Place::Top => "top",
        Place::Listener => "listener",
        Place::Path => "path",
    }
}

fn protocol_word(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Both => "both",
    }
}

fn protocol_of(word: &str) -> Result<Protocol> {
    Ok(match word {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "both" => Protocol::Both,
        _ => bail!("protocol must be tcp, udp or both"),
    })
}

/// Whether the tunnel forwards ports itself (the Iran end of a port-forwarding tunnel).
fn has_ports(config: &Value) -> bool {
    config["mode"] == "server" && config["listeners"][0]["maps"].as_array().is_some_and(|m| !m.is_empty())
}

/// What the edit screen shows for a tunnel, with the current values.
pub fn editable(config: &Value) -> Result<Value> {
    let ports = if has_ports(config) {
        let (rules, protocol, _, several) = current_ports(config);
        json!({"text": format_ports(&rules), "protocol": protocol_word(protocol), "several_addresses": several,
               "proxy_protocol": current_proxy(config).unwrap_or(0)})
    } else {
        Value::Null
    };
    // The traffic limit and the scheduled restart have their own parts of the screen.
    let settings: Vec<Value> = settings_of(config)?
        .iter()
        .filter(|s| !s.name.starts_with("quota.") && !s.name.starts_with("schedule."))
        .map(|s| {
            json!({
                "name": s.name, "place": place_word(s.place), "unit": s.unit, "min": s.min, "max": s.max,
                "default": s.default, "value": read_setting(config, s), "description": s.description,
            })
        })
        .collect();
    Ok(json!({
        "ports": ports,
        "quota": {
            "limit_gb": config["quota"]["limit_gb"].as_u64().unwrap_or(0),
            "period_days": config["quota"]["period_days"].as_u64().unwrap_or(30),
        },
        "settings": settings,
        "restart_hours": config["schedule"]["restart_every_hours"].as_u64().unwrap_or(0),
    }))
}

/// The configuration with `changes` applied: `{"ports": {"text", "protocol"}, "quota": {"limit_gb",
/// "period_days"}, "settings": [{"name", "place", "value"}]}`; each part is optional, a setting
/// value of `null` goes back to its default. Every value is checked against its allowed range.
pub fn apply(config: &Value, changes: &Value) -> Result<Value> {
    let mut edited = config.clone();
    if let Some(ports) = changes.get("ports").filter(|p| !p.is_null()) {
        ensure!(has_ports(config), "this tunnel does not forward ports here");
        let text = ports["text"].as_str().context("ports.text is missing")?;
        let rules = parse_ports(text)?;
        ensure!(!rules.is_empty(), "give at least one port");
        let protocol = protocol_of(ports["protocol"].as_str().unwrap_or("tcp"))?;
        edited = with_ports(&edited, &rules, protocol);
    }
    if let Some(quota) = changes.get("quota").filter(|q| !q.is_null()) {
        let limit = quota["limit_gb"].as_u64().context("quota.limit_gb must be a whole number")?;
        let days = quota["period_days"].as_u64().unwrap_or(30);
        ensure!(limit <= 1_000_000, "the traffic limit must be 0 (none) to 1000000 GB");
        ensure!((1..=3650).contains(&days), "the period must be 1 to 3650 days");
        if limit == 0 {
            if let Some(object) = edited.as_object_mut() {
                object.remove("quota");
            }
        } else {
            edited["quota"] = json!({"limit_gb": limit, "period_days": days});
        }
    }
    if let Some(version) = changes.get("proxy_protocol").filter(|p| !p.is_null()) {
        ensure!(has_ports(config), "this tunnel does not forward ports here");
        let version = version.as_u64().filter(|v| *v <= 2).context("PROXY protocol must be 0 (off), 1 or 2")?;
        for map in edited["listeners"][0]["maps"].as_array_mut().into_iter().flatten() {
            if map["type"] == "udp" {
                continue;
            }
            if version == 0 {
                if let Some(object) = map.as_object_mut() {
                    object.remove("proxy_protocol");
                }
            } else {
                map["proxy_protocol"] = json!(version);
            }
        }
    }
    if let Some(hours) = changes.get("restart_hours").filter(|h| !h.is_null()) {
        let hours = hours.as_u64().filter(|h| *h <= 8760).context("the restart interval must be 0 (never) to 8760 hours")?;
        let setting = settings_of(config)?
            .into_iter()
            .find(|s| s.name == "schedule.restart_every_hours")
            .context("this tunnel has no scheduled restart setting")?;
        apply_setting(&mut edited, &setting, (hours > 0).then_some(hours))?;
    }
    if let Some(list) = changes.get("settings").and_then(Value::as_array) {
        let known: Vec<Setting> = settings_of(config)?;
        for change in list {
            let name = change["name"].as_str().context("a setting without a name")?;
            let place = change["place"].as_str().unwrap_or("top");
            let setting = known
                .iter()
                .find(|s| s.name == name && place_word(s.place) == place)
                .with_context(|| format!("{name} is not a setting of this tunnel"))?;
            let value = match &change["value"] {
                Value::Null => None,
                value => {
                    let value = value.as_u64().with_context(|| format!("{name} must be a whole number"))?;
                    ensure!(
                        (setting.min..=setting.max).contains(&value),
                        "{name} must be {} to {}",
                        setting.min,
                        setting.max
                    );
                    Some(value)
                }
            };
            apply_setting(&mut edited, setting, value)?;
        }
    }
    plan::check(&edited).context("the changed settings are not valid")?;
    Ok(edited)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iran() -> Value {
        json!({
            "mode": "server", "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "listeners": [{"addr": "0.0.0.0:7000", "transport": "tcp",
                "maps": [{"type": "tcp", "bind": "0.0.0.0:443", "target": "127.0.0.1:443"},
                         {"type": "udp", "bind": "0.0.0.0:9392", "target": "127.0.0.1:9392"}]}]
        })
    }

    #[test]
    fn the_edit_screen_lists_ports_limit_and_settings() {
        let screen = editable(&iran()).unwrap();
        assert_eq!(screen["ports"]["text"], "443, 9392");
        assert_eq!(screen["ports"]["protocol"], "both");
        assert_eq!(screen["quota"]["limit_gb"], 0);
        let names: Vec<&str> = screen["settings"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"stream_window"), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with("quota.")), "{names:?}");
        // A foreign end has no ports to edit.
        let foreign = json!({"mode": "client", "tunnel_key": iran()["tunnel_key"], "allowed_targets": ["127.0.0.1:443"],
            "paths": [{"addr": "203.0.113.10:7000", "transport": "tcp"}]});
        assert!(editable(&foreign).unwrap()["ports"].is_null());
    }

    #[test]
    fn changes_are_applied_checked_and_limited() {
        let config = iran();
        let edited = apply(&config, &json!({
            "ports": {"text": "443, 8443", "protocol": "tcp"},
            "quota": {"limit_gb": 500, "period_days": 30},
            "settings": [{"name": "stream_window", "place": "top", "value": 256}]
        }))
        .unwrap();
        let screen = editable(&edited).unwrap();
        assert_eq!(screen["ports"]["text"], "443, 8443");
        assert_eq!(screen["quota"]["limit_gb"], 500);
        assert_eq!(edited["stream_window"], 256);
        // PROXY protocol on the TCP maps only, and a scheduled restart.
        let more = apply(&edited, &json!({"proxy_protocol": 2, "restart_hours": 24})).unwrap();
        let maps = more["listeners"][0]["maps"].as_array().unwrap();
        assert!(maps.iter().all(|m| (m["type"] == "tcp") == (m["proxy_protocol"] == 2)), "{maps:?}");
        assert_eq!(more["schedule"]["restart_every_hours"], 24);
        let screen = editable(&more).unwrap();
        assert_eq!(screen["ports"]["proxy_protocol"], 2);
        assert_eq!(screen["restart_hours"], 24);
        let off = apply(&more, &json!({"proxy_protocol": 0, "restart_hours": 0})).unwrap();
        assert!(off["listeners"][0]["maps"].as_array().unwrap().iter().all(|m| m.get("proxy_protocol").is_none()));
        assert_eq!(editable(&off).unwrap()["restart_hours"], 0);
        assert!(apply(&more, &json!({"proxy_protocol": 3})).is_err());
        assert!(apply(&more, &json!({"restart_hours": 9000})).is_err());
        // Back to the default, and no limit.
        let back = apply(&edited, &json!({"quota": {"limit_gb": 0}, "settings": [{"name": "stream_window", "place": "top", "value": null}]})).unwrap();
        assert!(back.get("quota").is_none());
        assert!(back.get("stream_window").is_none());
        for bad in [
            json!({"settings": [{"name": "stream_window", "place": "top", "value": 999_999}]}),
            json!({"settings": [{"name": "rm -rf", "place": "top", "value": 1}]}),
            json!({"quota": {"limit_gb": 5, "period_days": 0}}),
            json!({"ports": {"text": "", "protocol": "tcp"}}),
            json!({"ports": {"text": "443", "protocol": "sctp"}}),
        ] {
            assert!(apply(&config, &bad).is_err(), "{bad}");
        }
    }
}
