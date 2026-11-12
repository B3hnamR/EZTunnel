//! Actions on every tunnel at once: start, stop, restart, delete, and one setting for all.
use super::plan::apply_setting;
use super::service::{self, State};
use super::store::Store;
use super::tune;
use super::ui;
use crate::settings::Setting;
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

/// What has to be done to a tunnel in a given state, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Start the existing service.
    Start,
    /// Write the service again and (re)start it; also creates a missing service.
    Install,
    Stop,
}

pub fn step_for(action: Action, state: State) -> Option<Step> {
    match (action, state) {
        (Action::Start, State::Running | State::Starting) => None,
        (Action::Start, State::NoService) => Some(Step::Install),
        (Action::Start, State::Stopped | State::Failed) => Some(Step::Start),
        (Action::Stop, State::Running | State::Starting) => Some(Step::Stop),
        (Action::Stop, _) => None,
        (Action::Restart, _) => Some(Step::Install),
    }
}

/// A setting that at least one saved tunnel offers, and the tunnels that offer it.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub setting: Setting,
    pub tunnels: Vec<String>,
}

/// Every numeric setting offered by some tunnel, in menu order, with the tunnels it applies to.
pub fn candidates(store: &Store) -> Result<Vec<Candidate>> {
    let mut list: Vec<Candidate> = Vec::new();
    for name in store.names()? {
        // One tunnel's file being unreadable must not hide the setting of every other one.
        let Ok(config) = store.read(&name) else {
            continue;
        };
        let Ok(settings) = tune::settings_of(&config) else {
            continue;
        };
        for setting in settings {
            match list
                .iter_mut()
                .find(|c| c.setting.name == setting.name && c.setting.place == setting.place)
            {
                Some(found) => found.tunnels.push(name.clone()),
                None => list.push(Candidate {
                    setting,
                    tunnels: vec![name.clone()],
                }),
            }
        }
    }
    Ok(list)
}

/// Sets (or with `None` resets to the default) one setting in each of the named tunnels. A
/// tunnel whose result would not pass the program's checks is left as it was.
pub fn set_everywhere(
    store: &Store,
    setting: &Setting,
    value: Option<u64>,
    tunnels: &[String],
) -> Vec<(String, Result<()>)> {
    tunnels
        .iter()
        .map(|name| {
            let result = store.read(name).and_then(|mut config| {
                apply_setting(&mut config, setting, value)?;
                store.save(name, &config)
            });
            (name.clone(), result)
        })
        .collect()
}

fn run(store: &Store, action: Action) -> Result<()> {
    if !store.system {
        ui::warn("This works on services, which need root and systemd.");
        return Ok(());
    }
    let mut touched = 0;
    for name in store.names()? {
        let Some(step) = step_for(action, service::state(store, &name)) else {
            ui::note(&format!("{name}: nothing to do"));
            continue;
        };
        let result = match step {
            Step::Start => service::start(&name),
            Step::Install => service::install(store, &name),
            Step::Stop => service::stop(&name),
        };
        match result {
            Ok(()) => {
                touched += 1;
                ui::ok(&name);
            }
            Err(error) => ui::fail(&format!("{name}: {error:#}")),
        }
    }
    ui::info(&format!("{touched} tunnel(s) changed"));
    Ok(())
}

fn delete_all(store: &Store) -> Result<()> {
    let names = store.names()?;
    ui::warn(&format!(
        "This stops and deletes ALL {} tunnel(s): {}",
        names.len(),
        names.join(", ")
    ));
    if !ui::confirm("Delete every tunnel?", false)?
        || !ui::confirm("Really delete them all? This cannot be undone.", false)?
    {
        return Ok(());
    }
    for name in &names {
        let result = (|| {
            if store.system {
                service::remove(name)?;
            }
            store.remove(name)
        })();
        match result {
            Ok(()) => ui::ok(&format!("Deleted {name}")),
            Err(error) => ui::fail(&format!("{name}: {error:#}")),
        }
    }
    Ok(())
}

fn change_setting(store: &Store) -> Result<()> {
    let candidates = candidates(store)?;
    if candidates.is_empty() {
        ui::info("There are no settings to change.");
        return Ok(());
    }
    let total = store.names()?.len();
    ui::note(
        "Pick a setting. It changes in every tunnel that has it; the others stay as they are.",
    );
    let labels: Vec<String> = candidates
        .iter()
        .map(|c| {
            format!(
                "{:<34} {}",
                c.setting.name,
                ui::dim(&format!("{} of {total} tunnels", c.tunnels.len()))
            )
        })
        .collect();
    let Some(choice) = ui::choose("Setting", &labels, 0)? else {
        return Ok(());
    };
    let candidate = &candidates[choice];
    let Some(value) = tune::ask_number_batch(&candidate.setting)? else {
        return Ok(());
    };
    let results = set_everywhere(store, &candidate.setting, value, &candidate.tunnels);
    let mut changed = Vec::new();
    for (name, result) in results {
        match result {
            Ok(()) => {
                ui::ok(&name);
                changed.push(name);
            }
            Err(error) => ui::fail(&format!("{name}: {error:#}")),
        }
    }
    // Only the ones already running: this is "pick up my setting change", not "start every
    // tunnel that has it" - a tunnel the operator stopped on purpose stays stopped.
    let running: Vec<&String> = changed
        .iter()
        .filter(|name| {
            matches!(
                service::state(store, name),
                State::Running | State::Starting
            )
        })
        .collect();
    if store.system && !running.is_empty() && ui::confirm("Restart the changed tunnels now?", true)?
    {
        for name in &running {
            if let Err(error) = service::install(store, name) {
                ui::fail(&format!("{name}: {error:#}"));
            }
        }
        ui::ok("Restarted");
    }
    Ok(())
}

/// The "All tunnels" screen.
pub fn menu(store: &Store) -> Result<()> {
    loop {
        ui::banner("All tunnels");
        let count = store.names()?.len();
        if count == 0 {
            ui::info("There are no tunnels yet.");
            ui::pause();
            return Ok(());
        }
        let items = vec![
            format!(
                "Start all          {}",
                ui::dim("the ones that are not running")
            ),
            format!(
                "Stop all           {}",
                ui::dim("the ones that are running")
            ),
            format!(
                "Restart all        {}",
                ui::dim("with their current settings")
            ),
            format!(
                "Change one setting {}",
                ui::dim("in every tunnel that has it")
            ),
            "Delete all".to_string(),
            ui::dim("← Back"),
        ];
        let Some(choice) = ui::choose(&format!("{count} tunnel(s)"), &items, 0)? else {
            return Ok(());
        };
        let result = match choice {
            0 => run(store, Action::Start),
            1 => run(store, Action::Stop),
            2 => run(store, Action::Restart),
            3 => change_setting(store),
            4 => delete_all(store),
            _ => return Ok(()),
        };
        if let Err(error) = result {
            if ui::is_back(&error) {
                continue;
            }
            ui::fail(&format!("{error:#}"));
        }
        ui::pause();
        if choice == 4 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::for_test(directory.path().to_path_buf());
        (directory, store)
    }

    fn client(port: u16) -> Value {
        json!({"mode":"client",
            "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "allowed_targets":["127.0.0.1:*"], "paths":[{"addr": format!("192.0.2.1:{port}")}]})
    }

    fn server() -> Value {
        json!({"mode":"server",
            "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "listeners":[{"addr":"0.0.0.0:7000"}]})
    }

    fn setting(name: &str) -> Setting {
        crate::settings::all()
            .into_iter()
            .find(|s| s.name == name && s.place == crate::settings::Place::Top)
            .unwrap()
    }

    #[test]
    fn each_action_only_touches_the_tunnels_it_applies_to() {
        use State::*;
        for state in [Running, Starting] {
            assert_eq!(step_for(Action::Start, state), None);
            assert_eq!(step_for(Action::Stop, state), Some(Step::Stop));
            assert_eq!(step_for(Action::Restart, state), Some(Step::Install));
        }
        for state in [Stopped, Failed] {
            assert_eq!(step_for(Action::Start, state), Some(Step::Start));
            assert_eq!(step_for(Action::Stop, state), None);
            assert_eq!(step_for(Action::Restart, state), Some(Step::Install));
        }
        // A tunnel without a service is created when started, and has nothing to stop.
        assert_eq!(step_for(Action::Start, NoService), Some(Step::Install));
        assert_eq!(step_for(Action::Stop, NoService), None);
        assert_eq!(step_for(Action::Restart, NoService), Some(Step::Install));
    }

    #[test]
    fn a_setting_is_offered_for_the_tunnels_that_have_it() {
        let (_directory, store) = store();
        store.save("a-client", &client(7000)).unwrap();
        store.save("b-server", &server()).unwrap();
        let list = candidates(&store).unwrap();
        let find = |name: &str| list.iter().find(|c| c.setting.name == name).unwrap();
        assert_eq!(find("heartbeat_sec").tunnels, ["a-client", "b-server"]);
        // Only a server limits handshakes, and the dial retry pause is the client's.
        assert_eq!(find("max_pending_handshakes").tunnels, ["b-server"]);
        assert_eq!(find("retry_interval").tunnels, ["a-client"]);
    }

    #[test]
    fn a_damaged_tunnel_file_is_skipped_but_does_not_hide_the_others_settings() {
        let (_directory, store) = store();
        store.save("a-client", &client(7000)).unwrap();
        store.save("b-server", &server()).unwrap();
        std::fs::write(store.path("b-server"), "not json").unwrap();
        let list = candidates(&store).unwrap();
        let find = |name: &str| list.iter().find(|c| c.setting.name == name).unwrap();
        assert_eq!(find("heartbeat_sec").tunnels, ["a-client"]);
        assert!(
            list.iter()
                .all(|c| !c.tunnels.contains(&"b-server".to_string()))
        );
    }

    #[test]
    fn one_setting_changes_everywhere_and_a_bad_result_leaves_that_tunnel_alone() {
        let (_directory, store) = store();
        store.save("a-client", &client(7000)).unwrap();
        store.save("b-server", &server()).unwrap();
        let names = vec!["a-client".to_string(), "b-server".to_string()];
        let results = set_everywhere(&store, &setting("heartbeat_sec"), Some(20), &names);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        for name in &names {
            assert_eq!(store.read(name).unwrap()["heartbeat_sec"], 20);
        }
        // 50 is not allowed with the default dead timeout (40): both are refused and unchanged.
        let results = set_everywhere(&store, &setting("heartbeat_sec"), Some(50), &names);
        assert!(results.iter().all(|(_, r)| r.is_err()));
        for name in &names {
            assert_eq!(store.read(name).unwrap()["heartbeat_sec"], 20);
        }
        // Back to the default removes the key.
        let results = set_everywhere(&store, &setting("heartbeat_sec"), None, &names);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        for name in &names {
            assert!(store.read(name).unwrap().get("heartbeat_sec").is_none());
        }
    }
}
