//! Export and import of all tunnels as one file: a backup, or a move to another server.
//!
//! The file holds the tunnels' ordinary configuration, which includes their secret tunnel keys,
//! so it is written readable by its owner only and must be kept like the keys themselves.
use super::store::Store;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use std::path::Path;

/// Marker and format number of an export file.
const MARKER: &str = "eztunnel_export";
const FORMAT: u64 = 1;

/// All saved tunnels as one document, and the names of any that could not be read (one damaged
/// file must not keep every other tunnel out of the backup).
pub fn export(store: &Store) -> Result<(Value, Vec<String>)> {
    let mut tunnels = Map::new();
    let mut skipped = Vec::new();
    for name in store.names()? {
        match store.read(&name) {
            Ok(config) => {
                tunnels.insert(name, config);
            }
            Err(_) => skipped.push(name),
        }
    }
    Ok((
        json!({
            MARKER: FORMAT,
            "program": env!("CARGO_PKG_VERSION"),
            "tunnels": tunnels,
        }),
        skipped,
    ))
}

/// Writes the export to `path` (mode 0600). Returns how many tunnels it holds and the names of
/// any that could not be read and so are missing from it.
pub fn write_export(store: &Store, path: &Path) -> Result<(usize, Vec<String>)> {
    let (document, skipped) = export(store)?;
    let count = document["tunnels"].as_object().map_or(0, Map::len);
    ensure!(count > 0, "there are no tunnels to export");
    let mut text = serde_json::to_string_pretty(&document)?;
    text.push('\n');
    // The file is written under a new name (created exclusively, so it can neither be an existing
    // file nor a link planted by someone else) and renamed over `path`. An older export is
    // replaced only once the new one is complete, and a link at `path` is replaced, not followed.
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "export".into());
    let temp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let written = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options
            .open(&temp)
            .with_context(|| format!("write {}", temp.display()))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp, path).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written?;
    Ok((count, skipped))
}

/// Reads an export file into (name, configuration) pairs, in file order.
pub fn parse_export(text: &str) -> Result<Vec<(String, Value)>> {
    let document: Value = serde_json::from_str(text).context("the file is not valid JSON")?;
    ensure!(
        document.get(MARKER).and_then(Value::as_u64) == Some(FORMAT),
        "this is not an EZTunnel export file (made by 'Export all tunnels')"
    );
    let Some(tunnels) = document.get("tunnels").and_then(Value::as_object) else {
        bail!("the export file has no tunnels");
    };
    ensure!(!tunnels.is_empty(), "the export file has no tunnels");
    let mut list = Vec::new();
    for (name, config) in tunnels {
        super::plan::check_name(name)
            .with_context(|| format!("the export holds a tunnel with the invalid name {name:?}"))?;
        ensure!(config.is_object(), "tunnel {name} is not a configuration");
        list.push((name.clone(), config.clone()));
    }
    Ok(list)
}

/// What an import did, per tunnel name.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub imported: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Saves the tunnels of an export. Existing tunnels are kept unless `replace` is set; every
/// configuration is checked like at start-up before it is saved, and one bad tunnel does not stop
/// the others.
pub fn import(store: &Store, tunnels: &[(String, Value)], replace: bool) -> Report {
    let mut report = Report::default();
    for (name, config) in tunnels {
        if store.exists(name) && !replace {
            report.skipped.push(name.clone());
            continue;
        }
        match store.save(name, config) {
            Ok(()) => report.imported.push(name.clone()),
            Err(error) => report.failed.push((name.clone(), format!("{error:#}"))),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::for_test(directory.path().to_path_buf());
        (directory, store)
    }

    fn sample(port: u16) -> Value {
        json!({"mode":"client",
            "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "allowed_targets":["127.0.0.1:*"], "paths":[{"addr": format!("192.0.2.1:{port}")}]})
    }

    /// An export never writes through a link and never leaves a half-written file behind.
    #[cfg(unix)]
    #[test]
    fn an_export_replaces_a_link_instead_of_writing_through_it() {
        use std::os::unix::fs::PermissionsExt;
        let (_one, source) = store();
        source.save("alpha", &sample(7000)).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let target = directory.path().join("export.json");
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        write_export(&source, &target).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            !std::fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o077,
            0
        );
        assert!(parse_export(&std::fs::read_to_string(&target).unwrap()).is_ok());
        // Nothing but the export is left in the directory.
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn a_damaged_tunnel_file_is_left_out_but_does_not_block_the_rest() {
        let (_one, source) = store();
        source.save("alpha", &sample(7000)).unwrap();
        source.save("beta", &sample(7001)).unwrap();
        // Bypass save()'s own validation to simulate on-disk damage (a bad hand edit, a crash).
        std::fs::write(source.path("beta"), "not json").unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let (count, skipped) = write_export(&source, file.path()).unwrap();
        assert_eq!(count, 1);
        assert_eq!(skipped, ["beta"]);
        let tunnels = parse_export(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
        assert_eq!(
            tunnels.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(),
            ["alpha"]
        );
    }

    #[test]
    fn all_tunnels_survive_an_export_and_an_import_on_another_server() {
        let (_one, source) = store();
        let (a, b) = (sample(7000), sample(7001));
        source.save("alpha", &a).unwrap();
        source.save("beta", &b).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(write_export(&source, file.path()).unwrap(), (2, vec![]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(file.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the export holds secret keys");
        }
        let tunnels = parse_export(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
        assert_eq!(
            tunnels.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        let (_two, target) = store();
        let report = import(&target, &tunnels, false);
        assert_eq!(report.imported, ["alpha", "beta"]);
        assert!(report.skipped.is_empty() && report.failed.is_empty());
        assert_eq!(target.read("alpha").unwrap(), a);
        assert_eq!(target.read("beta").unwrap(), b);
    }

    #[test]
    fn an_existing_tunnel_is_kept_unless_replacing_is_asked_for() {
        let (_one, target) = store();
        let old = sample(7000);
        target.save("alpha", &old).unwrap();
        let tunnels = vec![("alpha".to_string(), sample(7777))];
        let report = import(&target, &tunnels, false);
        assert_eq!(report.skipped, ["alpha"]);
        assert_eq!(target.read("alpha").unwrap(), old);
        let report = import(&target, &tunnels, true);
        assert_eq!(report.imported, ["alpha"]);
        assert_eq!(target.read("alpha").unwrap(), tunnels[0].1);
    }

    #[test]
    fn a_broken_tunnel_is_reported_and_the_others_are_still_imported() {
        let (_one, target) = store();
        let mut broken = sample(7000);
        broken["paths"][0]["addr"] = json!("not an address");
        let tunnels = vec![
            ("bad".to_string(), broken),
            ("good".to_string(), sample(7001)),
        ];
        let report = import(&target, &tunnels, false);
        assert_eq!(report.imported, ["good"]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "bad");
        assert!(!target.exists("bad"));
    }

    #[test]
    fn files_that_are_not_exports_are_refused() {
        assert!(parse_export("not json").is_err());
        assert!(parse_export("{}").is_err());
        assert!(parse_export(r#"{"eztunnel_export":2,"tunnels":{"a":{}}}"#).is_err());
        assert!(parse_export(r#"{"eztunnel_export":1,"tunnels":{}}"#).is_err());
        assert!(parse_export(r#"{"eztunnel_export":1,"tunnels":{"../evil":{}}}"#).is_err());
        assert!(parse_export(r#"{"eztunnel_export":1,"tunnels":{"a":"text"}}"#).is_err());
        assert!(parse_export(r#"{"eztunnel_export":1,"tunnels":{"a":{"mode":"client"}}}"#).is_ok());
    }

    #[test]
    fn nothing_is_exported_when_there_are_no_tunnels() {
        let (_one, empty) = store();
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(write_export(&empty, file.path()).is_err());
    }
}
