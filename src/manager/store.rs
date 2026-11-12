//! Where tunnels live on disk: one checked configuration file per tunnel.
use super::plan::check_name;
use crate::config::Config;
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// System account the tunnel services run as.
pub const SERVICE_USER: &str = "eztunnel";

pub struct Store {
    root: PathBuf,
    /// Running as root with systemd: tunnels become system services. Otherwise (a test
    /// directory given in `EZTUNNEL_HOME`) configurations are only written.
    pub system: bool,
}

impl Store {
    pub fn open() -> Result<Self> {
        if let Some(home) = std::env::var_os("EZTUNNEL_HOME") {
            let root = PathBuf::from(home);
            create_private_dir(&root)?;
            return Ok(Self {
                root,
                system: is_root() && Path::new("/run/systemd/system").exists(),
            });
        }
        if !is_root() {
            bail!("the tunnel manager changes system services; run it as root: sudo eztunnel");
        }
        let root = PathBuf::from("/etc/eztunnel");
        create_private_dir(&root)?;
        Ok(Self {
            root,
            system: Path::new("/run/systemd/system").exists(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A store in a test directory: tunnels are only written, no services are touched.
    #[cfg(test)]
    pub(crate) fn for_test(root: PathBuf) -> Self {
        Self {
            root,
            system: false,
        }
    }

    /// Whether this is the real installation (`/etc/eztunnel`) and not a test directory chosen
    /// with `EZTUNNEL_HOME`. Only the real one owns the program and the system files.
    pub fn is_system_install(&self) -> bool {
        self.root == Path::new("/etc/eztunnel")
    }

    fn dir(&self) -> PathBuf {
        self.root.join("tunnels")
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir().join(format!("{name}.json"))
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    pub fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let entries = match fs::read_dir(self.dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(names),
            Err(error) => return Err(error).context("read the tunnel directory"),
        };
        for entry in entries {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".json")
                && check_name(stem).is_ok()
            {
                names.push(stem.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn read(&self, name: &str) -> Result<Value> {
        let text =
            fs::read_to_string(self.path(name)).with_context(|| format!("read tunnel {name}"))?;
        serde_json::from_str(&text).with_context(|| format!("tunnel {name} is not valid JSON"))
    }

    /// Checks a configuration the same way the service will, then replaces the tunnel's file.
    /// The previous version is kept as `NAME.json.bak`.
    pub fn save(&self, name: &str, config: &Value) -> Result<()> {
        check_name(name)?;
        create_private_dir(&self.dir())?;
        let mut text = serde_json::to_string_pretty(config)?;
        text.push('\n');
        let candidate = self.dir().join(format!(".{name}.json.new"));
        write_private(&candidate, text.as_bytes())?;
        if let Err(error) = check_file(&candidate) {
            let _ = fs::remove_file(&candidate);
            return Err(error);
        }
        let target = self.path(name);
        if target.exists() {
            if let Err(error)=atomic_private(&self.dir().join(format!("{name}.json.bak")),&fs::read(&target)?){
                let _=fs::remove_file(&candidate);return Err(error.context("keep the previous configuration"));
            }
        }
        fs::rename(&candidate, &target).context("replace the configuration")?;
        self.give_to_service(&target);
        Ok(())
    }

    /// Whether the tunnel has a previous version (`NAME.json.bak`) to go back to.
    pub fn has_previous(&self, name: &str) -> bool {
        self.dir().join(format!("{name}.json.bak")).exists()
    }

    /// Puts the previous version back. It is checked like any save, and the version being
    /// replaced becomes the new previous one, so going back can be undone the same way.
    pub fn restore_previous(&self, name: &str) -> Result<()> {
        check_name(name)?;
        let path = self.dir().join(format!("{name}.json.bak"));
        let text = fs::read_to_string(&path).context("there is no previous version")?;
        let value: Value =
            serde_json::from_str(&text).context("the previous version is damaged")?;
        self.save(name, &value)
    }

    /// Writes a candidate next to the tunnel for editing by hand.
    pub fn draft(&self, name: &str) -> Result<PathBuf> {
        let draft = self.dir().join(format!(".{name}.json.edit"));
        fs::copy(self.path(name), &draft).context("copy the configuration for editing")?;
        set_private(&draft)?;
        Ok(draft)
    }

    /// Replaces a tunnel with a draft that passed `check_file`.
    pub fn adopt(&self, name: &str, draft: &Path) -> Result<()> {
        let value: Value = serde_json::from_str(&fs::read_to_string(draft)?)?;
        self.save(name, &value)?;
        let _ = fs::remove_file(draft);
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        fs::remove_file(self.path(name)).with_context(|| format!("delete tunnel {name}"))?;
        let _ = fs::remove_file(self.dir().join(format!("{name}.json.bak")));
        // An edit that was never finished holds the whole configuration, tunnel key included.
        let _ = fs::remove_file(self.dir().join(format!(".{name}.json.edit")));
        Ok(())
    }

    /// Makes root the owner of the directories and a configuration file again (legacy
    /// builds run their services as root, with a limited capability set that cannot read a
    /// file owned by the former service account).
    #[cfg(unix)]
    pub fn give_to_root(&self, file: &Path) {
        if !self.system {
            return;
        }
        for path in [self.root.as_path(), &self.dir(), file] {
            let _ = std::process::Command::new("chown").arg("root:root").arg(path).status();
        }
    }

    /// Lets the service account read the directories and a configuration file.
    pub fn give_to_service(&self, file: &Path) {
        if self.system && user_exists(SERVICE_USER) {
            for path in [self.root.as_path(), &self.dir(), file] {
                let _ = std::process::Command::new("chown")
                    .arg(format!("{SERVICE_USER}:{SERVICE_USER}"))
                    .arg(path)
                    .status();
            }
        }
    }
}

/// The checks the service runs at start: structure, tunnel key, permissions and TLS files.
pub fn check_file(path: &Path) -> Result<Config> {
    let config = Config::load(path)?;
    config.private_key()?;
    crate::transport::validate_tls_config(&config)?;
    config.ensure_fixed_ports()?;
    Ok(config)
}

pub fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    false
}

pub fn user_exists(name: &str) -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub(super) fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

/// Writes `bytes` to `path` readable by its owner only (0600): used for anything holding a
/// secret or, like a checker report, data the tool exists to keep off other local accounts.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        // The tunnels directory can be writable by the service account (give_to_service); refuse
        // to write through a symlink planted at this path instead of following it elsewhere.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_private(path)?;
    ensure!(path.exists(), "configuration was not written");
    Ok(())
}

fn atomic_private(path:&Path,bytes:&[u8])->Result<()>{
    use std::io::Write;
    let mut nonce=[0;8];crate::stealth::random_bytes(&mut nonce)?;
    let temporary=path.with_file_name(format!(".backup-{}.tmp",hex::encode(nonce)));
    let mut options=fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
    let mut file=options.open(&temporary)?;
    let result=(||->Result<()>{file.write_all(bytes)?;file.sync_all()?;fs::rename(&temporary,path)?;Ok(())})();
    if result.is_err(){let _=fs::remove_file(&temporary);}result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store {
            root: directory.path().to_path_buf(),
            system: false,
        };
        (directory, store)
    }

    #[test]
    fn deleting_a_tunnel_deletes_its_unfinished_edit_with_the_key() {
        let (_directory, store) = store();
        store
            .save(
                "alpha",
                &serde_json::json!({"mode":"client",
                    "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
                    "allowed_targets":["127.0.0.1:*"], "paths":[{"addr":"192.0.2.1:7000"}]}),
            )
            .unwrap();
        let draft = store.draft("alpha").unwrap();
        assert!(draft.exists());
        store.remove("alpha").unwrap();
        assert!(!draft.exists(), "the draft kept the tunnel key");
        assert!(!store.path("alpha").exists());
    }

    #[test]
    fn only_etc_eztunnel_counts_as_the_system_install() {
        let (_directory, test_store) = store();
        assert!(!test_store.is_system_install());
        let real = Store {
            root: "/etc/eztunnel".into(),
            system: true,
        };
        assert!(real.is_system_install());
    }

    fn sample() -> Value {
        serde_json::json!({"mode":"client",
            "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "allowed_targets":["127.0.0.1:*"], "paths":[{"addr":"192.0.2.1:7000"}]})
    }

    #[test]
    fn the_previous_settings_can_be_put_back_and_the_step_undone() {
        let (_directory, store) = store();
        let mut first = sample();
        first["paths"][0]["addr"] = serde_json::json!("192.0.2.1:7000");
        let mut second = sample();
        second["paths"][0]["addr"] = serde_json::json!("192.0.2.1:7001");
        // Nothing to go back to before a second save.
        store.save("t", &first).unwrap();
        assert!(!store.has_previous("t"));
        assert!(store.restore_previous("t").is_err());
        store.save("t", &second).unwrap();
        assert!(store.has_previous("t"));
        let port = |store: &Store| -> String {
            let text = std::fs::read_to_string(store.path("t")).unwrap();
            let value: Value = serde_json::from_str(&text).unwrap();
            value["paths"][0]["addr"].as_str().unwrap().to_string()
        };
        assert_eq!(port(&store), "192.0.2.1:7001");
        store.restore_previous("t").unwrap();
        assert_eq!(port(&store), "192.0.2.1:7000");
        // The version that was replaced is now the previous one: going back can be undone.
        store.restore_previous("t").unwrap();
        assert_eq!(port(&store), "192.0.2.1:7001");
        // A damaged backup is refused and leaves the current file alone.
        std::fs::write(store.dir().join("t.json.bak"), "{ not json").unwrap();
        assert!(store.restore_previous("t").is_err());
        assert_eq!(port(&store), "192.0.2.1:7001");
    }

    #[test]
    fn saving_checks_keeps_a_backup_and_lists() {
        let (_directory, store) = store();
        assert!(store.names().unwrap().is_empty());
        store.save("first", &sample()).unwrap();
        store.save("first", &sample()).unwrap();
        assert!(store.dir().join("first.json.bak").exists());
        let mut broken = sample();
        broken["paths"][0]["addr"] = serde_json::json!("not an address");
        assert!(store.save("second", &broken).is_err());
        assert!(!store.exists("second"));
        assert_eq!(store.names().unwrap(), vec!["first".to_string()]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.path("first"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        store.remove("first").unwrap();
        assert!(store.names().unwrap().is_empty());
    }
    #[test]
    fn failed_backup_replacement_keeps_current_configuration_bytes(){
        let(_directory,store)=store();store.save("job",&sample()).unwrap();let old=fs::read(store.path("job")).unwrap();
        fs::create_dir(store.dir().join("job.json.bak")).unwrap();let mut changed=sample();changed["paths"][0]["addr"]="192.0.2.1:7777".into();
        assert!(store.save("job",&changed).is_err());assert_eq!(fs::read(store.path("job")).unwrap(),old);
        assert!(store.dir().join("job.json.bak").is_dir());assert!(!store.dir().join(".job.json.new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn saving_refuses_to_write_through_a_symlinked_candidate_file() {
        let (directory, store) = store();
        let outside = directory.path().join("outside.txt");
        fs::write(&outside, "do not touch").unwrap();
        fs::create_dir_all(store.dir()).unwrap();
        std::os::unix::fs::symlink(&outside, store.dir().join(".victim.json.new")).unwrap();
        assert!(store.save("victim", &sample()).is_err());
        assert_eq!(fs::read_to_string(&outside).unwrap(), "do not touch");
        assert!(!store.exists("victim"));
    }
}
