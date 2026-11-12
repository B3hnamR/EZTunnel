//! "Optimize this server": kernel network settings that help a long-distance tunnel, applied
//! only after the operator confirms, kept across reboots, and fully reversible.
//!
//! A numeric limit (`AtLeast`, `AtMost`, `MaxField`) only changes when the current value is
//! worse than the recommendation; a value the operator already set higher (or lower, for
//! `AtMost`) is left alone. A setting with no ordered "better" (`Exact`: a queueing discipline or
//! congestion-control algorithm by name) is instead always set to the recommended value when it
//! differs. The previous values are saved so that Undo restores them exactly.
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Applied at boot after the manager's `60-eztunnel.conf`, so its smaller buffer limits for
/// KCP/FEC tunnels never replace the ones set here.
pub const SYSCTL_FILE: &str = "/etc/sysctl.d/61-eztunnel-optimize.conf";
/// The name used by 0.5.3 to 0.6.0. It sorted before `60-eztunnel.conf`, which then lowered
/// the buffer limits again at every boot. Removed when the optimization is applied or undone.
const LEGACY_SYSCTL_FILE: &str = "/etc/sysctl.d/60-eztunnel-optimize.conf";
const MODULES_FILE: &str = "/etc/modules-load.d/eztunnel-bbr.conf";
const BACKUP_FILE: &str = "/etc/eztunnel/optimize-backup.json";

/// Where the optimizer reads and writes. Tests point it at a scratch directory.
struct Files {
    sysctl: PathBuf,
    legacy_sysctl: PathBuf,
    modules: PathBuf,
    backup: PathBuf,
    /// Root of the kernel settings, `/proc/sys` on a real machine.
    proc: PathBuf,
}

impl Files {
    fn system() -> Self {
        Self {
            sysctl: SYSCTL_FILE.into(),
            legacy_sysctl: LEGACY_SYSCTL_FILE.into(),
            modules: MODULES_FILE.into(),
            backup: BACKUP_FILE.into(),
            proc: "/proc/sys".into(),
        }
    }

    fn proc_path(&self, key: &str) -> PathBuf {
        self.proc.join(key.replace('.', "/"))
    }

    fn read_proc(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.proc_path(key))
            .ok()
            .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
    }
}

/// How a recommended value compares with the current one.
#[derive(Clone, Copy)]
enum Rule {
    /// Must be exactly this value.
    Exact,
    /// A number; only raise it.
    AtLeast,
    /// A number; only lower it.
    AtMost,
    /// Three numbers (min default max); only raise the maximum.
    MaxField,
}

struct Tweak {
    key: &'static str,
    value: &'static str,
    rule: Rule,
    why: &'static str,
}

const TWEAKS: [Tweak; 16] = [
    Tweak {
        key: "net.core.default_qdisc",
        value: "fq",
        rule: Rule::Exact,
        why: "packet pacing queue that BBR works best with",
    },
    Tweak {
        key: "net.ipv4.tcp_congestion_control",
        value: "bbr",
        rule: Rule::Exact,
        why: "keeps speed on long, lossy links (measured 3-12 -> 19 MB/s foreign -> Iran)",
    },
    Tweak {
        key: "net.ipv4.tcp_slow_start_after_idle",
        value: "0",
        rule: Rule::Exact,
        why: "a connection keeps its speed after a pause instead of starting slow again",
    },
    Tweak {
        key: "net.ipv4.tcp_mtu_probing",
        value: "1",
        rule: Rule::Exact,
        why: "avoids connections that stall when large packets are silently dropped",
    },
    Tweak {
        key: "net.core.rmem_max",
        value: "33554432",
        rule: Rule::AtLeast,
        why: "largest receive buffer a socket may use (32 MB)",
    },
    Tweak {
        key: "net.core.wmem_max",
        value: "33554432",
        rule: Rule::AtLeast,
        why: "largest send buffer a socket may use (32 MB)",
    },
    Tweak {
        key: "net.ipv4.tcp_rmem",
        value: "4096 131072 33554432",
        rule: Rule::MaxField,
        why: "lets TCP grow its receive window to full speed on long links",
    },
    Tweak {
        key: "net.ipv4.tcp_wmem",
        value: "4096 65536 33554432",
        rule: Rule::MaxField,
        why: "lets TCP grow its send buffer to full speed on long links",
    },
    Tweak {
        key: "net.ipv4.tcp_notsent_lowat",
        value: "16384",
        rule: Rule::Exact,
        why: "less queueing delay under load",
    },
    Tweak {
        key: "net.ipv4.tcp_fastopen",
        value: "3",
        rule: Rule::Exact,
        why: "faster connection setup",
    },
    Tweak {
        key: "net.core.somaxconn",
        value: "8192",
        rule: Rule::AtLeast,
        why: "more connections may wait to be accepted when many users arrive at once",
    },
    Tweak {
        key: "net.core.netdev_max_backlog",
        value: "16384",
        rule: Rule::AtLeast,
        why: "fewer drops when packets arrive in bursts",
    },
    Tweak {
        key: "net.ipv4.tcp_max_syn_backlog",
        value: "8192",
        rule: Rule::AtLeast,
        why: "more half-open connections during busy moments",
    },
    Tweak {
        key: "net.ipv4.tcp_fin_timeout",
        value: "15",
        rule: Rule::AtMost,
        why: "closed connections free their resources sooner when many users come and go",
    },
    Tweak {
        key: "net.ipv4.udp_rmem_min",
        value: "16384",
        rule: Rule::AtLeast,
        why: "every UDP socket gets at least 16 KB to receive into (KCP, FEC, forwarded UDP)",
    },
    Tweak {
        key: "net.ipv4.udp_wmem_min",
        value: "16384",
        rule: Rule::AtLeast,
        why: "every UDP socket gets at least 16 KB to send from",
    },
];

/// One setting that would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub key: String,
    pub current: String,
    pub wanted: String,
    pub why: String,
}

fn read_proc(key: &str) -> Option<String> {
    Files::system().read_proc(key)
}

fn numbers(text: &str) -> Vec<u64> {
    text.split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect()
}

/// The value to set, or `None` when the current one is already as good.
fn wanted(rule: Rule, current: &str, value: &str) -> Option<String> {
    match rule {
        Rule::Exact => (current != value).then(|| value.to_string()),
        Rule::AtLeast => {
            let (now, want) = (numbers(current), numbers(value));
            match (now.first(), want.first()) {
                (Some(now), Some(want)) if now >= want => None,
                _ => Some(value.to_string()),
            }
        }
        Rule::AtMost => {
            let (now, want) = (numbers(current), numbers(value));
            match (now.first(), want.first()) {
                (Some(now), Some(want)) if now <= want => None,
                _ => Some(value.to_string()),
            }
        }
        Rule::MaxField => {
            let (now, want) = (numbers(current), numbers(value));
            if now.len() == 3 && want.len() == 3 {
                if now[2] >= want[2] {
                    None
                } else {
                    Some(format!("{} {} {}", now[0], now[1], want[2]))
                }
            } else {
                Some(value.to_string())
            }
        }
    }
}

/// Changes worth making, given a way to read current values. Settings this kernel does not
/// have are skipped; BBR is only offered when the kernel can provide it.
fn plan_with(read: impl Fn(&str) -> Option<String>, bbr: bool) -> Vec<Change> {
    TWEAKS
        .iter()
        .filter(|t| bbr || t.key != "net.ipv4.tcp_congestion_control")
        .filter_map(|t| {
            let current = read(t.key)?;
            let wanted = wanted(t.rule, &current, t.value)?;
            Some(Change {
                key: t.key.to_string(),
                current,
                wanted,
                why: t.why.to_string(),
            })
        })
        .collect()
}

/// Whether the kernel lists BBR as usable right now.
fn bbr_listed() -> bool {
    read_proc("net.ipv4.tcp_available_congestion_control")
        .is_some_and(|list| list.split_whitespace().any(|name| name == "bbr"))
}

/// Whether BBR can be offered: listed already, or available as a kernel module. Looking is all
/// this does; a preview must not change the machine, so nothing is loaded here.
fn bbr_available() -> bool {
    bbr_listed()
        || std::process::Command::new("modinfo")
            .args(["-n", "tcp_bbr"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
}

/// Whether applying these changes needs the BBR module loaded first.
fn needs_bbr_module(changes: &[Change], listed: bool) -> bool {
    !listed
        && changes
            .iter()
            .any(|c| c.key == "net.ipv4.tcp_congestion_control")
}

pub fn plan() -> Vec<Change> {
    plan_with(read_proc, bbr_available())
}

/// Whether optimizations from this program are in place.
pub fn applied() -> bool {
    let files = Files::system();
    files.sysctl.exists() || files.legacy_sysctl.exists()
}

/// Applies the changes now and keeps them across reboots. Returns the keys that could not be
/// set (for example inside a container that does not allow it).
pub fn apply(changes: &[Change]) -> Result<Vec<String>> {
    // Only now, when the operator has confirmed, may the kernel module be loaded.
    if needs_bbr_module(changes, bbr_listed()) {
        let _ = std::process::Command::new("modprobe")
            .arg("tcp_bbr")
            .stderr(std::process::Stdio::null())
            .status();
    }
    apply_in(&Files::system(), changes)
}

/// Writes `contents` to `path` as a temp file in the same directory, then renames it into place:
/// a crash mid-write leaves either the old file or the new one, never a truncated mix of both.
fn write_atomic(path: &std::path::Path, contents: &str) -> Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("write {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))
}

/// The values saved from before the first optimization. A missing file means none has run yet
/// (start from empty); a present-but-damaged one is a hard error instead of being silently
/// treated as empty, which would make Undo restore the already-optimized values as if they were
/// the original ones. `undo_in` treats the same file the same way, for the same reason.
fn load_backup(path: &std::path::Path) -> Result<BTreeMap<String, String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).with_context(|| {
            format!(
                "{} holds the original values from before the last optimization, but is damaged; \
                 fix or remove it by hand before optimizing again, or Undo will not be able to \
                 restore the true original values",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn apply_in(files: &Files, changes: &[Change]) -> Result<Vec<String>> {
    // Keep the values from before the first optimization, so Undo returns to the original.
    let mut backup = load_backup(&files.backup)?;
    for change in changes {
        backup
            .entry(change.key.clone())
            .or_insert_with(|| change.current.clone());
    }
    if let Some(dir) = files.backup.parent() {
        std::fs::create_dir_all(dir).context("create /etc/eztunnel")?;
    }
    write_atomic(&files.backup, &serde_json::to_string_pretty(&backup)?)
        .context("save the previous values")?;
    let mut failed = Vec::new();
    for change in changes {
        if std::fs::write(files.proc_path(&change.key), &change.wanted).is_err() {
            failed.push(change.key.clone());
        }
    }
    // The persistent file lists every recommended value now in force, including ones set by
    // an earlier run.
    let mut lines = vec![
        "# Written by EZTunnel: Tools -> Optimize this server. Undo removes this file.".to_string(),
    ];
    for tweak in &TWEAKS {
        if let Some(value) = files.read_proc(tweak.key) {
            let ours = backup.contains_key(tweak.key);
            if ours {
                lines.push(format!("{} = {value}", tweak.key));
            }
        }
    }
    // The kernel settings above are already live by this point even if what follows fails - keep
    // going and report it through `failed` instead of leaving it a silent, unrecoverable gap
    // between what is active now and what is restored at the next boot.
    if let Err(error) = write_atomic(&files.sysctl, &(lines.join("\n") + "\n")) {
        tracing::warn!(%error, "could not write the sysctl file that keeps the optimization across a reboot");
        failed.push("reboot persistence (the sysctl file)".to_string());
    }
    let _ = std::fs::remove_file(&files.legacy_sysctl);
    if changes
        .iter()
        .any(|c| c.key == "net.ipv4.tcp_congestion_control")
        && let Err(error) = write_atomic(&files.modules, "tcp_bbr\n")
    {
        tracing::warn!(%error, "could not write the module-loading file that keeps BBR loaded across a reboot");
        failed.push("reboot persistence (the kernel module list)".to_string());
    }
    Ok(failed)
}

/// Restores the values from before the optimization and removes its files.
pub fn undo() -> Result<usize> {
    undo_checked(&Files::system())
}
fn undo_checked(files: &Files) -> Result<usize> {
    let restored = undo_in(files)?;
    let remaining = load_backup(&files.backup)?.len();
    anyhow::ensure!(
        remaining == 0,
        "restored {restored} setting(s), but {remaining} could not be restored; original values are retained for another Undo attempt"
    );
    Ok(restored)
}

/// A kernel setting name like `net.core.rmem_max`. The backup file is read as root, and a key that
/// is a path (`/etc/...`, `../..`) would make `Path::join` leave `/proc/sys` altogether.
fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn undo_in(files: &Files) -> Result<usize> {
    let backup = load_backup(&files.backup)?;
    let mut restored = 0;
    // What could not be put back stays in the backup, so Undo can be run again.
    let mut left = BTreeMap::new();
    for (key, value) in &backup {
        if valid_key(key) && std::fs::write(files.proc_path(key), value).is_ok() {
            restored += 1;
        } else if valid_key(key) {
            left.insert(key.clone(), value.clone());
        }
    }
    for file in [&files.sysctl, &files.legacy_sysctl, &files.modules] {
        let _ = std::fs::remove_file(file);
    }
    if left.is_empty() {
        let _ = std::fs::remove_file(&files.backup);
    } else {
        write_atomic(&files.backup, &serde_json::to_string_pretty(&left)?)
            .context("keep the values that could not be restored")?;
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bbr_module_is_loaded_only_when_applying_a_bbr_change_the_kernel_does_not_list() {
        let change = |key: &str| Change {
            key: key.into(),
            current: "x".into(),
            wanted: "y".into(),
            why: String::new(),
        };
        let bbr = [change("net.ipv4.tcp_congestion_control")];
        let other = [change("net.core.somaxconn")];
        assert!(needs_bbr_module(&bbr, false));
        assert!(
            !needs_bbr_module(&bbr, true),
            "already listed: nothing to load"
        );
        assert!(
            !needs_bbr_module(&other, false),
            "no BBR change: nothing to load"
        );
        assert!(!needs_bbr_module(&[], false));
    }

    fn reader(values: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn only_worse_values_change() {
        let read = reader(&[
            ("net.ipv4.tcp_congestion_control", "cubic"),
            ("net.core.default_qdisc", "fq"),
            ("net.core.rmem_max", "67108864"),
            ("net.core.wmem_max", "212992"),
            ("net.ipv4.tcp_rmem", "4096 87380 6291456"),
            ("net.ipv4.tcp_wmem", "4096 16384 67108864"),
        ]);
        let changes = plan_with(read, true);
        let keys: Vec<&str> = changes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "net.ipv4.tcp_congestion_control",
                "net.core.wmem_max",
                "net.ipv4.tcp_rmem"
            ]
        );
        // Only the maximum of a triple is raised; the other two stay.
        assert_eq!(changes[2].wanted, "4096 87380 33554432");
    }

    #[test]
    fn at_most_values_only_go_down() {
        let lower = reader(&[("net.ipv4.tcp_fin_timeout", "10")]);
        assert!(plan_with(lower, true).is_empty());
        let higher = reader(&[("net.ipv4.tcp_fin_timeout", "60")]);
        let changes = plan_with(higher, true);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].wanted, "15");
    }

    #[test]
    fn bbr_is_not_offered_when_the_kernel_lacks_it() {
        let read = reader(&[("net.ipv4.tcp_congestion_control", "cubic")]);
        assert!(plan_with(read, false).is_empty());
    }

    #[test]
    fn an_already_optimized_server_needs_nothing() {
        let values: Vec<(&str, &str)> = TWEAKS.iter().map(|t| (t.key, t.value)).collect();
        assert!(plan_with(reader(&values), true).is_empty());
    }

    /// systemd-sysctl applies files in name order and the last value wins. The manager's
    /// buffer file asks for less than the optimizer, so it must come first.
    #[test]
    fn the_optimizer_file_is_applied_after_the_manager_buffer_file() {
        let name = |path: &str| std::path::Path::new(path).file_name().unwrap().to_owned();
        assert!(name(SYSCTL_FILE) > name(super::super::service::BUFFER_SYSCTL_FILE));
        assert!(name(LEGACY_SYSCTL_FILE) < name(super::super::service::BUFFER_SYSCTL_FILE));
    }

    fn scratch(root: &std::path::Path) -> Files {
        Files {
            sysctl: root.join("sysctl.d/61-eztunnel-optimize.conf"),
            legacy_sysctl: root.join("sysctl.d/60-eztunnel-optimize.conf"),
            modules: root.join("modules-load.d/eztunnel-bbr.conf"),
            backup: root.join("eztunnel/optimize-backup.json"),
            proc: root.join("proc"),
        }
    }

    #[test]
    fn a_backup_cannot_make_undo_write_outside_the_kernel_settings() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let files = scratch(directory.path());
        std::fs::create_dir_all(directory.path().join("eztunnel"))?;
        std::fs::create_dir_all(directory.path().join("proc/net/core"))?;
        let outside = directory.path().join("outside");
        let backup = serde_json::json!({
            outside.to_string_lossy(): "pwned",
            "../outside": "pwned",
            "net.core.rmem_max": "212992",
        });
        std::fs::write(&files.backup, backup.to_string())?;
        assert_eq!(undo_in(&files)?, 1);
        assert!(!outside.exists() && !directory.path().join("proc/outside").exists());
        assert_eq!(
            std::fs::read_to_string(files.proc_path("net.core.rmem_max"))?,
            "212992"
        );
        assert!(!files.backup.exists(), "nothing valid was left to restore");
        assert!(valid_key("net.ipv4.tcp_rmem") && !valid_key("net..x") && !valid_key("/etc/x"));
        Ok(())
    }

    #[test]
    fn a_damaged_backup_is_a_hard_error_for_both_apply_and_undo() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let files = scratch(directory.path());
        std::fs::create_dir_all(directory.path().join("eztunnel"))?;
        std::fs::create_dir_all(directory.path().join("proc/net/core"))?;
        std::fs::write(files.proc_path("net.core.rmem_max"), "212992\n")?;
        std::fs::write(&files.backup, "not json")?;
        let changes = plan_with(|key| files.read_proc(key), true);
        // Neither path may silently treat a present-but-damaged backup as if it held nothing:
        // apply must not overwrite it with post-change values believing they were the original,
        // and undo has nothing trustworthy to restore from either.
        assert!(apply_in(&files, &changes).is_err());
        assert!(undo_in(&files).is_err());
        // The damaged file itself is untouched, so the operator can still inspect or fix it.
        assert_eq!(std::fs::read_to_string(&files.backup)?, "not json");
        Ok(())
    }

    #[test]
    fn values_that_could_not_be_restored_stay_in_the_backup() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let files = scratch(directory.path());
        std::fs::create_dir_all(directory.path().join("eztunnel"))?;
        std::fs::create_dir_all(directory.path().join("proc/net/core"))?;
        // net/ipv4 does not exist, so that write fails.
        let backup =
            serde_json::json!({"net.core.rmem_max": "212992", "net.ipv4.tcp_rmem": "4096"});
        std::fs::write(&files.backup, backup.to_string())?;
        assert_eq!(undo_in(&files)?, 1);
        let kept: BTreeMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&files.backup)?)?;
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["net.ipv4.tcp_rmem"]);
        let error = undo_checked(&files).unwrap_err();
        assert!(format!("{error:#}").contains("could not be restored"));
        assert!(files.backup.exists());
        Ok(())
    }

    #[test]
    fn apply_then_undo_restores_everything_and_removes_every_file() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let files = scratch(directory.path());
        for dir in [
            "sysctl.d",
            "modules-load.d",
            "proc/net/core",
            "proc/net/ipv4",
        ] {
            std::fs::create_dir_all(directory.path().join(dir))?;
        }
        std::fs::write(files.proc_path("net.core.rmem_max"), "212992\n")?;
        std::fs::write(
            files.proc_path("net.ipv4.tcp_congestion_control"),
            "cubic\n",
        )?;
        // A tunnel optimized by 0.6.0 still has the old file name.
        std::fs::write(&files.legacy_sysctl, "net.core.rmem_max = 33554432\n")?;
        let changes = plan_with(|key| files.read_proc(key), true);
        assert_eq!(changes.len(), 2, "{changes:?}");

        assert!(apply_in(&files, &changes)?.is_empty());
        assert_eq!(
            files.read_proc("net.core.rmem_max").as_deref(),
            Some("33554432")
        );
        let persistent = std::fs::read_to_string(&files.sysctl)?;
        assert!(
            persistent.contains("net.core.rmem_max = 33554432"),
            "{persistent}"
        );
        assert!(persistent.contains("net.ipv4.tcp_congestion_control = bbr"));
        assert!(
            !files.legacy_sysctl.exists(),
            "the old file name is cleaned up"
        );
        assert!(files.modules.exists());

        assert_eq!(undo_in(&files)?, 2);
        assert_eq!(
            files.read_proc("net.core.rmem_max").as_deref(),
            Some("212992")
        );
        assert_eq!(
            files
                .read_proc("net.ipv4.tcp_congestion_control")
                .as_deref(),
            Some("cubic")
        );
        for file in [
            &files.sysctl,
            &files.legacy_sysctl,
            &files.modules,
            &files.backup,
        ] {
            assert!(!file.exists(), "{} was left behind", file.display());
        }
        Ok(())
    }
}
