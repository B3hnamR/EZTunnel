//! Maintenance from the dashboard: official releases (found, downloaded and checked on the
//! dashboard's server the way the installer checks them), installing one on a server through the
//! updater, rollback, and backups of the tunnel configurations.
use crate::manager::{backup, store::Store, update};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

pub const REPOSITORY: &str = "B3hnamR/EZTunnel";
const MEMBER: &str = "eztunnel-linux/bin/eztunnel";
/// The largest program file accepted (the updater has the same limit).
pub const MAX_PROGRAM: u64 = 64 << 20;
/// Bytes per piece when a program is sent to a server over the agent link.
pub const PIECE: usize = 1 << 20;
/// Where a server keeps a program being sent to it.
const INCOMING_DIR: &str = "/var/lib/eztunnel-incoming";

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn version_ok(text: &str) -> bool {
    text == "latest" || update::parse_version(text.trim_start_matches('v')).is_some()
}

/// Downloads with curl (as the official installer does): HTTPS only, redirects allowed only to
/// HTTPS, a size cap and a time limit.
fn curl(url: &str, max: u64, proxy: Option<&str>) -> Result<Vec<u8>> {
    let mut command = Command::new("curl");
    command.args(["--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https", "--max-time", "300"]);
    command.args(["--max-filesize", &max.to_string()]);
    if let Some(proxy) = proxy.filter(|p| !p.is_empty()) {
        command.args(["--proxy", proxy]);
    }
    let output = command.arg(url).stdin(std::process::Stdio::null()).output().context("run curl")?;
    ensure!(output.status.success(), "download failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    ensure!(output.stdout.len() as u64 <= max, "the download is larger than expected");
    Ok(output.stdout)
}

/// The newest release: its version, notes and date.
pub fn latest(proxy: Option<&str>) -> Result<Value> {
    let body = curl(&format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"), 2 << 20, proxy)?;
    let release: Value = serde_json::from_slice(&body).context("an unexpected answer from the release page")?;
    let tag = release["tag_name"].as_str().context("the release has no version")?;
    Ok(json!({
        "version": tag.trim_start_matches('v'),
        "notes": release["body"].as_str().unwrap_or(""),
        "published": release["published_at"],
        "url": release["html_url"],
    }))
}

fn elf_machine(bytes: &[u8]) -> Option<u16> {
    (bytes.len() > 20 && bytes[..4] == *b"\x7fELF").then(|| u16::from_le_bytes([bytes[18], bytes[19]]))
}

/// Downloads a release for one CPU type, checks the archive against SHA256SUMS, takes the
/// program out of it, checks its CPU and its release signature, and keeps it in `dir`.
pub fn fetch(version: &str, arch: &str, dir: &Path, proxy: Option<&str>) -> Result<Value> {
    ensure!(version_ok(version), "a version looks like 0.9.14 (or latest)");
    let machine = match arch {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => bail!("supported CPUs are x86_64 and aarch64"),
    };
    let base = if version == "latest" {
        format!("https://github.com/{REPOSITORY}/releases/latest/download")
    } else {
        format!("https://github.com/{REPOSITORY}/releases/download/v{}", version.trim_start_matches('v'))
    };
    let asset = format!("eztunnel-linux-{arch}.tar.gz");
    let sums = String::from_utf8(curl(&format!("{base}/SHA256SUMS"), 1 << 20, proxy)?).context("SHA256SUMS is not text")?;
    let expected: Vec<&str> = sums
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (sum, name) = (words.next()?, words.next()?);
            (name.trim_start_matches('*') == asset).then_some(sum)
        })
        .collect();
    ensure!(expected.len() == 1 && expected[0].len() == 64, "SHA256SUMS must list {asset} exactly once");
    let archive = curl(&format!("{base}/{asset}"), MAX_PROGRAM, proxy)?;
    ensure!(sha256_hex(&archive).eq_ignore_ascii_case(expected[0]), "the archive does not match SHA256SUMS");
    let work = WorkDir::new(dir)?;
    let archive_path = work.0.join(&asset);
    std::fs::write(&archive_path, &archive)?;
    // Only the documented member is read; archive paths, links and modes are never trusted.
    let list = Command::new("tar").args(["-tzf"]).arg(&archive_path).arg("--").arg(MEMBER).output().context("run tar")?;
    ensure!(list.status.success() && String::from_utf8_lossy(&list.stdout).trim() == MEMBER, "the archive does not hold the program at {MEMBER}");
    let program = Command::new("tar").args(["-xOzf"]).arg(&archive_path).arg("--").arg(MEMBER).output().context("run tar")?;
    ensure!(program.status.success(), "cannot read the program from the archive");
    let bytes = program.stdout;
    ensure!(elf_machine(&bytes) == Some(machine), "the program is not for {arch}");
    let mut meta = keep(&bytes, dir)?;
    // A program for another CPU cannot be asked its version here; the release it came from says it.
    if meta["version"] == "" && version != "latest" {
        meta["version"] = json!(version.trim_start_matches('v'));
        let file = meta["file"].as_str().unwrap_or_default().to_string();
        write_private(&dir.join(file).with_extension("json"), serde_json::to_string(&meta)?.as_bytes())?;
    }
    Ok(meta)
}

/// Checks a program file (uploaded or downloaded) and keeps it under its checksum.
pub fn keep(bytes: &[u8], dir: &Path) -> Result<Value> {
    ensure!(bytes.len() as u64 <= MAX_PROGRAM, "the file is too large to be an EZTunnel program");
    let arch = match elf_machine(bytes) {
        Some(62) => "x86_64",
        Some(183) => "aarch64",
        _ => bail!("this is not a Linux x86_64 or aarch64 program"),
    };
    match crate::release::verify_bytes(bytes) {
        crate::release::Outcome::Verified => {}
        other => bail!("only officially signed program files can be installed; this one is {other:?}"),
    }
    let sum = sha256_hex(bytes);
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.bin", &sum[..16]));
    write_private(&path, bytes)?;
    let version = probe_version(&path, arch).unwrap_or_default();
    let meta = json!({"file": path.file_name().unwrap().to_string_lossy(), "sha256": sum, "arch": arch, "version": version, "size": bytes.len(), "added": super::now()});
    write_private(&path.with_extension("json"), serde_json::to_string(&meta)?.as_bytes())?;
    Ok(meta)
}

/// A private folder for one job, removed with everything in it when dropped.
struct WorkDir(PathBuf);

impl WorkDir {
    fn new(parent: &Path) -> Result<Self> {
        let mut random = [0u8; 8];
        crate::stealth::random_bytes(&mut random).context("random name")?;
        let path = parent.join(format!(".work-{}", hex::encode(random)));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

/// Writes a new private file (never an existing one), and makes sure it is on disk.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// The version a signed program reports, when it runs on this CPU.
fn probe_version(path: &Path, arch: &str) -> Option<String> {
    if arch != std::env::consts::ARCH {
        return None;
    }
    let work = WorkDir::new(path.parent()?).ok()?;
    let copy = work.0.join("eztunnel");
    std::fs::copy(path, &copy).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    let out = Command::new(&copy).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().strip_prefix("eztunnel ").map(str::to_string)
}

/// The programs kept on the dashboard's server, newest first.
pub fn kept(dir: &Path) -> Vec<Value> {
    let mut list: Vec<Value> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
        .collect();
    list.sort_by_key(|m: &Value| std::cmp::Reverse(m["added"].as_u64().unwrap_or(0)));
    list
}

/// A kept program by its file name (only names this module wrote are accepted).
pub fn read_kept(dir: &Path, file: &str) -> Result<Vec<u8>> {
    ensure!(file.len() == 20 && file.ends_with(".bin") && file[..16].bytes().all(|b| b.is_ascii_hexdigit()), "unknown program file");
    std::fs::read(dir.join(file)).context("the program file is gone")
}

/// What a server is sending: its expected size and checksum.
static INCOMING: Mutex<Option<(u64, String)>> = Mutex::new(None);

fn incoming_path() -> PathBuf {
    Path::new(INCOMING_DIR).join("program.part")
}

/// A server's side of receiving a program: `begin` ({size, sha256}), `piece` ({offset, data}).
pub fn receive(request: &Value) -> Result<Value> {
    match request["step"].as_str() {
        Some("begin") => {
            let size = request["size"].as_u64().filter(|s| *s > 0 && *s <= MAX_PROGRAM).context("a bad size")?;
            let sum = request["sha256"].as_str().filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).context("a bad checksum")?;
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(INCOMING_DIR)?;
            write_private(&incoming_path(), &[])?;
            *INCOMING.lock().unwrap() = Some((size, sum.to_lowercase()));
            Ok(json!({"ready": true}))
        }
        Some("piece") => {
            use base64::Engine;
            let (size, _) = INCOMING.lock().unwrap().clone().context("nothing is being sent")?;
            let offset = request["offset"].as_u64().context("a bad offset")?;
            let data = base64::engine::general_purpose::STANDARD.decode(request["data"].as_str().unwrap_or("")).context("bad data")?;
            ensure!(data.len() <= PIECE && offset + data.len() as u64 <= size, "the piece does not fit");
            let mut file = std::fs::OpenOptions::new().write(true).open(incoming_path())?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&data)?;
            Ok(json!({"written": offset + data.len() as u64}))
        }
        _ => bail!("unknown step"),
    }
}

/// Installs the program this server received (or, on the dashboard's server, one given
/// directly), after checking its checksum; the updater checks the signature again.
pub fn install_received(allow_downgrade: bool) -> Result<Value> {
    let (size, sum) = INCOMING.lock().unwrap().take().context("no program was sent")?;
    let bytes = std::fs::read(incoming_path())?;
    let _ = std::fs::remove_file(incoming_path());
    ensure!(bytes.len() as u64 == size && sha256_hex(&bytes) == sum, "the program did not arrive intact");
    let output = update::install_signed(&bytes, allow_downgrade)?;
    Ok(json!({"done": true, "output": output}))
}

/// This server's program: the installed version, the one kept for rollback, and the CPU.
pub fn versions() -> Value {
    let version_of = |path: &Path| -> Option<String> {
        let out = Command::new(path).arg("--version").output().ok()?;
        String::from_utf8_lossy(&out.stdout).trim().strip_prefix("eztunnel ").map(str::to_string)
    };
    let installed = Path::new(update::INSTALLED);
    let previous = update::previous_path(installed);
    json!({
        "installed": version_of(installed),
        "previous": previous.exists().then(|| version_of(&previous)).flatten(),
        "has_previous": previous.exists(),
        "running": env!("CARGO_PKG_VERSION"),
        "restart_needed": restart_needed(installed),
        "arch": std::env::consts::ARCH,
    })
}

/// Whether this process (the agent or the dashboard) runs the installed program as it was before
/// the file was replaced: then it shows the new version but still runs the old program until it
/// restarts. Version numbers cannot tell (a new build of the same version).
fn restart_needed(installed: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(exe) = std::fs::read_link("/proc/self/exe") else { return false };
        let exe = exe.to_string_lossy();
        let installed_text = installed.to_string_lossy();
        if exe != installed_text && exe != format!("{installed_text} (deleted)") {
            return false;
        }
        match (std::fs::metadata("/proc/self/exe"), std::fs::metadata(installed)) {
            (Ok(running), Ok(file)) => running.ino() != file.ino() || running.dev() != file.dev(),
            _ => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = installed;
        false
    }
}

pub fn rollback() -> Result<Value> {
    update::run_rollback(Path::new(update::INSTALLED), &update::Options { allow_downgrade: true, no_restart: false })?;
    Ok(json!({"done": true}))
}

/// The tunnel configurations of this server (they hold the tunnel keys).
pub fn export(store: &Store) -> Result<Value> {
    let (document, skipped) = backup::export(store)?;
    Ok(json!({"backup": document, "skipped": skipped}))
}

/// Saves the tunnels of a backup; existing ones are kept unless `replace`.
pub fn import(store: &Store, text: &str, replace: bool) -> Result<Value> {
    let tunnels = backup::parse_export(text)?;
    let report = backup::import(store, &tunnels, replace);
    Ok(json!({
        "imported": report.imported,
        "skipped": report.skipped,
        "failed": report.failed.iter().map(|(n, e)| json!({"name": n, "error": e})).collect::<Vec<_>>(),
    }))
}

/// Backups kept by the dashboard: `<unix seconds>-<server id>.json`, newest first.
pub fn backups(dir: &Path) -> Vec<Value> {
    let mut list: Vec<Value> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let (at, server) = name.strip_suffix(".json")?.split_once('-')?;
            let size = e.metadata().ok()?.len();
            Some(json!({"file": name, "at": at.parse::<u64>().ok()?, "server": server, "size": size}))
        })
        .collect();
    list.sort_by_key(|b| std::cmp::Reverse(b["at"].as_u64().unwrap_or(0)));
    list
}

/// A kept backup's name, checked so it cannot leave the backup folder.
pub fn backup_name_ok(file: &str) -> bool {
    file.strip_suffix(".json").and_then(|s| s.split_once('-')).is_some_and(|(at, server)| {
        at.bytes().all(|b| b.is_ascii_digit()) && !server.is_empty() && server.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// Keeps a backup, and only the newest `keep` per server.
pub fn save_backup(dir: &Path, server: &str, document: &Value, keep: usize) -> Result<String> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let server = if server.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') { server } else { "server" };
    // Written whole to a file of its own, then published under a name nobody else has: two
    // backups in the same second (a manual one beside the scheduled one) never share a file.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = dir.join(format!(".backup-{}-{unique}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    write_new_private(&temporary, serde_json::to_string_pretty(document)?.as_bytes())?;
    // Always after the newest backup of this server (also when the clock went back): the one
    // just made is never the oldest, so keeping the newest `keep` never removes it.
    let newest = backups(dir)
        .iter()
        .filter(|b| b["server"] == server)
        .filter_map(|b| b["at"].as_u64())
        .max();
    let first = newest.map_or(super::now(), |newest| super::now().max(newest + 1));
    let mut published = None;
    for later in 0..1000 {
        let file = format!("{}-{server}.json", first + later);
        // A hard link fails when the name exists: the publish is exclusive and atomic.
        match std::fs::hard_link(&temporary, dir.join(&file)) {
            Ok(()) => {
                published = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error).context("save the backup");
            }
        }
    }
    let _ = std::fs::remove_file(&temporary);
    let file = published.context("no free backup name")?;
    let mine: Vec<String> = backups(dir).into_iter().filter(|b| b["server"] == server).filter_map(|b| b["file"].as_str().map(str::to_string)).collect();
    for old in mine.iter().skip(keep) {
        let _ = std::fs::remove_file(dir.join(old));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_or_foreign_programs_are_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        assert!(keep(b"#!/bin/sh\necho hi\n", dir.path()).is_err(), "not a program");
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[18] = 62;
        assert!(keep(&elf, dir.path()).is_err(), "unsigned");
        assert!(kept(dir.path()).is_empty());
        for bad in ["../etc/passwd", "0123456789abcdef.json", "zz23456789abcdef.bin"] {
            assert!(read_kept(dir.path(), bad).is_err(), "{bad}");
        }
        assert!(!version_ok("1.2"));
        assert!(version_ok("v0.9.14") && version_ok("latest"));
        assert!(fetch("nope", "x86_64", dir.path(), None).is_err());
        assert!(fetch("0.9.14", "mips", dir.path(), None).is_err());
    }

    #[test]
    fn backups_are_kept_per_server_and_named_safely() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..3 {
            save_backup(dir.path(), "local", &json!({"tunnels": {}}), 2).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        save_backup(dir.path(), "a1b2c3", &json!({"tunnels": {}}), 2).unwrap();
        let list = backups(dir.path());
        assert_eq!(list.iter().filter(|b| b["server"] == "local").count(), 2);
        assert_eq!(list.len(), 3);
        assert!(backup_name_ok(list[0]["file"].as_str().unwrap()));
        for bad in ["../x.json", "1-../../x.json", "abc-local.json", "1-.json"] {
            assert!(!backup_name_ok(bad), "{bad}");
        }
    }

    /// Many backups in one second with the real retention: each one saved is kept (it is the
    /// newest), and only the oldest go.
    #[test]
    fn a_backup_just_saved_is_never_the_one_removed() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..30 {
            let file = save_backup(dir.path(), "local", &json!({"n": n}), 12).unwrap();
            assert!(dir.path().join(&file).exists(), "backup {n} ({file}) was removed at once");
        }
        let kept: Vec<u64> = backups(dir.path())
            .iter()
            .map(|b| serde_json::from_slice::<Value>(&std::fs::read(dir.path().join(b["file"].as_str().unwrap())).unwrap()).unwrap()["n"].as_u64().unwrap())
            .collect();
        assert_eq!(kept, (18..30).rev().collect::<Vec<u64>>(), "the newest twelve");
    }

    /// Backups made at the same moment each get their own whole file.
    #[test]
    fn backups_in_the_same_second_never_share_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let saves: Vec<_> = (0..8)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || save_backup(&path, "local", &json!({"n": n, "pad": "x".repeat(n * 1000)}), 100).unwrap())
            })
            .collect();
        let mut names: Vec<String> = saves.into_iter().map(|s| s.join().unwrap()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 8, "every backup has its own name");
        let mut seen: Vec<u64> = names
            .iter()
            .map(|name| {
                let value: Value = serde_json::from_slice(&std::fs::read(path.join(name)).unwrap()).unwrap();
                value["n"].as_u64().unwrap()
            })
            .collect();
        seen.sort();
        assert_eq!(seen, (0..8).collect::<Vec<u64>>(), "each file holds one whole backup");
        assert!(std::fs::read_dir(&path).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
    }

    #[test]
    fn a_program_must_arrive_whole_before_it_is_installed() {
        assert!(install_received(false).is_err(), "nothing was sent");
        assert!(receive(&json!({"step": "piece", "offset": 0, "data": ""})).is_err());
        assert!(receive(&json!({"step": "begin", "size": 0, "sha256": "00"})).is_err());
    }
}
