//! Updating the installed program from a file, with a way back.
//!
//! `eztunnel update` is run by the NEW program file (downloaded and checked by you; nothing here
//! contacts the internet). It checks that it can read every saved tunnel, keeps the installed
//! program as `eztunnel.previous`, installs itself, restarts only the tunnels that were running,
//! and if one of them does not stay up it puts the old program back by itself. `eztunnel
//! rollback` goes back by hand.
use super::{service, store::Store, ui};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Where the program is installed.
pub const INSTALLED: &str = "/usr/local/bin/eztunnel";

/// The program that was installed before the last update.
pub fn previous_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".previous");
    PathBuf::from(name)
}

/// Where the earlier backup waits while an update is under way.
fn keep_path(previous: &Path) -> PathBuf {
    let mut name = previous.as_os_str().to_owned();
    name.push(".keep");
    PathBuf::from(name)
}

/// How long a restarted tunnel must stay up (after it first is) to count as healthy.
const STAY_UP: Duration = Duration::from_secs(5);
/// How long a restarted tunnel may take to come up at all.
const COME_UP: Duration = Duration::from_secs(20);

/// The things an update needs from the machine; tests replace them.
pub trait Host {
    /// Real installations must have a trusted directory chain and regular owned files.
    /// Fake hosts use isolated temporary directories and do not execute programs.
    fn validate_target(&self, _target: &Path) -> Result<()> {
        Ok(())
    }
    /// The version a program file reports (`1.2.3`).
    fn version(&self, program: &Path) -> Result<String>;
    /// Names of the tunnels whose services are running now.
    fn running_tunnels(&self) -> Result<Vec<String>>;
    /// Checks that this program accepts every saved tunnel configuration.
    fn check_configs(&self) -> Result<()>;
    /// Checks that `program` (not necessarily this one) accepts every saved tunnel
    /// configuration. Used before a rollback, where the program being switched to is the older
    /// one on disk, not the one currently running.
    fn check_configs_as(&self, program: &Path) -> Result<()>;
    /// Convert local persistent state when restoring a binary with an older file format.
    /// Called before installation/restart, including an automatic failed-update rollback.
    fn prepare_state_for(&self, _version: &str) -> Result<()> {
        Ok(())
    }
    /// Read-only compatibility check before switching files or executing rollback probes.
    fn check_state_for(&self, _version: &str) -> Result<()> {
        Ok(())
    }
    /// Writes the service again for `program` and restarts it.
    fn restart(&self, tunnel: &str, program: &Path) -> Result<()>;
    /// Whether the tunnel's service is running.
    fn is_running(&self, tunnel: &str) -> bool;
    fn sleep(&self, duration: Duration);
}

pub struct Options {
    /// Install even when the installed program is newer or the same.
    pub allow_downgrade: bool,
    /// Only replace the program file; leave the running tunnels as they are.
    pub no_restart: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Updated {
        from: String,
        to: String,
        restarted: Vec<String>,
    },
    /// A restarted tunnel did not stay up; the old program is back.
    RolledBack { failed: Vec<String> },
}

/// Splits `1.2.3` into numbers for comparison; anything after a `-` is ignored.
pub fn parse_version(text: &str) -> Option<[u64; 3]> {
    let core = text.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let mut numbers = [0; 3];
    for slot in &mut numbers {
        *slot = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(numbers)
}

/// The CPU architecture of an ELF file (`e_machine`), if it is one.
pub fn elf_machine(path: &Path) -> Option<u16> {
    use std::io::Read;
    let mut header = [0u8; 20];
    std::fs::File::open(path)
        .ok()?
        .read_exact(&mut header)
        .ok()?;
    (header[..6] == [0x7f, b'E', b'L', b'F', 2, 1])
        .then(|| u16::from_le_bytes([header[18], header[19]]))
}

pub fn sha256_hex(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Copies `source` over `destination` so that no program ever sees a half-written file:
/// written next to it under a temporary name, then renamed.
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    Staged::write(&read_program(source)?, destination)?.install(destination,|directory|{std::fs::File::open(directory)?.sync_all()?;Ok(())})
}

/// Largest program file accepted (the real one is a few MiB).
const MAX_PROGRAM_BYTES: u64 = 256 * 1024 * 1024;

/// Reads a program file once. Everything after this (the signature check, the version probe,
/// the installation) works from these bytes or from a private copy of them, never from the
/// path again: a file in a user-writable directory can be swapped between two opens.
fn read_program(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "{} is not a regular program file",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(MAX_PROGRAM_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_PROGRAM_BYTES,
        "{} is too large to be an EZTunnel program",
        path.display()
    );
    Ok(bytes)
}

/// Root's updater must never descend through a directory another user controls.
/// Unix ACL write access is also reflected in the group-class permission mask.
#[cfg(target_os = "linux")]
fn validate_installation_target(target: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(
        target.is_absolute(),
        "installation target must be an absolute path"
    );
    let parent = target
        .parent()
        .context("installation directory is missing")?;
    let mut directory = PathBuf::from("/");
    for part in parent.components() {
        match part {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => directory.push(name),
            _ => bail!("installation path must not contain dot or parent components"),
        }
        let m = std::fs::symlink_metadata(&directory)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "installation directory and every ancestor must be root-owned, without symlinks or other-user write access: {}",
            directory.display()
        );
    }
    for path in [
        target.to_path_buf(),
        previous_path(target),
        previous_hash_path(target),
        keep_path(&previous_path(target)),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(m) => ensure!(
                m.is_file() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
                "installation file must be regular, root-owned and not writable by other users: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

struct UpdateLock(std::fs::File);
impl UpdateLock {
    fn acquire(target: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::{
                fd::AsRawFd,
                unix::fs::{MetadataExt, OpenOptionsExt},
            };
            let mut name = target.as_os_str().to_owned();
            name.push(".update.lock");
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(PathBuf::from(name))?;
            let m = file.metadata()?;
            ensure!(
                m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
                "update lock must be a private owned regular file"
            );
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "another update or rollback is in progress"
            );
            return Ok(Self(file));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            bail!("the updater requires Linux");
        }
    }
}
impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = &self.0;
    } // closing the descriptor releases the lock.
}

/// A verified program held as a private, root-only file next to the installed one. It is the
/// only thing that is ever executed or installed from a candidate, so what was verified is
/// what runs and what lands in place.
struct Staged {
    directory: PathBuf,
    pathname: PathBuf,
    executable: PathBuf,
    file: std::fs::File,
    installed: std::cell::Cell<bool>,
}

impl Staged {
    fn write(bytes: &[u8], target: &Path) -> Result<Self> {
        use std::io::Write;
        let parent = target
            .parent()
            .context("installation directory is missing")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.mode() & 0o022 == 0,
                "installation directory must be owned by the updater and not writable by other users"
            );
        }
        let mut random = [0u8; 16];
        crate::stealth::random_bytes(&mut random).context("allocate private update staging")?;
        let directory = parent.join(format!(".eztunnel-update-{}", hex::encode(random)));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory)?;
        let path = directory.join("program");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let result = (|| {
            let mut writable = options.open(&path)?;
            writable.write_all(bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                writable.set_permissions(std::fs::Permissions::from_mode(0o500))?;
            }
            writable.sync_all()?;
            drop(writable); // executable files must not retain a writable open handle.
            let file = std::fs::File::open(&path)?;
            #[cfg(target_os = "linux")]
            let executable = {
                use std::os::fd::AsRawFd;
                PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
            };
            #[cfg(not(target_os = "linux"))]
            let executable = path.clone();
            Ok(Self {
                directory: directory.clone(),
                pathname: path.clone(),
                executable,
                file,
                installed: std::cell::Cell::new(false),
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&directory);
        }
        result
    }

    fn path(&self) -> &Path {
        &self.executable
    }

    /// Moves the staged program into place as `destination`.
    fn install(&self, destination: &Path,sync_directory:impl FnOnce(&Path)->Result<()>) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.file
                .set_permissions(std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&self.pathname, destination)
            .with_context(|| format!("replace {}", destination.display()))?;
        self.installed.set(true);
        sync_directory(destination.parent().context("installation directory is missing")?)?;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pathname);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

/// Where the hash of the program kept as `.previous` is recorded when it is kept.
fn previous_hash_path(target: &Path) -> PathBuf {
    let mut name = previous_path(target).into_os_string();
    name.push(".sha256");
    PathBuf::from(name)
}

fn record_previous(target: &Path) {
    if let Ok(hash) = sha256_hex(&previous_path(target)) {
        let _ = std::fs::write(previous_hash_path(target), hash);
    }
}

/// A rollback target is either one this updater itself kept (its recorded hash matches: it is
/// the program that was installed here before, which may carry no signature) or a validly
/// signed release. Anything else is not run as root.
fn ensure_rollback_trusted(target: &Path, bytes: &[u8]) -> Result<()> {
    let _ = target;
    ensure_signed_bytes(bytes)
        .context("the previous program is not signed by the release authority")
}

/// Where `eztunnel update` and `eztunnel rollback` also write what they print, so the result can
/// be read after the SSH session (which may run through the tunnel being restarted) came back.
pub const LOG_FILE: &str = "/var/log/eztunnel-update.log";
/// A log larger than this is started afresh.
const LOG_LIMIT: u64 = 1024 * 1024;

/// The log in use; unset (nothing logged) outside `run_update` / `run_rollback`, as in tests.
static LOG: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

fn say(message: &str) {
    say_to(&mut std::io::stderr(), message);
    record(message);
}

/// Writes `message` to the terminal. A terminal that went away (the SSH session dropped) makes the
/// write fail; that must not stop the update, so the error is ignored (`eprintln!` would panic).
fn say_to(out: &mut dyn std::io::Write, message: &str) {
    let _ = writeln!(out, "{message}");
}

/// Appends `message`, time-stamped, to the log (if one is in use).
fn record(message: &str) {
    if let Some(path) = LOG.get() {
        append_log(path, message);
    }
}

fn append_log(path: &Path, message: &str) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o640);
    }
    let Ok(mut file) = options.open(path) else {
        return;
    };
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (y, mo, d, h, mi) = super::checker::civil(seconds);
    let _ = writeln!(
        file,
        "{y}-{mo:02}-{d:02} {h:02}:{mi:02}:{:02} UTC  {message}",
        seconds % 60
    );
}

/// Starts logging to `path`; a log over the size limit is started afresh.
fn open_log(path: &Path) {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > LOG_LIMIT) {
        let _ = std::fs::remove_file(path);
    }
    let _ = LOG.set(path.to_path_buf());
}

/// Keeps this process alive when its terminal goes away. Closing the SSH session sends SIGHUP,
/// which would otherwise kill an update between restarting the tunnels and checking that they
/// stay up (and before an automatic rollback). The old setting comes back when this is dropped.
struct HangupIgnored {
    #[cfg(target_os = "linux")]
    before: libc::sighandler_t,
}

fn ignore_hangup() -> HangupIgnored {
    HangupIgnored {
        // SAFETY: SIG_IGN installs no handler code.
        #[cfg(target_os = "linux")]
        before: unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) },
    }
}

impl Drop for HangupIgnored {
    fn drop(&mut self) {
        // SAFETY: puts back the disposition `signal` returned.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::signal(libc::SIGHUP, self.before);
        }
    }
}

/// Runs a whole `update` / `rollback`: survives a hang-up, logs, and records the final error too
/// (it is printed by `main`, which may no longer have a terminal).
fn logged(what: &str, body: impl FnOnce() -> Result<()>) -> Result<()> {
    let _hangup = ignore_hangup();
    open_log(Path::new(LOG_FILE));
    record(&format!(
        "--- eztunnel {what} ({})",
        env!("CARGO_PKG_VERSION")
    ));
    say(&format!("This is also written to {LOG_FILE}."));
    let result = body();
    match &result {
        Ok(()) => record("Finished."),
        Err(error) => record(&format!("Failed: {error:#}")),
    }
    result
}

/// Brings the tunnels in `tunnels` up with `program` and waits until they all stay up.
/// Returns the names that did not.
fn restart_and_watch(host: &dyn Host, tunnels: &[String], program: &Path) -> Vec<String> {
    let mut failed = Vec::new();
    for name in tunnels {
        if let Err(error) = host.restart(name, program) {
            say(&format!("  {name}: could not restart: {error:#}"));
            failed.push(name.clone());
        }
    }
    let waiting: Vec<&String> = tunnels.iter().filter(|n| !failed.contains(n)).collect();
    // First everything must come up...
    let step = Duration::from_millis(500);
    let mut waited = Duration::ZERO;
    while waited < COME_UP && !waiting.iter().all(|name| host.is_running(name)) {
        host.sleep(step);
        waited += step;
    }
    // ...then stay up: one that stops at any moment of the window counts as failed, not only one
    // that happens to be down when the window ends.
    let mut stayed = Duration::ZERO;
    while stayed < STAY_UP {
        host.sleep(step);
        stayed += step;
        for name in &waiting {
            if !host.is_running(name) && !failed.contains(name) {
                failed.push((*name).clone());
            }
        }
    }
    failed
}

/// Installs `candidate` as `target`, keeping the old program as `previous`.
pub fn perform(
    host: &dyn Host,
    candidate: &Path,
    target: &Path,
    options: &Options,
) -> Result<Outcome> {
    perform_with_sync(host,candidate,target,options,|directory|{std::fs::File::open(directory)?.sync_all()?;Ok(())})
}

fn perform_with_sync(
    host:&dyn Host,candidate:&Path,target:&Path,options:&Options,
    sync_directory:impl FnOnce(&Path)->Result<()>,
) -> Result<Outcome> {
    host.validate_target(target)?;
    let _lock = UpdateLock::acquire(target)?;
    let previous = previous_path(target);
    // Official updater candidates require release-file authentication. Read once and
    // authenticated BEFORE anything of it runs; from here on only a private copy of exactly
    // those bytes is executed or installed.
    let bytes = read_program(candidate)?;
    ensure_signed_bytes(&bytes)?;
    let staged = Staged::write(&bytes, target)?;
    drop(bytes);
    let new_version = host.version(staged.path()).context("run the new program")?;
    ensure!(
        parse_version(&new_version).is_some(),
        "the new program reports an unreadable version {new_version:?}"
    );
    ensure!(
        target.exists(),
        "no installed program at {}; use the installer for a first installation",
        target.display()
    );
    ensure!(
        candidate.canonicalize()? != target.canonicalize()?,
        "this is already the installed program; run the new file, not {}",
        target.display()
    );
    let old_bytes = read_program(target)?;
    ensure_signed_bytes(&old_bytes)
        .context("the installed program is not a trusted signed release")?;
    let old_staged = Staged::write(&old_bytes, target)?;
    let old_version = host
        .version(old_staged.path())
        .context("run the installed program to read its version")?;
    
    
    host.check_state_for(&new_version)?;
    if !options.no_restart {
        host.check_state_for(&old_version)
            .context("the installed program cannot provide a compatible recovery path; a coordinated migration requires --no-restart")?;
    }
    if !options.allow_downgrade {
        let (old, new) = (parse_version(&old_version), parse_version(&new_version));
        ensure!(
            matches!((old, new), (Some(old), Some(new)) if new > old),
            "the installed version {old_version} is not older than {new_version}; use --allow-downgrade to install it anyway"
        );
    }
    match (elf_machine(target), elf_machine(staged.path())) {
        (Some(installed), Some(new)) => ensure!(
            installed == new,
            "the new program is for a different CPU architecture than the installed one"
        ),
        (_, None) => bail!("the new file is not a Linux program"),
        _ => {}
    }
    host.check_configs()
        .context("the new program cannot read a saved tunnel; nothing was changed")?;
    let running = if options.no_restart {
        Vec::new()
    } else {
        host.running_tunnels()?
    };
    say(&format!("Updating {old_version} → {new_version}"));
    // The program kept by an earlier update stays safe until this one has worked: a failed
    // update must not cost the older backup.
    let earlier = keep_path(&previous);
    let had_earlier = previous.exists();
    if had_earlier {
        std::fs::rename(&previous, &earlier).context("set the earlier backup aside")?;
    }
    let restore_earlier = || {
        if had_earlier {
            let _ = std::fs::rename(&earlier, &previous);
        } else {
            let _ = std::fs::remove_file(&previous);
        }
    };
    if let Err(error) = replace_file(target, &previous) {
        restore_earlier();
        return Err(error.context("keep the installed program as the previous one"));
    }
    record_previous(target);
    if let Err(error) = host.prepare_state_for(&new_version) {
        restore_earlier();
        return Err(error.context("prepare persistent state for the new program"));
    }
    if let Err(error) = staged.install(target,sync_directory) {
        if !staged.installed.get(){
            restore_earlier();
            return Err(error.context("install the new program; the old one is unchanged"));
        }
        // Rename committed: .previous is now the only immediate recovery copy.
        // Restore it before housekeeping; if restoration fails keep both history
        // files and report the ambiguous installation for explicit recovery.
        if let Err(restore)=replace_file(&previous,target){
            return Err(anyhow::anyhow!("New program was installed but final synchronization failed: {error:#}. Automatic restore failed: {restore:#}. Recovery files were retained at {} and {}",previous.display(),earlier.display()));
        }
        restore_earlier();
        return Err(error.context("installation finalization failed after replacement; the previous program was restored"));
    }
    if running.is_empty() {
        let _ = std::fs::remove_file(&earlier);
        return Ok(Outcome::Updated {
            from: old_version,
            to: new_version,
            restarted: running,
        });
    }
    say(&format!(
        "Restarting {} tunnel(s) and watching them…",
        running.len()
    ));
    let failed = restart_and_watch(host, &running, target);
    if failed.is_empty() {
        let _ = std::fs::remove_file(&earlier);
        return Ok(Outcome::Updated {
            from: old_version,
            to: new_version,
            restarted: running,
        });
    }
    say(&format!(
        "Not up after the update: {}. Putting {old_version} back.",
        failed.join(", ")
    ));
    host.prepare_state_for(&old_version)
        .context("restore persistent state for the previous program")?;
    replace_file(&previous, target).context("put the previous program back")?;
    restore_earlier();
    let still_failing = restart_and_watch(host, &running, target);
    if !still_failing.is_empty() {
        bail!(
            "the previous program was restored, but tunnel recovery failed: {}; inspect the update log",
            still_failing.join(", ")
        );
    }
    Ok(Outcome::RolledBack { failed })
}

/// Swaps the installed program and the previous one, and restarts the running tunnels.
pub fn rollback(host: &dyn Host, target: &Path, options: &Options) -> Result<Outcome> {
    host.validate_target(target)?;
    let _lock = UpdateLock::acquire(target)?;
    let previous = previous_path(target);
    ensure!(
        previous.exists(),
        "there is no previous program ({} is missing)",
        previous.display()
    );
    // Same discipline as an update: read once, require that these bytes are the program this
    // updater kept and a valid release signature, and run only a private copy of them.
    let bytes = read_program(&previous)?;
    ensure_rollback_trusted(target, &bytes)?;
    let staged = Staged::write(&bytes, target)?;
    drop(bytes);
    let back_to = host
        .version(staged.path())
        .context("run the previous program")?;
    host.check_state_for(&back_to)?;
    host.check_configs_as(staged.path())
        .context("the previous program cannot read a saved tunnel; nothing was changed")?;
    let current = read_program(target)
        .and_then(|bytes| {
            ensure_signed_bytes(&bytes)?;
            let staged_current = Staged::write(&bytes, target)?;
            host.version(staged_current.path())
        })
        .unwrap_or_else(|_| "unknown".into());
    let running = if options.no_restart {
        Vec::new()
    } else {
        host.running_tunnels()?
    };
    // Keep the program being replaced, so a second rollback goes forward again.
    let mut holding = previous.as_os_str().to_owned();
    holding.push(".swap");
    let holding = PathBuf::from(holding);
    replace_file(target, &holding)?;
    host.prepare_state_for(&back_to)
        .context("prepare persistent state for rollback")?;
    staged.install(target,|directory|{std::fs::File::open(directory)?.sync_all()?;Ok(())})?;
    std::fs::rename(&holding, &previous)?;
    // `.previous` is now the program that was just replaced.
    record_previous(target);
    say(&format!("Rolled back {current} → {back_to}"));
    let failed = if running.is_empty() {
        Vec::new()
    } else {
        restart_and_watch(host, &running, target)
    };
    if !failed.is_empty() {
        bail!(
            "rollback installed {back_to}, but these tunnels did not recover: {}",
            failed.join(", ")
        );
    }
    Ok(if failed.is_empty() {
        Outcome::Updated {
            from: current,
            to: back_to,
            restarted: running,
        }
    } else {
        Outcome::RolledBack { failed }
    })
}

/// The real machine.
pub struct System {
    store: Store,
}

fn check_protocol_boundary(version: &str) -> Result<()> {
    let version = parse_version(version).context("cannot determine protocol compatibility")?;
    ensure!(version >= [0, 9, 0], "the 0.9 protocol requires coordinated endpoints; ordinary update/rollback cannot cross the 0.9.0 boundary. Use explicit local installation with both endpoints stopped or staged");
    Ok(())
}

impl System {
    pub fn open() -> Result<Self> {
        let store = Store::open()?;
        ensure!(
            store.system && store.is_system_install(),
            "updating needs the real installation (root, with systemd)"
        );
        Ok(Self { store })
    }
}

impl Host for System {
    fn validate_target(&self, target: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            validate_installation_target(target)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            bail!("the updater requires Linux")
        }
    }
    fn check_state_for(&self, version: &str) -> Result<()> {
        check_protocol_boundary(version)
    }
    fn prepare_state_for(&self, version: &str) -> Result<()> {
        self.check_state_for(version)
    }
    fn version(&self, program: &Path) -> Result<String> {
        let output = Command::new(program)
            .arg("--version")
            .output()
            .with_context(|| format!("run {}", program.display()))?;
        ensure!(
            output.status.success(),
            "{} --version failed",
            program.display()
        );
        let text = String::from_utf8_lossy(&output.stdout);
        text.trim()
            .strip_prefix("eztunnel ")
            .map(str::to_string)
            .with_context(|| format!("{} is not an EZTunnel program", program.display()))
    }

    fn running_tunnels(&self) -> Result<Vec<String>> {
        Ok(self
            .store
            .names()?
            .into_iter()
            .filter(|name| {
                matches!(
                    service::state(&self.store, name),
                    service::State::Running | service::State::Starting
                )
            })
            .collect())
    }

    fn check_configs(&self) -> Result<()> {
        for name in self.store.names()? {
            super::store::check_file(&self.store.path(&name))
                .with_context(|| format!("tunnel {name}"))?;
        }
        Ok(())
    }

    fn check_configs_as(&self, program: &Path) -> Result<()> {
        for name in self.store.names()? {
            let path = self.store.path(&name);
            let output = Command::new(program)
                .arg("--config")
                .arg(&path)
                .arg("--check")
                .output()
                .with_context(|| format!("run {} --check", program.display()))?;
            ensure!(
                output.status.success(),
                "tunnel {name}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn restart(&self, tunnel: &str, program: &Path) -> Result<()> {
        service::install_with(&self.store, tunnel, program)
    }

    fn is_running(&self, tunnel: &str) -> bool {
        service::state(&self.store, tunnel) == service::State::Running
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Official updater candidates require a release signature, independently of execution.
fn ensure_signed_bytes(bytes: &[u8]) -> Result<()> {
    // Unit tests use fake, unsigned program files; a test that wants the real check turns it
    // on for its own thread. Nothing here exists in a shipped build.
    #[cfg(test)]
    if !tests::ENFORCE_SIGNING.with(|flag| flag.get()) {
        return Ok(());
    }
    match crate::release::verify_bytes(bytes) {
        crate::release::Outcome::Verified => Ok(()),
        other => bail!(
            "this build only installs officially signed program files; this file is {other:?}. Download the release from the official source and check its SHA-256."
        ),
    }
}


/// `eztunnel update`: this program file installs itself.
pub fn run_update(target: &Path, options: &Options) -> Result<()> {
    ensure!(
        super::store::is_root(),
        "updating changes system files: run it as root"
    );
    logged("update", || update_here(target, options))
}

fn update_here(target: &Path, options: &Options) -> Result<()> {
    let candidate = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .context("locate this program")?;
    say(&format!("New program: {}", candidate.display()));
    say(&format!("SHA-256:     {}", sha256_hex(&candidate)?));
    say("Compare the SHA-256 with the one published with the release.");
    let system = System::open()?;
    match perform(&system, &candidate, target, options)? {
        Outcome::Updated {
            from,
            to,
            restarted,
        } => {
            say(&format!(
                "Updated {from} → {to}; {} tunnel(s) restarted.",
                restarted.len()
            ));
            say(&format!(
                "The old program is kept as {}; `eztunnel rollback` goes back.",
                previous_path(target).display()
            ));
            Ok(())
        }
        Outcome::RolledBack { failed } => bail!(
            "the update was undone because {} did not stay up; the previous program runs again",
            failed.join(", ")
        ),
    }
}

/// `eztunnel rollback`.
pub fn run_rollback(target: &Path, options: &Options) -> Result<()> {
    ensure!(
        super::store::is_root(),
        "this changes system files: run it as root"
    );
    logged("rollback", || rollback_here(target, options))
}

fn rollback_here(target: &Path, options: &Options) -> Result<()> {
    let system = System::open()?;
    match rollback(&system, target, options)? {
        Outcome::Updated { to, restarted, .. } => {
            say(&format!(
                "Now running {to}; {} tunnel(s) restarted.",
                restarted.len()
            ));
            Ok(())
        }
        Outcome::RolledBack { failed } => bail!(
            "{} did not stay up with the previous program",
            failed.join(", ")
        ),
    }
}

/// Tools → Update: runs a downloaded program file so that it installs itself.
pub fn update_screen() -> Result<()> {
    ui::banner("Update EZTunnel");
    ui::note(
        "Download the new release yourself and check its SHA-256 against the one published\nwith it. Give the path of the program file (for example eztunnel-linux-x86_64).\nIt installs itself, keeps this version for a rollback, restarts the running tunnels,\nand goes back by itself if one of them does not stay up. Nothing is downloaded here.",
    );
    let path = ui::form(|| {
        let path = ui::ask("Path of the new program file", None, |t: &String| {
            if Path::new(t.trim()).is_file() {
                Ok(())
            } else {
                Err("that file does not exist".to_string())
            }
        })?;
        let path = PathBuf::from(path.trim());
        ui::info(&format!("SHA-256: {}", sha256_hex(&path)?));
        if !ui::confirm(
            "Does it match the published checksum? Run it to update?",
            false,
        )? {
            return Err(ui::Back.into());
        }
        Ok(path)
    })?;
    // This menu runs as root, so it must not run a downloaded file it has not authenticated.
    // The file is read once, verified, and only a private root-only copy of those bytes runs.
    let bytes = read_program(&path)?;
    if let Err(error) = ensure_signed_bytes(&bytes) {
        ui::fail(&format!("{error:#}"));
        ui::pause();
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    validate_installation_target(Path::new("/usr/local/bin/eztunnel.incoming"))?;
    let staged = Staged::write(&bytes, Path::new("/usr/local/bin/eztunnel.incoming"))?;
    drop(bytes);
    let mut command = Command::new(staged.path());
    command.arg("update");
    // The update must finish even if this menu dies with its SSH session (the new program also
    // ignores the hang-up itself; this covers the moment before it gets there).
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `signal` is async-signal-safe and touches no memory of this process.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                Ok(())
            });
        }
    }
    let status =
        ui::with_interrupt_for_children(|| command.status()).context("run the new program")?;
    if status.success() {
        ui::ok("Updated. Open the manager again to use the new version.");
        ui::pause();
        std::process::exit(0);
    }
    ui::fail("The update did not finish; see the messages above.");
    ui::pause();
    Ok(())
}

/// Tools → Roll back.
pub fn rollback_screen() -> Result<()> {
    ui::banner("Roll back EZTunnel");
    let target = Path::new(INSTALLED);
    if !previous_path(target).exists() {
        ui::info("There is no previous version: no update has been made on this server.");
        ui::pause();
        return Ok(());
    }
    if !ui::confirm(
        "Go back to the previous version and restart the running tunnels?",
        false,
    )? {
        return Ok(());
    }
    match run_rollback(
        target,
        &Options {
            allow_downgrade: true,
            no_restart: false,
        },
    ) {
        Ok(()) => {
            ui::ok("Rolled back. Open the manager again to use that version.");
            ui::pause();
            std::process::exit(0);
        }
        Err(error) => {
            ui::fail(&format!("{error:#}"));
            ui::pause();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap};

    /// A pretend program: the 20 header bytes of an x86-64 ELF file, then the version on a line
    /// of its own, then a body that tells the files apart.
    fn program(version: &str, body: &str) -> Vec<u8> {
        let mut bytes = vec![0x7f, b'E', b'L', b'F'];
        bytes.resize(18, 0);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes.extend_from_slice(&62u16.to_le_bytes());
        bytes.extend_from_slice(
            format!(
                "{version}
{body}"
            )
            .as_bytes(),
        );
        bytes
    }

    fn version_in(path: &Path) -> String {
        let bytes = std::fs::read(path).unwrap_or_default();
        String::from_utf8_lossy(bytes.get(20..).unwrap_or_default())
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn has_version(path: &Path, version: &str) -> bool {
        version_in(path) == version
    }

    // Generic state-machine tests use explicit fake executable bytes.
    thread_local! {
        /// Whether `ensure_signed_bytes` really checks signatures on this test thread.
        pub(super) static ENFORCE_SIGNING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// A host that fails the test if anything is run: used to prove a refused file never runs.
    struct Tripwire;

    impl Host for Tripwire {
        fn version(&self, program: &Path) -> Result<String> {
            panic!("ran {} before it was authenticated", program.display())
        }
        fn running_tunnels(&self) -> Result<Vec<String>> {
            panic!("touched the machine")
        }
        fn check_configs(&self) -> Result<()> {
            panic!("touched the machine")
        }
        fn check_configs_as(&self, program: &Path) -> Result<()> {
            panic!("ran {} before it was authenticated", program.display())
        }
        fn restart(&self, _: &str, _: &Path) -> Result<()> {
            panic!("touched the machine")
        }
        fn is_running(&self, _: &str) -> bool {
            panic!("touched the machine")
        }
        fn sleep(&self, _: Duration) {}
    }

    /// A signed candidate is installed from the bytes that were verified; an unsigned one is
    /// refused before any of it runs.
    #[test]
    fn an_unsigned_candidate_is_refused_before_it_runs() {
        ENFORCE_SIGNING.with(|flag| flag.set(true));
        let (_directory, target, new) = setup("1.0.0", "1.1.0");
        let options = Options {
            allow_downgrade: false,
            no_restart: true,
        };
        let error = perform(&Tripwire, &new, &target, &options).unwrap_err();
        assert!(
            format!("{error:#}").contains("officially signed"),
            "{error:#}"
        );
        // Nothing was staged, installed or kept.
        assert!(!previous_path(&target).exists());
        assert!(has_version(&target, "1.0.0"));
        let mut staged = target.as_os_str().to_owned();
        staged.push(".staged");
        assert!(!PathBuf::from(staged).exists());
    }

    #[test]
    fn ordinary_updates_never_cross_the_0_9_protocol_boundary() {
        assert!(check_protocol_boundary("0.8.9").is_err());
        assert!(check_protocol_boundary("0.1.5").is_err());
        assert!(check_protocol_boundary("0.9.0").is_ok());
        assert!(check_protocol_boundary("0.9.1").is_ok());
        assert!(check_protocol_boundary("not a version").is_err());
    }

    #[test]
    fn rollback_refuses_an_untracked_unsigned_previous_program_and_never_runs_it() {
        ENFORCE_SIGNING.with(|flag| flag.set(true));
        let (_directory, target, _new) = setup("1.1.0", "1.0.0");
        // A `.previous` that this updater did not keep (no recorded hash) and that carries no
        // release signature.
        std::fs::write(previous_path(&target), program("0.9.0", "planted")).unwrap();
        let options = Options {
            allow_downgrade: true,
            no_restart: true,
        };
        let error = rollback(&Tripwire, &target, &options).unwrap_err();
        assert!(format!("{error:#}").contains("not signed"), "{error:#}");
        assert!(has_version(&target, "1.1.0"));
    }

    /// An adjacent checksum is diagnostic data, never a substitute for a release signature.
    #[test]
    fn rollback_requires_a_release_signature_even_when_the_recorded_hash_matches() {
        ENFORCE_SIGNING.with(|flag| flag.set(true));
        let (_directory, target, new) = setup("1.0.0", "1.1.0");
        let bytes = std::fs::read(&new).unwrap();
        std::fs::write(previous_path(&target), &bytes).unwrap();
        record_previous(&target);
        assert!(ensure_rollback_trusted(&target, &bytes).is_err());
        let mut swapped = bytes.clone();
        swapped.push(b'!');
        std::fs::write(previous_path(&target), &swapped).unwrap();
        assert!(ensure_rollback_trusted(&target, &swapped).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_staging_executes_the_open_descriptor_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("installed");
        let bytes = std::fs::read("/bin/echo").unwrap();
        let staged = Staged::write(&bytes, &target).unwrap();
        let private_dir = staged.directory.clone();
        // A changed staging pathname cannot change which open executable is probed.
        std::fs::rename(&staged.pathname, private_dir.join("original")).unwrap();
        std::fs::write(&staged.pathname, b"not executable").unwrap();
        let result = Command::new(staged.path())
            .arg("descriptor-kept")
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"descriptor-kept\n");
        std::fs::remove_file(private_dir.join("original")).unwrap();
        drop(staged);
        assert!(!private_dir.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_lock_serializes_one_target_and_rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("installed");
        let first = UpdateLock::acquire(&target).unwrap();
        assert!(UpdateLock::acquire(&target).is_err());
        drop(first);
        assert!(UpdateLock::acquire(&target).is_ok());
        std::fs::remove_file(dir.path().join("installed.update.lock")).unwrap();
        std::os::unix::fs::symlink("unrelated", dir.path().join("installed.update.lock")).unwrap();
        assert!(UpdateLock::acquire(&target).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn privileged_targets_under_a_shared_temporary_directory_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_installation_target(&dir.path().join("installed")).is_err());
    }

    #[test]
    fn the_staged_copy_is_what_gets_installed_even_if_the_source_changes() {
        let (_directory, target, new) = setup("1.0.0", "1.1.0");
        let verified = read_program(&new).unwrap();
        let staged = Staged::write(&verified, &target).unwrap();
        // The source path is swapped after verification...
        std::fs::write(&new, program("6.6.6", "evil")).unwrap();
        staged.install(&target,|directory|{std::fs::File::open(directory)?.sync_all()?;Ok(())}).unwrap();
        // ...but what lands is the verified content.
        assert_eq!(std::fs::read(&target).unwrap(), verified);
        assert!(has_version(&target, "1.1.0"));
    }

    struct Fake {
        running: Vec<String>,
        /// Tunnels that do not stay up while this program content is installed.
        broken_with: HashMap<String, String>,
        configs_ok: bool,
        /// Versions that cannot read a saved tunnel (checked against the program passed to
        /// `check_configs_as`, for example the older binary a rollback is about to switch to).
        unreadable_by: Vec<String>,
        target: PathBuf,
        restarts: RefCell<Vec<String>>,
        prepared: RefCell<Vec<String>>,
        /// Tunnels that come up and run for a while, then stop, while this program content is
        /// installed.
        late_crash: HashMap<String, String>,
        checks: RefCell<HashMap<String, usize>>,
    }

    impl Host for Fake {
        fn prepare_state_for(&self, version: &str) -> Result<()> {
            self.prepared.borrow_mut().push(version.to_owned());
            Ok(())
        }
        fn version(&self, program: &Path) -> Result<String> {
            let version = version_in(program);
            ensure!(!version.is_empty(), "empty program");
            Ok(version)
        }
        fn running_tunnels(&self) -> Result<Vec<String>> {
            Ok(self.running.clone())
        }
        fn check_configs(&self) -> Result<()> {
            ensure!(self.configs_ok, "tunnel a: bad config");
            Ok(())
        }
        fn check_configs_as(&self, program: &Path) -> Result<()> {
            let version = version_in(program);
            ensure!(
                !self.unreadable_by.contains(&version),
                "tunnel a: {version} does not understand a saved field"
            );
            Ok(())
        }
        fn restart(&self, tunnel: &str, _program: &Path) -> Result<()> {
            assert_eq!(
                self.prepared.borrow().last(),
                Some(&version_in(_program)),
                "state must be readable by the binary before any service restart"
            );
            self.restarts.borrow_mut().push(tunnel.to_string());
            Ok(())
        }
        fn is_running(&self, tunnel: &str) -> bool {
            if let Some(bad) = self.late_crash.get(tunnel)
                && has_version(&self.target, bad)
            {
                let mut checks = self.checks.borrow_mut();
                let count = checks.entry(tunnel.to_string()).or_insert(0);
                *count += 1;
                if *count > 3 {
                    return false;
                }
            }
            self.broken_with
                .get(tunnel)
                .is_none_or(|bad| !has_version(&self.target, bad))
        }
        fn sleep(&self, _duration: Duration) {}
    }

    fn setup(installed: &str, candidate: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("eztunnel");
        let new = directory.path().join("download");
        std::fs::write(&target, program(installed, "body-old")).unwrap();
        std::fs::write(&new, program(candidate, "body-new")).unwrap();
        (directory, target, new)
    }

    fn fake(target: &Path, running: &[&str]) -> Fake {
        // These tests use fake program files without release trailers: signing is not
        // enforced on their threads unless a test asks for it.
        Fake {
            running: running.iter().map(|n| n.to_string()).collect(),
            broken_with: HashMap::new(),
            configs_ok: true,
            unreadable_by: Vec::new(),
            target: target.to_path_buf(),
            restarts: RefCell::new(Vec::new()),
            prepared: RefCell::new(Vec::new()),
            late_crash: HashMap::new(),
            checks: RefCell::new(HashMap::new()),
        }
    }

    const NORMAL: Options = Options {
        allow_downgrade: false,
        no_restart: false,
    };

    #[test]
    fn post_rename_sync_failure_restores_installed_bytes_and_preserves_earlier_history(){
        let(_directory,target,new)=setup("0.9.12","0.9.13");
        let original=std::fs::read(&target).unwrap();let older=program("0.9.11","older");
        std::fs::write(previous_path(&target),&older).unwrap();
        let host=fake(&target,&[]);
        let error=perform_with_sync(&host,&new,&target,&Options{allow_downgrade:false,no_restart:true},|_|anyhow::bail!("simulated parent fsync failure")).unwrap_err();
        assert!(format!("{error:#}").contains("previous program was restored"));
        assert_eq!(std::fs::read(&target).unwrap(),original);
        assert_eq!(std::fs::read(previous_path(&target)).unwrap(),older);
    }

    #[test]
    fn versions_are_read_and_compared_as_numbers() {
        assert_eq!(parse_version("0.7.0"), Some([0, 7, 0]));
        assert_eq!(parse_version("0.10.2"), Some([0, 10, 2]));
        assert_eq!(parse_version("1.2.3-rc1"), Some([1, 2, 3]));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("a.b.c"), None);
        assert!(parse_version("0.10.0") > parse_version("0.9.9"));
    }

    #[test]
    fn an_update_keeps_the_old_program_and_restarts_only_running_tunnels() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        std::fs::write(previous_path(&target), program("0.6.2", "body-earlier")).unwrap();
        let host = fake(&target, &["alpha", "beta"]);
        let outcome = perform(&host, &new, &target, &NORMAL).unwrap();
        assert_eq!(
            outcome,
            Outcome::Updated {
                from: "0.7.0".into(),
                to: "0.7.1".into(),
                restarted: vec!["alpha".into(), "beta".into()]
            }
        );
        assert!(has_version(&target, "0.7.1"));
        assert!(has_version(&previous_path(&target), "0.7.0"));
        assert_eq!(*host.restarts.borrow(), ["alpha", "beta"]);
        assert!(!keep_path(&previous_path(&target)).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn signed_fixture_update_and_rollback_validate_exact_bytes_without_private_authority() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        crate::release::with_fixture_authority(key.verifying_key().to_bytes(), || {
            ENFORCE_SIGNING.with(|flag| flag.set(true));
            let (_directory, target, candidate) = setup("0.9.0", "0.9.1");
            for path in [&target, &candidate] {
                let mut bytes = std::fs::read(path).unwrap();
                let signature = key.sign(blake3::hash(&bytes).as_bytes());
                bytes.extend_from_slice(b"EZT1");
                bytes.push(239);
                bytes.extend_from_slice(&signature.to_bytes());
                bytes.extend_from_slice(&[0; 3]);
                std::fs::write(path, bytes).unwrap();
            }
            let original = std::fs::read(&target).unwrap();
            let new = std::fs::read(&candidate).unwrap();
            let host = fake(&target, &[]);
            perform(&host, &candidate, &target, &Options { allow_downgrade: false, no_restart: true }).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), new);
            assert_eq!(std::fs::read(previous_path(&target)).unwrap(), original);
            rollback(&host, &target, &Options { allow_downgrade: true, no_restart: true }).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), original);
            let mut corrupt = new;
            corrupt[20] ^= 1;
            std::fs::write(&candidate, corrupt).unwrap();
            assert!(perform(&host, &candidate, &target, &Options { allow_downgrade: true, no_restart: true }).is_err());
            assert_eq!(std::fs::read(&target).unwrap(), original);
        });
    }

    #[test]
    fn a_tunnel_that_does_not_stay_up_undoes_the_update() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        // An earlier update left 0.6.2 as the previous program; a failed update must not lose it.
        std::fs::write(previous_path(&target), program("0.6.2", "body-earlier")).unwrap();
        let mut host = fake(&target, &["alpha", "beta"]);
        host.broken_with.insert("beta".into(), "0.7.1".into());
        let outcome = perform(&host, &new, &target, &NORMAL).unwrap();
        assert_eq!(
            outcome,
            Outcome::RolledBack {
                failed: vec!["beta".into()]
            }
        );
        assert!(has_version(&target, "0.7.0"));
        assert!(has_version(&previous_path(&target), "0.6.2"));
        assert!(!keep_path(&previous_path(&target)).exists());
        // Restarted for the update, then again for the way back.
        assert_eq!(*host.restarts.borrow(), ["alpha", "beta", "alpha", "beta"]);
        assert_eq!(*host.prepared.borrow(), ["0.7.1", "0.7.0"]);
    }

    /// A build that is up when the first checks run and stops a moment later must still be undone.
    #[test]
    fn a_tunnel_that_stops_in_the_middle_of_the_window_undoes_the_update() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        let mut host = fake(&target, &["alpha", "beta"]);
        host.late_crash.insert("beta".into(), "0.7.1".into());
        let outcome = perform(&host, &new, &target, &NORMAL).unwrap();
        assert_eq!(
            outcome,
            Outcome::RolledBack {
                failed: vec!["beta".into()]
            }
        );
        assert!(has_version(&target, "0.7.0"));
    }

    #[test]
    fn nothing_changes_when_the_new_program_cannot_read_a_tunnel() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        let mut host = fake(&target, &["alpha"]);
        host.configs_ok = false;
        let error = perform(&host, &new, &target, &NORMAL).unwrap_err();
        assert!(format!("{error:#}").contains("nothing was changed"));
        assert!(has_version(&target, "0.7.0"));
        assert!(!previous_path(&target).exists());
        assert!(host.restarts.borrow().is_empty());
    }

    #[test]
    fn an_older_or_equal_version_needs_to_be_asked_for() {
        for candidate in ["0.7.0", "0.6.2"] {
            let (_directory, target, new) = setup("0.7.0", candidate);
            let host = fake(&target, &[]);
            assert!(
                perform(&host, &new, &target, &NORMAL).is_err(),
                "{candidate}"
            );
            assert!(has_version(&target, "0.7.0"));
            let allowed = Options {
                allow_downgrade: true,
                no_restart: false,
            };
            assert!(
                perform(&host, &new, &target, &allowed).is_ok(),
                "{candidate}"
            );
            assert!(has_version(&target, candidate));
        }
    }

    #[test]
    fn no_restart_replaces_the_file_and_leaves_tunnels_alone() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        let host = fake(&target, &["alpha"]);
        let options = Options {
            allow_downgrade: false,
            no_restart: true,
        };
        let outcome = perform(&host, &new, &target, &options).unwrap();
        assert!(matches!(outcome, Outcome::Updated { ref restarted, .. } if restarted.is_empty()));
        assert!(host.restarts.borrow().is_empty());
    }

    

    

    

    #[test]
    fn rollback_swaps_the_two_programs_so_a_second_one_goes_forward() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        let host = fake(&target, &["alpha"]);
        perform(&host, &new, &target, &NORMAL).unwrap();
        host.restarts.borrow_mut().clear();
        let options = Options {
            allow_downgrade: true,
            no_restart: false,
        };
        rollback(&host, &target, &options).unwrap();
        assert!(has_version(&target, "0.7.0"));
        assert!(has_version(&previous_path(&target), "0.7.1"));
        assert_eq!(*host.restarts.borrow(), ["alpha"]);
        rollback(&host, &target, &options).unwrap();
        assert!(has_version(&target, "0.7.1"));
        // Without a previous program there is nothing to go back to.
        std::fs::remove_file(previous_path(&target)).unwrap();
        assert!(rollback(&host, &target, &options).is_err());
    }

    #[test]
    fn rollback_refuses_and_changes_nothing_when_the_previous_program_cannot_read_a_saved_tunnel() {
        let (_directory, target, new) = setup("0.7.0", "0.7.1");
        let mut host = fake(&target, &["alpha"]);
        perform(&host, &new, &target, &NORMAL).unwrap();
        host.restarts.borrow_mut().clear();
        // The newer program saved a field 0.7.0 does not understand.
        host.unreadable_by.push("0.7.0".into());
        let options = Options {
            allow_downgrade: true,
            no_restart: false,
        };
        assert!(rollback(&host, &target, &options).is_err());
        assert!(has_version(&target, "0.7.1"));
        assert!(has_version(&previous_path(&target), "0.7.0"));
        assert!(host.restarts.borrow().is_empty());
    }

    #[test]
    fn a_program_of_another_architecture_or_no_program_at_all_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let elf = |machine: u16| {
            let mut bytes = vec![0x7f, b'E', b'L', b'F'];
            bytes.resize(18, 0);
            bytes[4] = 2;
            bytes[5] = 1;
            bytes.extend_from_slice(&machine.to_le_bytes());
            bytes
        };
        let (x86, arm, text) = (
            directory.path().join("x86"),
            directory.path().join("arm"),
            directory.path().join("text"),
        );
        std::fs::write(&x86, elf(62)).unwrap();
        std::fs::write(&arm, elf(183)).unwrap();
        std::fs::write(&text, "not a program").unwrap();
        assert_eq!(elf_machine(&x86), Some(62));
        assert_eq!(elf_machine(&arm), Some(183));
        assert_eq!(elf_machine(&text), None);
        let mut invalid=elf(183);
        invalid[5]=2;
        std::fs::write(&arm,&invalid).unwrap();
        assert_eq!(elf_machine(&arm),None,"big-endian headers must not be read as little-endian");
        invalid[5]=1;invalid[4]=1;
        std::fs::write(&arm,invalid).unwrap();
        assert_eq!(elf_machine(&arm),None,"32-bit headers are not supported release candidates");
        assert_eq!(elf_machine(&directory.path().join("missing")), None);
    }

    /// A terminal that went away: every write fails.
    struct GoneTerminal;
    impl std::io::Write for GoneTerminal {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(5))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(5))
        }
    }

    #[test]
    fn a_terminal_that_went_away_does_not_stop_the_messages() {
        say_to(
            &mut GoneTerminal,
            "Restarting 1 tunnel(s) and watching them…",
        );
        let mut seen = Vec::new();
        say_to(&mut seen, "next");
        assert_eq!(
            seen,
            b"next
"
        );
    }

    #[test]
    fn the_log_gets_time_stamped_lines_appended() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("update.log");
        append_log(&log, "Updating 0.8.3 → 0.8.4");
        append_log(&log, "Finished.");
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].ends_with(" UTC  Updating 0.8.3 → 0.8.4"),
            "{}",
            lines[0]
        );
        assert!(lines[1].starts_with("20") && lines[1].ends_with("Finished."));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&log).unwrap().permissions().mode();
            assert_eq!(mode & 0o007, 0, "the log is not world-readable");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_hang_up_is_ignored_while_updating() {
        {
            let _hangup = ignore_hangup();
            // SAFETY: SIGHUP is ignored right now; with the default action this would end the
            // test program.
            assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        }
        // The default action is back.
        // SAFETY: only reads and restores the disposition.
        let now = unsafe { libc::signal(libc::SIGHUP, libc::SIG_DFL) };
        assert_eq!(now, libc::SIG_DFL);
    }

    #[test]
    fn the_checksum_is_the_usual_sha256() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("f");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            sha256_hex(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
