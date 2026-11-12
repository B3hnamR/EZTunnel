//! Small operating-system helpers.

/// Sanity bound used when no limit is configured; some container setups report an enormous hard limit.
const DEFAULT_CAP: u64 = 1_048_576;

/// Raises the soft limit on open files so a busy tunnel does not start refusing users when it
/// needs many sockets. With `requested` it aims for that many (never above the hard limit);
/// otherwise it uses the hard limit, capped at a sanity bound. Returns the limit now in effect.
// `rlim_t` is 32 bits wide on some Linux targets, so the casts below are not always no-ops.
#[allow(clippy::unnecessary_cast)]
#[cfg(target_os = "linux")]
pub fn raise_open_file_limit(requested: Option<u64>) -> std::io::Result<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit struct for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let goal = requested.unwrap_or(DEFAULT_CAP) as libc::rlim_t;
    let wanted = limit.rlim_max.min(goal);
    if wanted > limit.rlim_cur {
        let raised = libc::rlimit {
            rlim_cur: wanted,
            rlim_max: limit.rlim_max,
        };
        // SAFETY: `raised` is a valid rlimit struct; the soft limit does not exceed the hard limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(wanted as u64);
    }
    Ok(limit.rlim_cur as u64)
}

#[cfg(not(target_os = "linux"))]
pub fn raise_open_file_limit(_requested: Option<u64>) -> std::io::Result<u64> {
    Ok(0)
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unnecessary_cast)]
mod tests {
    #[test]
    fn open_file_limit_never_goes_down() {
        let before = {
            let mut l = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid pointer to a local struct.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) }, 0);
            l.rlim_cur as u64
        };
        let after = super::raise_open_file_limit(None).unwrap();
        assert!(after >= before);
    }
}

/// Completes when the process is asked to stop: Ctrl-C, or SIGTERM (what `systemctl stop` sends).
pub async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
