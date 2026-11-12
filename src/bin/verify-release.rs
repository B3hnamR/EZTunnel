//! Verify an official update file. This does not inspect the running executable.
use anyhow::{Context, Result, ensure};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().context("usage: verify-release <candidate>")?;
    ensure!(args.next().is_none(), "usage: verify-release <candidate>");
    let bytes = std::fs::read(&path).context("read candidate")?;
    let outcome = eztunnel::release::verify_bytes(&bytes);
    println!("{outcome:?}");
    ensure!(outcome == eztunnel::release::Outcome::Verified, "candidate is not an authenticated official release");
    Ok(())
}
