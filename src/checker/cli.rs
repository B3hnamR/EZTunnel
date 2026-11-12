//! `eztunnel check start|join`: the checker without the menu, for scripts and plain terminals.
//! Progress goes to standard error, one line per step; the report goes to standard output.
use super::{Report, Side, Verdict, code::CheckCode, control::Command, run};
use anyhow::{Context, Result};
use std::{collections::HashSet, path::Path, time::Duration};

pub async fn run(code: CheckCode, me: Side, json: Option<&Path>) -> Result<Report> {
    super::logbuf::capture();
    let mut handle = run::spawn(code, me);
    let mut last_step = String::new();
    let mut reported = HashSet::new();
    let mut stopping = false;
    let report = loop {
        tokio::select! {
            changed = handle.view.changed() => {
                if changed.is_err() {
                    continue;
                }
                let view = handle.view.borrow_and_update().clone();
                if view.step != last_step {
                    eprintln!("· {}", view.step);
                    last_step = view.step.clone();
                }
                for row in &view.rows {
                    if let Some(verdict) = row.verdict
                        && reported.insert(row.spec.id)
                        && verdict != Verdict::Skipped
                    {
                        eprintln!(
                            "  {} · {} dials: {}{}",
                            row.spec.transport_name(),
                            row.spec.dialer_label(),
                            verdict.label(),
                            row.note.as_ref().map_or(String::new(), |n| format!(" ({n})"))
                        );
                    }
                }
            }
            result = &mut handle.task => break result.context("the check failed")??,
            _ = tokio::signal::ctrl_c(), if !stopping => {
                stopping = true;
                eprintln!("· stopping: removing the test tunnels");
                let _ = handle.commands.send(Command::Stop);
            }
            () = tokio::time::sleep(Duration::from_secs(3600)) => {}
        }
    };
    if let Some(path) = json {
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("save the report to {}", path.display()))?;
    }
    print!("{}", report.text());
    Ok(report)
}
