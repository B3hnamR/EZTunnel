//! CLI contract exercised through the actual binary, including validation performed
//! after Clap parses root-level options. No Dashboard login or external services.
#![cfg(feature = "dashboard")]

use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_eztunnel");

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("run EZTunnel binary")
}

fn assert_json_input_error(args: &[&str]) {
    let output = run(args);
    let body: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap_or_else(|_| {
        panic!(
            "expected JSON stderr for {args:?}: {:?}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(output.status.code(), Some(2), "{args:?}: {body}");
    assert!(output.stdout.is_empty(), "{args:?}");
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "invalid_input");
    assert_eq!(body["http_status"], serde_json::Value::Null);
}

#[test]
fn fleet_rejects_incompatible_root_options_as_json() {
    // These parse successfully; the shared root-level validation runs afterward.
    // The nonexistent config must never be opened or followed by a login prompt.
    assert_json_input_error(&["--config", "/nonexistent/eztunnel.json", "fleet", "servers"]);
    assert_json_input_error(&["--gen", "server", "fleet", "servers"]);
}

#[test]
fn fleet_rejects_parser_and_value_errors_as_json() {
    assert_json_input_error(&["fleet", "start"]);
    assert_json_input_error(&["fleet", "unknown-subcommand"]);
    assert_json_input_error(&["fleet", "logs", "qa-test", "--lines", "bad"]);
    assert_json_input_error(&["fleet", "logs", "qa-test", "--lines", "0"]);
}

#[test]
fn fleet_parser_failures_with_prefixed_root_options_are_json() {
    assert_json_input_error(&["--badflag", "fleet", "servers"]);
    assert_json_input_error(&[
        "--config",
        "/nonexistent/eztunnel.json",
        "fleet",
        "unknown-subcommand",
    ]);
    assert_json_input_error(&["--gen", "server", "fleet", "start"]);
    assert_json_input_error(&["--config=/nonexistent/eztunnel.json", "fleet", "start"]);
    assert_json_input_error(&[
        "-c",
        "/nonexistent/eztunnel.json",
        "fleet",
        "logs",
        "qa-test",
        "--lines",
        "bad",
    ]);
    assert_json_input_error(&[
        "--gen", "server", "fleet", "logs", "qa-test", "--lines", "0",
    ]);
}

#[test]
fn help_and_non_fleet_errors_remain_human_readable() {
    for args in [
        &["fleet", "--help"][..],
        &["--config", "/nonexistent/eztunnel.json", "fleet", "--help"][..],
        &["--help"][..],
        &["--version"][..],
    ] {
        let output = run(args);
        assert!(
            output.status.success(),
            "{args:?}: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for args in [
        &["--config", "/nonexistent/eztunnel.json", "key"][..],
        &["--gen", "server", "key"][..],
        &["--config", "fleet", "key"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("subcommands cannot be combined"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn missing_root_option_values_do_not_misidentify_fleet() {
    // Even if "fleet" appears later, Clap fails on the missing root value first.
    // These errors belong to the root CLI, not the fleet JSON interface.
    for args in [
        &["--gen", "--config", "fleet"][..],
        &["--config", "--gen", "fleet"][..],
        &["-c", "--gen", "fleet"][..],
        &["--gen", "-c", "fleet"][..],
        &["--gen", "--", "fleet"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with("error: "),
            "{args:?}: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn non_fleet_parser_errors_stay_human_readable() {
    for args in [
        &["key", "fleet"][..],
        &["--config", "fleet", "unknown-subcommand"][..],
        &["--badflag", "key"][..],
        &["--", "fleet", "servers"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with("error: "),
            "{args:?}"
        );
    }
}

#[test]
fn upstream_012_preset_and_rename_cli_shapes_reach_dashboard_client() {
    // A missing state directory is deliberately used: parse must succeed without
    // installing, logging in, or touching a tunnel.
    let prefix = ["fleet", "--state-dir", "/nonexistent/eztunnel-fleet-qa-012"];
    for suffix in [
        & ["preset", "qa-tunnel", "--server", "local", "--preset", "gaming"][..],
        & ["preset", "qa-tunnel", "--preset", "balanced", "--write"][..],
        & ["rename-server", "local", "--name", "New name"][..],
        & ["rename-server", "local", "--name", ""][..],
    ] {
        let args = prefix.iter().copied().chain(suffix.iter().copied()).collect::<Vec<_>>();
        let output = run(&args);
        let body: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(7), "{args:?}: {body}");
        assert_eq!(body["error"], "dashboard_not_configured", "{args:?}: {body}");
        assert!(output.stdout.is_empty());
    }
    assert_json_input_error(&["fleet", "preset", "qa-tunnel"]);
    assert_json_input_error(&["fleet", "rename-server", "local"]);
}
