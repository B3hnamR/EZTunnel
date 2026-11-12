//! `--gen server` and `--gen client` must print JSON that becomes a valid configuration as soon as
//! the placeholder is replaced with a real tunnel key.

use std::process::Command;

use anyhow::Result;
use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_eztunnel")
}

fn generate(role: &str) -> Result<String> {
    let output = Command::new(binary()).args(["--gen", role]).output()?;
    anyhow::ensure!(output.status.success(), "--gen {role} failed");
    Ok(String::from_utf8(output.stdout)?)
}

fn new_key() -> Result<String> {
    let output = Command::new(binary()).arg("key").output()?;
    anyhow::ensure!(output.status.success(), "key failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Writes a configuration readable only by its owner, as a tunnel key requires.
fn write_private(path: &std::path::Path, text: &str) -> Result<()> {
    std::fs::write(path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn check(config: &std::path::Path) -> Result<bool> {
    Ok(Command::new(binary())
        .arg("--config")
        .arg(config)
        .arg("--check")
        .output()?
        .status
        .success())
}

#[test]
fn generated_templates_are_json_with_an_explanatory_note() -> Result<()> {
    for role in ["server", "client"] {
        let value: Value = serde_json::from_str(&generate(role)?)?;
        assert_eq!(value["mode"], role);
        assert!(value["_comment"].as_str().is_some_and(|c| !c.is_empty()));
    }
    let server: Value = serde_json::from_str(&generate("server")?)?;
    assert!(
        server["_comment"].as_str().unwrap().contains("0.0.0.0"),
        "the server note must explain how to accept users from other machines"
    );
    Ok(())
}

#[test]
fn templates_with_a_real_key_pass_the_check_and_placeholders_do_not() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let key = new_key()?;
    let server_text = generate("server")?;
    let client_text = generate("client")?;
    let server_path = directory.path().join("server.json");
    let client_path = directory.path().join("client.json");

    // Untouched templates must be refused: they still hold the placeholder key.
    write_private(&server_path, &server_text)?;
    write_private(&client_path, &client_text)?;
    assert!(
        !check(&server_path)?,
        "server template with a placeholder was accepted"
    );
    assert!(
        !check(&client_path)?,
        "client template with a placeholder was accepted"
    );

    write_private(
        &server_path,
        &server_text.replace("REPLACE-WITH-THE-TUNNEL-KEY", &key),
    )?;
    write_private(
        &client_path,
        &client_text.replace("REPLACE-WITH-THE-TUNNEL-KEY", &key),
    )?;
    assert!(
        check(&server_path)?,
        "server template with a key was refused"
    );
    assert!(
        check(&client_path)?,
        "client template with a key was refused"
    );
    Ok(())
}
