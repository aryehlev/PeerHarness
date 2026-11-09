//! Environment-variable binary resolution and child environment scrubbing.
//!
//! This is the only test in its binary because it mutates the process environment.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ph_learning::providers::{resolve_binary, CLAUDE_BIN_ENV, CODEX_BIN_ENV};
use ph_learning::{
    build_provider, AdvisoryPurpose, AdvisoryRequest, ClaudeCodeCli, CodexCli, ProviderConfig,
    ProviderKind,
};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
        .unwrap();
    f.sync_all().unwrap();
    drop(f);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn env_resolution_and_scrubbing() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("env.txt");
    let bin = script(
        dir.path(),
        "fake-claude",
        &format!(
            "cat >/dev/null\nprintf '%s|%s' \"${{PEERHARNESS_PASSPHRASE:-unset}}\" \"${{PEERHARNESS_ADVISORY_CHILD:-unset}}\" > '{}'\n\
             echo '{{\"type\":\"result\",\"is_error\":false,\"result\":\"ok\"}}'",
            marker.display()
        ),
    );

    // Defaults when unset.
    std::env::remove_var(CLAUDE_BIN_ENV);
    std::env::remove_var(CODEX_BIN_ENV);
    assert_eq!(
        resolve_binary(None, CLAUDE_BIN_ENV, "claude"),
        PathBuf::from("claude")
    );
    assert_eq!(ClaudeCodeCli::from_env().binary(), Path::new("claude"));
    assert_eq!(CodexCli::from_env().binary(), Path::new("codex"));

    // Empty value counts as unset.
    std::env::set_var(CLAUDE_BIN_ENV, "");
    assert_eq!(
        resolve_binary(None, CLAUDE_BIN_ENV, "claude"),
        PathBuf::from("claude")
    );

    std::env::set_var(CLAUDE_BIN_ENV, &bin);
    std::env::set_var("PEERHARNESS_PASSPHRASE", "do-not-forward-this");
    assert_eq!(ClaudeCodeCli::from_env().binary(), bin.as_path());
    // Explicit beats env.
    assert_eq!(
        resolve_binary(Some(Path::new("/x/claude")), CLAUDE_BIN_ENV, "claude"),
        PathBuf::from("/x/claude")
    );

    let cfg = ProviderConfig {
        kind: ProviderKind::ClaudeCode,
        enabled: true,
        ..ProviderConfig::default()
    };
    let p = build_provider(&cfg).unwrap().unwrap();
    let resp = p
        .complete(&AdvisoryRequest::new(AdvisoryPurpose::RefineCandidate, "x"))
        .unwrap();
    assert_eq!(resp.text, "ok");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "unset|1");

    std::env::remove_var(CLAUDE_BIN_ENV);
    std::env::remove_var("PEERHARNESS_PASSPHRASE");
}
