//! Claude Code settings.json install/remove/status.

use std::fs;
use std::path::{Path, PathBuf};

use ph_observer::{
    hooks_status, install_hooks, remove_hooks, remove_hooks_for, HookCommand, HookEvent,
    SettingsError,
};
use serde_json::Value;

fn fixture_bytes() -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hooks/settings_with_foreign_hooks.json"),
    )
    .unwrap()
}

struct Env {
    _dir: tempfile::TempDir,
    settings: PathBuf,
    backups: PathBuf,
    root: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    Env {
        settings: root.join("claude/settings.json"),
        backups: root.join("home/backups"),
        root,
        _dir: dir,
    }
}

fn cmd(env: &Env) -> HookCommand {
    HookCommand::new(
        &env.root.join("bin/peerharness"),
        Some(&env.root.join("home")),
    )
    .unwrap()
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

fn backups(env: &Env) -> Vec<PathBuf> {
    match fs::read_dir(&env.backups) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn commands(v: &Value, event: &str) -> Vec<String> {
    v["hooks"][event]
        .as_array()
        .map(|groups| {
            groups
                .iter()
                .flat_map(|g| g["hooks"].as_array().cloned().unwrap_or_default())
                .filter_map(|e| e["command"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Asserts each needle occurs in `hay`, in this order.
fn assert_in_order(hay: &str, needles: &[&str]) {
    let mut from = 0;
    for n in needles {
        let pos = hay[from..]
            .find(n)
            .unwrap_or_else(|| panic!("{n:?} missing or out of order"));
        from += pos + n.len();
    }
}

fn write_settings(env: &Env, bytes: &[u8]) {
    fs::create_dir_all(env.settings.parent().unwrap()).unwrap();
    fs::write(&env.settings, bytes).unwrap();
}

#[test]
fn install_preserves_foreign_content_and_is_idempotent() {
    let env = env();
    let original = fixture_bytes();
    write_settings(&env, &original);
    let c = cmd(&env);

    let r = install_hooks(&env.settings, &c, &env.backups).unwrap();
    assert!(r.changed);
    assert!(!r.created);
    let backup = r.backup_path.clone().unwrap();
    assert_eq!(fs::read(&backup).unwrap(), original);
    let name = backup.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("claude-settings-") && name.ends_with("Z.json"),
        "{name}"
    );
    #[cfg(unix)]
    assert_eq!(mode(&backup), 0o600);

    let after = fs::read_to_string(&env.settings).unwrap();
    assert!(after.ends_with("}\n"));
    assert!(
        after.contains("\n  \"model\": \"opus\""),
        "2-space pretty print"
    );
    let v: Value = serde_json::from_str(&after).unwrap();

    // Key order preserved at top level and in nested objects (serde_json::Value sorts
    // keys, so check positions in the text).
    assert_in_order(
        &after,
        &[
            "\n  \"$schema\"",
            "\n  \"model\"",
            "\n  \"permissions\"",
            "\n  \"hooks\"",
            "\n  \"env\"",
            "\n  \"zzz_last\"",
        ],
    );
    assert_in_order(&after, &["\"ZED\"", "\"ALPHA\""]);
    assert_in_order(&after, &["\"b\": 1", "\"a\": 2"]);
    assert_in_order(
        &after,
        &["\"PreToolUse\"", "\"Stop\"", "\"UserPromptSubmit\""],
    );
    assert_in_order(&after, &["\"matcher\"", "/usr/local/bin/audit-bash"]);
    assert!(after.contains("2.5"));
    let orig: Value = serde_json::from_slice(&original).unwrap();
    for k in ["$schema", "model", "permissions", "env", "zzz_last"] {
        assert_eq!(v[k], orig[k], "{k} preserved");
    }
    assert_eq!(v["hooks"]["PreToolUse"], orig["hooks"]["PreToolUse"]);

    // Our entries: Stop keeps the foreign group first, then ours.
    assert_eq!(
        commands(&v, "Stop"),
        ["say done".to_owned(), c.render(HookEvent::Stop)]
    );
    assert_eq!(
        commands(&v, "UserPromptSubmit"),
        [c.render(HookEvent::UserPromptSubmit)]
    );
    let ours = &v["hooks"]["UserPromptSubmit"][0];
    assert!(ours.get("matcher").is_none());
    assert_eq!(ours["hooks"][0]["type"], "command");
    assert_eq!(ours["hooks"][0]["timeout"], 5);

    // Second install: nothing changes, no new backup.
    let before = fs::read(&env.settings).unwrap();
    let r2 = install_hooks(&env.settings, &c, &env.backups).unwrap();
    assert!(!r2.changed);
    assert_eq!(r2.backup_path, None);
    assert_eq!(fs::read(&env.settings).unwrap(), before);
    assert_eq!(backups(&env).len(), 1);

    let st = hooks_status(&env.settings).unwrap();
    assert!(st.settings_exists);
    assert_eq!(
        st.installed_events,
        [HookEvent::UserPromptSubmit, HookEvent::Stop]
    );
    assert_eq!(st.foreign_hook_count, 2);
    assert!(st.is_installed_for(&c));
    assert_eq!(st.entries.len(), 2);
    assert!(st
        .entries
        .iter()
        .all(|e| e.home.as_deref() == c.home() && e.event == e.command_event));
}

#[test]
fn remove_restores_original_structure() {
    let env = env();
    let original = fixture_bytes();
    write_settings(&env, &original);
    let c = cmd(&env);
    install_hooks(&env.settings, &c, &env.backups).unwrap();

    let r = remove_hooks(&env.settings, &env.backups).unwrap();
    assert!(r.changed);
    assert_eq!(r.removed_entries, 2);
    assert!(r.backup_path.is_some());
    let after = fs::read(&env.settings).unwrap();
    // The fixture is already in our output format, so install + remove restores it
    // byte for byte.
    assert_eq!(
        String::from_utf8(after).unwrap(),
        String::from_utf8(original).unwrap()
    );

    let r2 = remove_hooks(&env.settings, &env.backups).unwrap();
    assert!(!r2.changed);
    assert_eq!(r2.removed_entries, 0);
    assert_eq!(r2.backup_path, None);

    let st = hooks_status(&env.settings).unwrap();
    assert!(st.installed_events.is_empty());
    assert_eq!(st.foreign_hook_count, 2);
    assert!(!st.is_installed_for(&c));
}

#[test]
fn missing_settings_file_is_created_private() {
    let env = env();
    assert!(!env.settings.parent().unwrap().exists());
    let st = hooks_status(&env.settings).unwrap();
    assert!(!st.settings_exists);

    let c = cmd(&env);
    let r = install_hooks(&env.settings, &c, &env.backups).unwrap();
    assert!(r.changed && r.created);
    assert_eq!(r.backup_path, None);
    #[cfg(unix)]
    {
        assert_eq!(mode(&env.settings), 0o600);
        assert_eq!(mode(env.settings.parent().unwrap()), 0o700);
    }
    let v = read_json(&env.settings);
    assert_eq!(v.as_object().unwrap().len(), 1);
    assert_eq!(commands(&v, "Stop"), [c.render(HookEvent::Stop)]);

    // Removing drops everything we created.
    let r = remove_hooks(&env.settings, &env.backups).unwrap();
    assert!(r.changed);
    assert_eq!(fs::read_to_string(&env.settings).unwrap(), "{}\n");
    // Missing file: remove is a no-op.
    let env2 = self::env();
    assert!(!remove_hooks(&env2.settings, &env2.backups).unwrap().changed);
    assert!(!env2.settings.exists());
}

#[test]
fn malformed_settings_are_refused_untouched() {
    let cases: &[(&[u8], &str)] = &[
        (b"{ \"model\": \"opus\", ", "malformed"),
        (b"{\"a\": 1} trailing", "malformed"),
        (b"// comment\n{}", "malformed"),
        (b"{\"hooks\": {}, \"hooks\": {}}", "duplicate"),
        (b"[1, 2]", "structure"),
        (b"{\"hooks\": \"nope\"}", "structure"),
        (b"{\"hooks\": {\"Stop\": {\"hooks\": []}}}", "structure"),
        (b"\xEF\xBB\xBF{}", "malformed"),
    ];
    for (bytes, kind) in cases {
        let env = env();
        write_settings(&env, bytes);
        let err = install_hooks(&env.settings, &cmd(&env), &env.backups).unwrap_err();
        let ok = matches!(
            (*kind, &err),
            ("malformed", SettingsError::Malformed { .. })
                | ("duplicate", SettingsError::DuplicateKey { .. })
                | ("structure", SettingsError::UnexpectedStructure { .. })
        );
        assert!(ok, "{kind}: got {err:?}");
        assert!(err.to_string().contains("Nothing was changed"), "{err}");
        assert_eq!(fs::read(&env.settings).unwrap(), *bytes, "file untouched");
        assert!(backups(&env).is_empty(), "no backup on refusal");
        if *kind != "structure" {
            assert!(remove_hooks(&env.settings, &env.backups).is_err());
            assert!(hooks_status(&env.settings).is_err());
        }
        assert_eq!(fs::read(&env.settings).unwrap(), *bytes);
    }
}

#[test]
fn malformed_error_does_not_echo_contents() {
    let env = env();
    write_settings(
        &env,
        br#"{"env": {"TOKEN": "sk-ant-api03-FAKEFAKEFAKEFAKE" oops}"#,
    );
    let err = install_hooks(&env.settings, &cmd(&env), &env.backups).unwrap_err();
    assert!(!err.to_string().contains("FAKE"));
    assert!(!format!("{err:?}").contains("FAKE"));
}

#[test]
fn moved_binary_updates_in_place_and_dedups() {
    let env = env();
    let home = env.root.join("home");
    let old = HookCommand::new(&env.root.join("old/peerharness"), Some(&home)).unwrap();
    let new = HookCommand::new(&env.root.join("new/peerharness"), Some(&home)).unwrap();
    install_hooks(&env.settings, &old, &env.backups).unwrap();

    // Duplicate our Stop entry by hand (into a group with a foreign hook too).
    let mut v = read_json(&env.settings);
    let dup = v["hooks"]["Stop"][0]["hooks"][0].clone();
    v["hooks"]["Stop"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"hooks": [{"type": "command", "command": "echo keep"}, dup]}));
    fs::write(&env.settings, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    let r = install_hooks(&env.settings, &new, &env.backups).unwrap();
    assert!(r.changed);
    let v = read_json(&env.settings);
    assert_eq!(
        commands(&v, "Stop"),
        [new.render(HookEvent::Stop), "echo keep".to_owned()]
    );
    assert_eq!(
        commands(&v, "UserPromptSubmit"),
        [new.render(HookEvent::UserPromptSubmit)]
    );
    assert!(
        !install_hooks(&env.settings, &new, &env.backups)
            .unwrap()
            .changed
    );
}

#[test]
fn stale_timeout_is_repaired() {
    let env = env();
    let c = cmd(&env);
    install_hooks(&env.settings, &c, &env.backups).unwrap();
    let mut v = read_json(&env.settings);
    v["hooks"]["Stop"][0]["hooks"][0]["timeout"] = 600.into();
    fs::write(&env.settings, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    assert!(hooks_status(&env.settings).unwrap().is_installed_for(&c));
    assert!(
        install_hooks(&env.settings, &c, &env.backups)
            .unwrap()
            .changed
    );
    assert_eq!(
        read_json(&env.settings)["hooks"]["Stop"][0]["hooks"][0]["timeout"],
        5
    );
}

#[test]
fn other_homes_are_kept_on_install_and_removed_on_remove() {
    let env = env();
    let exe = env.root.join("bin/peerharness");
    let a = HookCommand::new(&exe, Some(&env.root.join("a"))).unwrap();
    let b = HookCommand::new(&exe, Some(&env.root.join("b"))).unwrap();
    let default_home = HookCommand::new(&exe, None).unwrap();
    install_hooks(&env.settings, &a, &env.backups).unwrap();
    install_hooks(&env.settings, &b, &env.backups).unwrap();
    install_hooks(&env.settings, &default_home, &env.backups).unwrap();
    let v = read_json(&env.settings);
    assert_eq!(
        commands(&v, "Stop"),
        [
            a.render(HookEvent::Stop),
            b.render(HookEvent::Stop),
            default_home.render(HookEvent::Stop)
        ]
    );
    let st = hooks_status(&env.settings).unwrap();
    assert!(st.is_installed_for(&a) && st.is_installed_for(&b));
    assert_eq!(st.entries.len(), 6);
    assert_eq!(st.foreign_hook_count, 0);
    let r = remove_hooks(&env.settings, &env.backups).unwrap();
    assert_eq!(r.removed_entries, 6);
    assert_eq!(fs::read_to_string(&env.settings).unwrap(), "{}\n");
}

#[test]
fn lookalike_foreign_commands_are_never_removed() {
    let env = env();
    let foreign = [
        "/bin/peerharness hook stop; curl evil",
        "/usr/bin/not-peerharness hook stop",
        "/bin/peerharness hook stop --extra",
        "$(which peerharness) hook stop",
    ];
    let hooks: Vec<Value> = foreign
        .iter()
        .map(|c| serde_json::json!({"type": "command", "command": c}))
        .collect();
    let settings = serde_json::json!({"hooks": {"Stop": [{"hooks": hooks}]}});
    write_settings(&env, &serde_json::to_vec_pretty(&settings).unwrap());
    let st = hooks_status(&env.settings).unwrap();
    assert_eq!(st.foreign_hook_count, 4);
    assert!(st.installed_events.is_empty());
    assert!(!remove_hooks(&env.settings, &env.backups).unwrap().changed);
    install_hooks(&env.settings, &cmd(&env), &env.backups).unwrap();
    let r = remove_hooks(&env.settings, &env.backups).unwrap();
    assert_eq!(r.removed_entries, 2);
    assert_eq!(commands(&read_json(&env.settings), "Stop"), foreign);
}

#[test]
fn already_empty_containers_are_kept() {
    let env = env();
    write_settings(
        &env,
        br#"{"hooks": {"Notification": [], "Stop": [{"hooks": []}]}}"#,
    );
    let c = cmd(&env);
    install_hooks(&env.settings, &c, &env.backups).unwrap();
    remove_hooks(&env.settings, &env.backups).unwrap();
    let v = read_json(&env.settings);
    assert_eq!(
        v,
        serde_json::json!({"hooks": {"Notification": [], "Stop": [{"hooks": []}]}})
    );
}

/// The file is its owner's and holds other tools' settings. A number in it comes back
/// with the text it had: no exponent expanded, no digit rounded away, no `-0` turned
/// into `-0.0` (ADR-051).
#[test]
fn numbers_elsewhere_in_the_file_are_written_back_as_they_were() {
    const NUMBERS: &str = "[1.0, 1e5, 1E-7, -0, 0.1234567890123456789, \
                           12345678901234567890123, 9007199254740993, \
                           18446744073709551616, -9223372036854775809, 1.10]";
    let env = env();
    let before = format!(
        r#"{{"numbers": {NUMBERS}, "env": {{"LIMIT": 2.50, "s": "not 1e5, not -0"}}, "hooks": {{"Stop": [{{"hooks": [{{"type": "command", "command": "say done", "timeout": 30.0}}]}}]}}}}"#
    );
    write_settings(&env, before.as_bytes());
    let c = cmd(&env);
    assert!(
        install_hooks(&env.settings, &c, &env.backups)
            .unwrap()
            .changed
    );
    let squeezed = |p: &Path| -> String {
        fs::read_to_string(p)
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    };
    let wanted: String = NUMBERS.chars().filter(|c| !c.is_whitespace()).collect();
    let after = squeezed(&env.settings);
    assert!(after.contains(&format!(r#""numbers":{wanted}"#)), "{after}");
    assert!(after.contains(r#""LIMIT":2.50"#), "{after}");
    assert!(after.contains(r#""s":"not1e5,not-0""#), "{after}");
    // Another tool's hook keeps its own number, and ours has the one we write.
    assert!(
        after.contains(r#""command":"saydone","timeout":30.0"#),
        "{after}"
    );
    assert!(after.contains(r#""timeout":5}"#), "{after}");
    // A second install changes nothing, and a removal leaves the numbers too.
    assert!(
        !install_hooks(&env.settings, &c, &env.backups)
            .unwrap()
            .changed
    );
    remove_hooks(&env.settings, &env.backups).unwrap();
    let after = squeezed(&env.settings);
    assert!(after.contains(&format!(r#""numbers":{wanted}"#)), "{after}");
    assert!(after.contains(r#""timeout":30.0"#), "{after}");
}

#[cfg(unix)]
#[test]
fn existing_permissions_are_kept() {
    use std::os::unix::fs::PermissionsExt;
    let env = env();
    write_settings(&env, b"{}");
    fs::set_permissions(&env.settings, fs::Permissions::from_mode(0o644)).unwrap();
    install_hooks(&env.settings, &cmd(&env), &env.backups).unwrap();
    assert_eq!(mode(&env.settings), 0o644);
    #[cfg(unix)]
    assert_eq!(mode(&env.backups), 0o700);
}

#[cfg(unix)]
#[test]
fn symlinked_settings_keep_the_link() {
    let env = env();
    let real = env.root.join("dotfiles/claude-settings.json");
    fs::create_dir_all(real.parent().unwrap()).unwrap();
    fs::write(&real, b"{\"model\": \"opus\"}").unwrap();
    fs::create_dir_all(env.settings.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, &env.settings).unwrap();
    install_hooks(&env.settings, &cmd(&env), &env.backups).unwrap();
    assert!(fs::symlink_metadata(&env.settings)
        .unwrap()
        .file_type()
        .is_symlink());
    let v = read_json(&real);
    assert_eq!(v["model"], "opus");
    assert!(v["hooks"]["Stop"].is_array());
}

#[test]
fn backups_never_overwrite_each_other() {
    let env = env();
    write_settings(&env, b"{}");
    let exe = env.root.join("bin/peerharness");
    let mut paths = Vec::new();
    for i in 0..3 {
        let c = HookCommand::new(&exe, Some(&env.root.join(format!("h{i}")))).unwrap();
        paths.push(
            install_hooks(&env.settings, &c, &env.backups)
                .unwrap()
                .backup_path
                .unwrap(),
        );
        paths.push(
            remove_hooks(&env.settings, &env.backups)
                .unwrap()
                .backup_path
                .unwrap(),
        );
    }
    let mut uniq = paths.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), paths.len());
    assert_eq!(backups(&env).len(), 6);
}

/// Runs the rendered command through `sh -c` with a fake `peerharness` living in a
/// directory whose name contains quotes, spaces and shell metacharacters.
#[cfg(unix)]
#[test]
fn rendered_command_is_shell_safe_for_weird_paths() {
    use std::os::unix::fs::PermissionsExt;
    let env = env();
    let weird = env.root.join("we'ird dir \"$HOME\" `id` ; & |*");
    fs::create_dir_all(&weird).unwrap();
    let exe = weird.join("peerharness");
    let out = env.root.join("out.txt");
    fs::write(
        &exe,
        "#!/bin/sh\nprintf '%s|%s|%s' \"$PEERHARNESS_HOME\" \"$1\" \"$2\" > \"$PH_TEST_OUT\"\n",
    )
    .unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let home = env.root.join("h'o me $x");
    let c = HookCommand::new(&exe, Some(&home)).unwrap();
    for event in HookEvent::INSTALLED {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(c.render(event))
            .env("PH_TEST_OUT", &out)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(&out).unwrap(),
            format!("{}|hook|{}", home.to_str().unwrap(), event.cli_arg())
        );
    }
    // And the weird command is still recognised for status and removal.
    install_hooks(&env.settings, &c, &env.backups).unwrap();
    let st = hooks_status(&env.settings).unwrap();
    assert!(st.is_installed_for(&c));
    assert_eq!(st.entries[0].home.as_deref(), home.to_str());
    assert!(
        !install_hooks(&env.settings, &c, &env.backups)
            .unwrap()
            .changed
    );
    assert_eq!(
        remove_hooks(&env.settings, &env.backups)
            .unwrap()
            .removed_entries,
        2
    );
}

#[test]
fn too_large_settings_are_refused() {
    let env = env();
    let mut big = b"{\"x\": \"".to_vec();
    big.resize(ph_observer::settings::MAX_SETTINGS_BYTES as usize + 1, b'a');
    big.extend_from_slice(b"\"}");
    write_settings(&env, &big);
    assert!(matches!(
        install_hooks(&env.settings, &cmd(&env), &env.backups),
        Err(SettingsError::TooLarge { .. })
    ));
    assert_eq!(fs::read(&env.settings).unwrap().len(), big.len());
}

/// Command substitution, quote-breaking and backticks in both paths never execute: a
/// canary file that the injected command would create must not appear.
#[cfg(unix)]
#[test]
fn injection_attempts_in_paths_do_not_execute() {
    use std::os::unix::fs::PermissionsExt;
    let env = env();
    let canary = env.root.join("pwned");
    let c = canary.to_str().unwrap();
    let evil_dir = env
        .root
        .join(format!("x'$(touch {c})'`touch {c}`\"; touch {c}; '"));
    fs::create_dir_all(&evil_dir).unwrap();
    let exe = evil_dir.join("peerharness");
    fs::write(&exe, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let home = env.root.join(format!("h'$(touch {c})'"));
    let cmd = HookCommand::new(&exe, Some(&home)).unwrap();
    for event in HookEvent::ALL {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd.render(event))
            .status()
            .unwrap();
        assert!(status.success());
    }
    assert!(!canary.exists(), "injected command ran");
    // Newlines and other control characters cannot be expressed at all.
    for bad in [
        "/a\nb/peerharness",
        "/a\rb/peerharness",
        "/a\u{0}b/peerharness",
    ] {
        assert!(HookCommand::new(Path::new(bad), None).is_err(), "{bad:?}");
    }
    assert!(HookCommand::new(&exe, Some(Path::new("/h\n$(id)"))).is_err());
}

#[test]
fn remove_hooks_for_only_removes_that_home() {
    let env = env();
    write_settings(&env, &fixture_bytes());
    let exe = env.root.join("bin/peerharness");
    let a = HookCommand::new(&exe, Some(&env.root.join("a"))).unwrap();
    let b = HookCommand::new(&exe, Some(&env.root.join("b"))).unwrap();
    // An install from a renamed binary is found by its exact rendered command.
    let renamed =
        HookCommand::new(&env.root.join("bin/ph-dev"), Some(&env.root.join("c"))).unwrap();
    for c in [&a, &b, &renamed] {
        install_hooks(&env.settings, c, &env.backups).unwrap();
    }
    let r = remove_hooks_for(&env.settings, &a, &env.backups).unwrap();
    assert_eq!(r.removed_entries, 2);
    assert!(r.backup_path.is_some());
    let st = hooks_status(&env.settings).unwrap();
    assert!(!st.is_installed_for(&a));
    assert!(st.is_installed_for(&b));
    // Idempotent.
    assert!(
        !remove_hooks_for(&env.settings, &a, &env.backups)
            .unwrap()
            .changed
    );
    // Renamed binary: not recognised by remove_hooks, but by remove_hooks_for.
    assert_eq!(
        remove_hooks_for(&env.settings, &renamed, &env.backups)
            .unwrap()
            .removed_entries,
        2
    );
    remove_hooks_for(&env.settings, &b, &env.backups).unwrap();
    // Back to the original structure (foreign hooks and unrelated keys intact).
    assert_eq!(
        read_json(&env.settings),
        serde_json::from_slice::<Value>(&fixture_bytes()).unwrap()
    );
    // Missing file is fine.
    let other = env.root.join("nope/settings.json");
    assert!(!remove_hooks_for(&other, &a, &env.backups).unwrap().changed);
}

/// A FIFO (or directory) at the settings path is refused immediately instead of blocking.
#[cfg(unix)]
#[test]
fn non_regular_settings_path_is_refused_without_blocking() {
    use std::sync::mpsc;
    use std::time::Duration;
    let env = env();
    fs::create_dir_all(env.settings.parent().unwrap()).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&env.settings)
        .status()
        .unwrap()
        .success());
    let (tx, rx) = mpsc::channel();
    let (s, b) = (env.settings.clone(), env.backups.clone());
    let c = cmd(&env);
    std::thread::spawn(move || {
        let _ = tx.send((
            install_hooks(&s, &c, &b).map(|_| ()),
            hooks_status(&s).map(|_| ()),
            remove_hooks(&s, &b).map(|_| ()),
        ));
    });
    let (i, st, r) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("settings code blocked on a FIFO");
    assert!(matches!(i, Err(SettingsError::NotAFile)));
    assert!(matches!(st, Err(SettingsError::NotAFile)));
    assert!(matches!(r, Err(SettingsError::NotAFile)));
    assert!(backups(&env).is_empty());

    let env2 = super_env_dir();
    assert!(matches!(
        install_hooks(&env2.settings, &cmd(&env2), &env2.backups),
        Err(SettingsError::NotAFile)
    ));
}

fn super_env_dir() -> Env {
    let e = env();
    fs::create_dir_all(&e.settings).unwrap();
    e
}
