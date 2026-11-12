//! `peerharness doctor`: local diagnostics only. No network calls, never unlocks keys.
//!
//! A binary built with debug assertions says so in a line of its own ([`DEBUG_BUILD`]):
//! such a build obeys the `PEERHARNESS_TEST_*` stand-ins, so whoever sets its environment
//! can name the program that answers a confirmation window. It is a line and never a
//! refusal: the test suite runs debug builds.

use anyhow::Result;
use ph_identity::{DeviceIdentity, KeystoreBackend, OsKeyStore};
use ph_store::Store;
use serde_json::json;

use super::{claude_settings_path, hook_command, Ctx};
use crate::config::{Config, KdfProfile};
use crate::daemon_info::DaemonInfo;
use crate::home::mode_of;
use crate::node::open_keystore_no_unlock;
use crate::output::{Report, Text};

/// What `doctor` says about a binary built with debug assertions. Release builds do not
/// read the stand-ins and print nothing.
pub const DEBUG_BUILD: &str = "debug build: it obeys the PEERHARNESS_TEST_* stand-ins that \
    the tests use in place of a confirmation window, a notification and Claude Code's \
    `claude` command. It is for development and tests, not for daily use; a release build \
    does not read them.";

/// What `status` says about it, in its list.
pub const DEBUG_BUILD_SHORT: &str = "debug: for development and tests, not for daily use";

/// Whether this binary obeys the test stand-ins.
pub const fn is_debug_build() -> bool {
    cfg!(debug_assertions)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

struct Checks(Vec<(&'static str, Level, String)>);

impl Checks {
    fn add(&mut self, name: &'static str, level: Level, detail: impl Into<String>) {
        self.0.push((name, level, detail.into()));
    }
}

pub fn run(ctx: &Ctx) -> Result<Report> {
    let home = &ctx.home;
    let mut c = Checks(Vec::new());

    // The binary itself, before anything about the home: it holds without one.
    if is_debug_build() {
        c.add("build", Level::Warn, DEBUG_BUILD);
    }

    // Home directory.
    if !home.root().is_dir() {
        c.add(
            "home",
            Level::Fail,
            format!(
                "{} does not exist: run `peerharness init`",
                home.root().display()
            ),
        );
        return finish(c);
    }
    match mode_of(home.root()) {
        Some(m) if m & 0o077 != 0 => c.add(
            "home",
            Level::Warn,
            format!("permissions {m:o}; expected 700 (run `chmod 700`)"),
        ),
        _ => c.add("home", Level::Ok, home.root().display().to_string()),
    }

    // Config.
    let cfg = if home.config_path().is_file() {
        match Config::load(home) {
            Ok(cfg) => {
                match mode_of(&home.config_path()) {
                    Some(m) if m & 0o077 != 0 => c.add(
                        "config",
                        Level::Warn,
                        format!("config.toml permissions {m:o}; expected 600"),
                    ),
                    _ => c.add("config", Level::Ok, "config.toml parses"),
                }
                if cfg.node.kdf_profile == KdfProfile::FastInsecureTest {
                    c.add(
                        "kdf",
                        Level::Warn,
                        "fast-insecure-test KDF profile (tests and demos only)",
                    );
                }
                if cfg.learning.provider.is_active() {
                    // No command calls a provider in this version (ADR-051): say what
                    // the setting does today, and what it would do.
                    c.add(
                        "provider",
                        Level::Warn,
                        format!(
                            "advisory provider `{}` is set in config.toml. No command of \
                             this version calls one; a remote provider would send previewed \
                             text off this device",
                            cfg.learning.provider.kind
                        ),
                    );
                } else {
                    c.add("provider", Level::Ok, "no advisory provider (fully local)");
                }
                Some(cfg)
            }
            Err(e) => {
                c.add("config", Level::Fail, format!("{e:#}"));
                None
            }
        }
    } else {
        c.add(
            "config",
            Level::Fail,
            "config.toml missing: run `peerharness init`",
        );
        None
    };

    // Database.
    let mut backend: Option<KeystoreBackend> = None;
    if home.db_path().is_file() {
        match Store::open(home.db_path()) {
            Ok(store) => {
                match store.quick_check() {
                    Ok(true) => c.add(
                        "database",
                        Level::Ok,
                        format!("schema v{}", store.schema_version().unwrap_or(0)),
                    ),
                    Ok(false) => c.add("database", Level::Fail, "integrity check failed"),
                    Err(e) => c.add("database", Level::Fail, e.to_string()),
                }
                if let Some(m) = mode_of(&home.db_path()) {
                    if m & 0o077 != 0 {
                        c.add(
                            "database perms",
                            Level::Warn,
                            format!("permissions {m:o}; expected 600"),
                        );
                    }
                }
                match store.identity() {
                    Ok(Some(id)) => {
                        c.add(
                            "identity",
                            Level::Ok,
                            format!("{} ({})", id.device_key.fingerprint(), id.keystore_backend),
                        );
                        backend = id.keystore_backend.parse().ok();
                    }
                    Ok(None) => c.add(
                        "identity",
                        Level::Fail,
                        "no device identity: run `peerharness init`",
                    ),
                    Err(e) => c.add("identity", Level::Fail, e.to_string()),
                }
                match store.peers() {
                    Ok(peers) => c.add(
                        "peers",
                        Level::Ok,
                        format!(
                            "{} known, {} with an address to sync with",
                            peers.len(),
                            peers.iter().filter(|p| !p.addrs.is_empty()).count()
                        ),
                    ),
                    Err(e) => c.add("peers", Level::Warn, e.to_string()),
                }
                match store.bundles() {
                    Ok(rows) => {
                        let bs = ph_skills::BundleStore::new(home.bundles_dir());
                        let bad = rows.iter().filter(|b| bs.get(&b.digest).is_err()).count();
                        if bad == 0 {
                            c.add(
                                "bundles",
                                Level::Ok,
                                format!("{} bundles verified", rows.len()),
                            );
                        } else {
                            c.add(
                                "bundles",
                                Level::Fail,
                                format!("{bad} of {} stored bundles fail verification", rows.len()),
                            );
                        }
                    }
                    Err(e) => c.add("bundles", Level::Warn, e.to_string()),
                }
            }
            Err(e) => c.add("database", Level::Fail, e.to_string()),
        }
    } else {
        c.add(
            "database",
            Level::Fail,
            "peerharness.db missing: run `peerharness init`",
        );
    }

    // Keystore (existence only, never unlocks).
    if let Some(b) = backend {
        if b == KeystoreBackend::Os {
            if let Err(e) = OsKeyStore::check_available() {
                c.add("keystore", Level::Fail, e.to_string());
            }
        }
        match open_keystore_no_unlock(home, b).and_then(|ks| Ok(DeviceIdentity::exists(&*ks)?)) {
            Ok(true) => c.add(
                "keystore",
                if b == KeystoreBackend::InsecureDev {
                    Level::Warn
                } else {
                    Level::Ok
                },
                format!(
                    "device key present ({b}{})",
                    if b == KeystoreBackend::InsecureDev {
                        ", PLAINTEXT"
                    } else {
                        ""
                    }
                ),
            ),
            Ok(false) => c.add(
                "keystore",
                Level::Fail,
                "device key missing from the keystore",
            ),
            Err(e) => c.add("keystore", Level::Fail, format!("{e:#}")),
        }
        if b != KeystoreBackend::Os {
            if let Some(m) = mode_of(&home.keys_dir()) {
                if m & 0o077 != 0 {
                    c.add(
                        "keys dir",
                        Level::Fail,
                        format!("permissions {m:o}; expected 700"),
                    );
                }
            }
        }
    }

    // Spool.
    let spool = home.spool_path();
    match std::fs::symlink_metadata(&spool) {
        Ok(m) if m.file_type().is_symlink() => {
            c.add("spool", Level::Fail, "the spool file is a symlink")
        }
        Ok(m) => c.add("spool", Level::Ok, format!("{} bytes waiting", m.len())),
        Err(_) => c.add("spool", Level::Ok, "empty"),
    }

    // Hooks.
    match (claude_settings_path(None), hook_command(home)) {
        (Ok(p), Ok(cmd)) => match ph_observer::hooks_status(&p) {
            Ok(st) if st.is_installed_for(&cmd) => c.add("claude hooks", Level::Ok, format!("installed in {}", p.display())),
            Ok(st) if !st.entries.is_empty() => c.add("claude hooks", Level::Warn, format!("{} PeerHarness entries in {} but not for this binary/home; re-run `peerharness watch claude --install`", st.entries.len(), p.display())),
            Ok(_) => c.add("claude hooks", Level::Ok, "not installed (optional)"),
            Err(e) => c.add("claude hooks", Level::Warn, format!("{}: {e}", p.display())),
        },
        (Err(e), _) | (_, Err(e)) => c.add("claude hooks", Level::Warn, format!("{e:#}")),
    }

    // Skills dir.
    match ph_skills::claude_skills_dir(ph_skills::SkillScope::User, std::path::Path::new(".")) {
        Ok(p) => c.add("skills dir", Level::Ok, p.display().to_string()),
        Err(e) => c.add("skills dir", Level::Warn, e.to_string()),
    }

    // The other agents (ADR-050): where their copies are, and what could not follow.
    if let Ok(config) = crate::config::Config::load(home) {
        let store = crate::node::Node::open(home).ok();
        let synced = crate::copies::sync(&config, store.as_ref().map(|n| &n.store));
        for agent in &config.agents.connected {
            let name = agent.check_name();
            match agent.paths() {
                None => c.add(
                    name,
                    Level::Warn,
                    format!(
                        "connected, but this build looks for its files only under {}",
                        crate::agents::AGENTS_HOME_ENV
                    ),
                ),
                Some(p) => match p.skills {
                    None => c.add(name, Level::Ok, "connected; reads Claude Code's skills"),
                    Some(dir) => {
                        let mine: Vec<_> =
                            synced.iter().filter(|s| s.agents.contains(agent)).collect();
                        let blocked: usize = mine.iter().map(|s| s.report.blocked.len()).sum();
                        let level = if blocked == 0 { Level::Ok } else { Level::Warn };
                        let mut detail = format!("connected; copies in {}", dir.display());
                        if blocked > 0 {
                            detail.push_str(&format!(" ({blocked} skill(s) could not follow: see the warnings after any command that changes a rule)"));
                        }
                        c.add(name, level, detail);
                    }
                },
            }
        }
    }

    // Daemon file.
    match (DaemonInfo::running(home), DaemonInfo::read(home)) {
        (Some(d), _) => {
            c.add("daemon", Level::Ok, format!("running (pid {})", d.pid));
            if let Some(i) = &d.internet {
                // Behind a router without a relay, nobody can reach this node.
                let level = if i.joined && (i.reachability == "public" || i.relays > 0) {
                    Level::Ok
                } else {
                    Level::Warn
                };
                c.add("internet", level, i.summary());
            }
        }
        (None, Ok(Some(_))) => c.add(
            "daemon",
            Level::Warn,
            "not running, and a daemon.json was left behind by one that stopped uncleanly",
        ),
        (None, Ok(None)) => c.add("daemon", Level::Ok, "not running"),
        (None, Err(e)) => c.add("daemon", Level::Warn, format!("{e:#}")),
    }
    let _ = cfg;
    finish(c)
}

fn finish(c: Checks) -> Result<Report> {
    let worst = c.0.iter().map(|x| x.1).max().unwrap_or(Level::Ok);
    let json = json!({
        "ok": worst != Level::Fail,
        "checks": c.0.iter().map(|(n, l, d)| json!({"check": n, "level": l.as_str(), "detail": d})).collect::<Vec<_>>(),
    });
    let mut t = Text::new();
    for (n, l, d) in &c.0 {
        t.line(format!("[{:>4}] {n:<15} {d}", l.as_str()));
    }
    t.line(match worst {
        Level::Ok => "All checks passed.",
        Level::Warn => "Some checks have warnings.",
        Level::Fail => "Some checks FAILED.",
    });
    let mut r = Report::new(json, t.finish());
    if worst == Level::Fail {
        r.exit = Some(crate::error::ExitKind::Runtime);
    }
    Ok(r)
}
