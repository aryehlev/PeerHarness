//! Install, remove and inspect PeerHarness hook entries in a Claude Code `settings.json`.
//!
//! Layout written (verified against the Claude Code hooks documentation):
//!
//! ```json
//! {
//!   "hooks": {
//!     "UserPromptSubmit": [
//!       { "hooks": [ { "type": "command",
//!                      "command": "PEERHARNESS_HOME='/h' '/bin/peerharness' hook user-prompt-submit",
//!                      "timeout": 5 } ] }
//!     ],
//!     "Stop": [ { "hooks": [ { "type": "command", "command": "... hook stop", "timeout": 5 } ] } ]
//!   }
//! }
//! ```
//!
//! No `matcher` is written: `UserPromptSubmit` and `Stop` do not support one.
//!
//! # Which entries are ours
//!
//! A hook entry is a PeerHarness entry when its `command` splits (with a strict POSIX
//! word splitter that rejects every shell metacharacter) into exactly
//! `[PEERHARNESS_HOME=<home>] <exe> hook <event-arg>` where `<exe>`'s file name is
//! `peerharness` (or `peerharness.exe`), or when it equals a command
//! [`HookCommand::render`] produces for the install in progress. Everything else is a
//! foreign entry and is never modified.
//!
//! * [`install_hooks`] replaces our entries **for the same home** (same
//!   `PEERHARNESS_HOME`, or none) in place, so a moved binary is updated rather than
//!   duplicated, and leaves entries for other homes alone.
//! * [`remove_hooks`] removes every PeerHarness entry (any home), then drops groups,
//!   event arrays and the `hooks` object that became empty because of the removal.
//! * [`remove_hooks_for`] does the same for one home only (plus exact matches of the
//!   given [`HookCommand`]'s rendered commands, which also covers a renamed binary).
//!
//! # Safety of the rewrite
//!
//! * The file is parsed with key order preserved and rewritten pretty-printed with two
//!   spaces and a trailing newline. Values are kept exactly; whitespace and formatting
//!   of the original are not (JSON has no lossless round trip through serde).
//! * Nothing is written when nothing changes (idempotence).
//! * Malformed JSON, duplicate keys, a non-object top level, a non-object `hooks`, a
//!   non-array event value, or a settings path that is not a regular file (a FIFO is
//!   detected without blocking) are refused with an actionable error and the file is left
//!   untouched.
//! * An existing file is always backed up first to
//!   `backups_dir/claude-settings-<YYYYMMDDTHHMMSSZ>.json` (0600).
//! * The new content is written to a temp file in the same directory and renamed over
//!   the original (keeping its permission bits); a new file is created 0600 together
//!   with its parent directory (0700). If the settings path is a symlink, the symlink's
//!   target is updated and the link is kept.
//! * Just before the rename the file is re-read; if it changed since it was parsed the
//!   operation aborts with [`SettingsError::ConcurrentModification`].

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ph_core::Timestamp;
use serde_json::Value;

use crate::fsutil::{
    ensure_private_dir, existing_mode, parent_dir, read_capped, write_atomic, write_new_private,
    CappedRead, PRIVATE_FILE_MODE,
};
use crate::hook::HookEvent;
use crate::json_doc::{Doc, Obj, DUPLICATE_KEY_MSG};
use crate::shell::{quote, split_words};

/// Largest settings file we will parse and rewrite (4 MiB).
pub const MAX_SETTINGS_BYTES: u64 = 4 * 1024 * 1024;

/// The hook `timeout` we install, in seconds.
pub const HOOK_TIMEOUT_SECS: u64 = 5;

/// The environment variable that selects the PeerHarness home.
pub const HOME_ENV_VAR: &str = "PEERHARNESS_HOME";

/// File name prefix of settings backups.
pub const BACKUP_PREFIX: &str = "claude-settings-";

/// Settings errors. `Display` is actionable and never includes file contents.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// The settings file is not valid JSON.
    #[error(
        "Claude Code settings file is not valid JSON (line {line}, column {column}); fix or move it and retry. Nothing was changed"
    )]
    Malformed {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// The settings file has a duplicate object key, which a rewrite would silently drop.
    #[error(
        "Claude Code settings file contains a duplicate key (near line {line}, column {column}); remove the duplicate and retry. Nothing was changed"
    )]
    DuplicateKey {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// Valid JSON, but not the documented shape where we need to edit it.
    #[error(
        "Claude Code settings file has an unexpected structure ({what}); fix it by hand and retry. Nothing was changed"
    )]
    UnexpectedStructure {
        /// Which part is wrong (static text).
        what: &'static str,
    },
    /// The file is larger than [`MAX_SETTINGS_BYTES`].
    #[error("Claude Code settings file is larger than {max} bytes; refusing to rewrite it. Nothing was changed")]
    TooLarge {
        /// The limit.
        max: u64,
    },
    /// The settings path exists but is not a regular file (a directory, FIFO, device...).
    #[error("Claude Code settings path is not a regular file; move it aside and retry. Nothing was changed")]
    NotAFile,
    /// The file changed while we were updating it.
    #[error("Claude Code settings file changed while PeerHarness was updating it; retry. It was not overwritten")]
    ConcurrentModification,
    /// A path given to [`HookCommand::new`] is relative.
    #[error("the {which} path for the hook command must be absolute")]
    RelativePath {
        /// `"executable"` or `"home"`.
        which: &'static str,
    },
    /// A path given to [`HookCommand::new`] is not valid UTF-8.
    #[error("the {which} path for the hook command is not valid UTF-8")]
    NonUtf8Path {
        /// `"executable"` or `"home"`.
        which: &'static str,
    },
    /// A path given to [`HookCommand::new`] contains control characters.
    #[error("the {which} path for the hook command contains control characters")]
    ControlCharInPath {
        /// `"executable"` or `"home"`.
        which: &'static str,
    },
    /// A filesystem operation failed.
    #[error("{op} failed: {kind}")]
    Io {
        /// What we were doing (static text).
        op: &'static str,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
}

fn io_err(op: &'static str) -> impl FnOnce(io::Error) -> SettingsError {
    move |e| SettingsError::Io { op, kind: e.kind() }
}

/// The user-level Claude Code settings path: `$CLAUDE_CONFIG_DIR/settings.json` when
/// `claude_config_dir` is given, else `<user_home>/.claude/settings.json`. Pure; the
/// caller reads the environment.
pub fn claude_user_settings_path(user_home: &Path, claude_config_dir: Option<&Path>) -> PathBuf {
    match claude_config_dir {
        Some(d) => d.join("settings.json"),
        None => user_home.join(".claude").join("settings.json"),
    }
}

/// The command line Claude Code runs for our hooks.
///
/// Rendered as `PEERHARNESS_HOME='<home>' '<exe>' hook <event-arg>` (the
/// `PEERHARNESS_HOME=` prefix only when a home is given). Both paths are always
/// single-quoted, with `'` written as `'\''`, so any path is safe for `sh -c`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HookCommand {
    exe: String,
    home: Option<String>,
}

impl fmt::Debug for HookCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HookCommand")
            .field("exe", &self.exe)
            .field("home", &self.home)
            .finish()
    }
}

fn check_path<'a>(p: &'a Path, which: &'static str) -> Result<&'a str, SettingsError> {
    let s = p.to_str().ok_or(SettingsError::NonUtf8Path { which })?;
    if !p.is_absolute() {
        return Err(SettingsError::RelativePath { which });
    }
    if s.chars().any(char::is_control) {
        return Err(SettingsError::ControlCharInPath { which });
    }
    Ok(s)
}

impl HookCommand {
    /// The hook timeout, in seconds.
    pub const TIMEOUT_SECS: u64 = HOOK_TIMEOUT_SECS;

    /// A hook command for the binary at `exe_path`, optionally pinned to a PeerHarness
    /// `home` (sets `PEERHARNESS_HOME`; pass it whenever the home is not the default so
    /// the hook writes to the right node).
    ///
    /// Both paths must be absolute, valid UTF-8 and free of control characters. The
    /// executable should be canonical (for example `std::env::current_exe()` then
    /// `canonicalize`); for [`remove_hooks`] to recognise the entry its file name must be
    /// `peerharness` or `peerharness.exe`.
    pub fn new(exe_path: &Path, home: Option<&Path>) -> Result<Self, SettingsError> {
        let exe = check_path(exe_path, "executable")?.to_owned();
        let home = home
            .map(|h| check_path(h, "home").map(str::to_owned))
            .transpose()?;
        Ok(Self { exe, home })
    }

    /// The executable path.
    pub fn exe(&self) -> &str {
        &self.exe
    }

    /// The pinned home, if any.
    pub fn home(&self) -> Option<&str> {
        self.home.as_deref()
    }

    /// The shell words that run this binary for this home, without a subcommand:
    /// `PEERHARNESS_HOME='<home>' '<exe>'` (the prefix only when a home is pinned).
    pub fn render_program(&self) -> String {
        let mut s = String::new();
        if let Some(h) = &self.home {
            s.push_str(HOME_ENV_VAR);
            s.push('=');
            s.push_str(&quote(h));
            s.push(' ');
        }
        s.push_str(&quote(&self.exe));
        s
    }

    /// The shell command for `event`.
    pub fn render(&self, event: HookEvent) -> String {
        let mut s = self.render_program();
        s.push_str(" hook ");
        s.push_str(event.cli_arg());
        s
    }

    /// The full hook entry object for `event`:
    /// `{"type": "command", "command": render(event), "timeout": 5}`.
    pub fn entry(&self, event: HookEvent) -> Value {
        serde_json::json!({
            "type": "command",
            "command": self.render(event),
            "timeout": Self::TIMEOUT_SECS,
        })
    }

    /// [`HookCommand::entry`] as an ordered document (`type`, `command`, `timeout`).
    fn entry_doc(&self, event: HookEvent) -> Doc {
        let mut m = Obj::new();
        m.insert("type", Doc::str("command"));
        m.insert("command", Doc::String(self.render(event)));
        m.insert("timeout", Doc::Number(Self::TIMEOUT_SECS.into()));
        Doc::Object(m)
    }
}

/// A recognised PeerHarness command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCommand {
    home: Option<String>,
    event: HookEvent,
}

/// Recognises `[PEERHARNESS_HOME=<h>] <.../peerharness> hook <event-arg>`.
fn parse_our_command(cmd: &str) -> Option<ParsedCommand> {
    let words = split_words(cmd)?;
    let (home, rest) = match words.split_first()? {
        (first, rest) if first.starts_with("PEERHARNESS_HOME=") => {
            (Some(first.get(HOME_ENV_VAR.len() + 1..)?.to_owned()), rest)
        }
        _ => (None, &words[..]),
    };
    let [exe, hook, arg] = rest else {
        return None;
    };
    if hook != "hook" {
        return None;
    }
    let name = Path::new(exe).file_name()?.to_str()?;
    if name != "peerharness" && name != "peerharness.exe" {
        return None;
    }
    let event = HookEvent::from_cli_arg(arg)?;
    Some(ParsedCommand { home, event })
}

fn entry_command(entry: &Doc) -> Option<&str> {
    entry.as_object()?.get("command")?.as_str()
}

/// What [`install_hooks`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// The file was written.
    pub changed: bool,
    /// The backup of the previous file, when one existed and was changed.
    pub backup_path: Option<PathBuf>,
    /// True when the settings file did not exist and was created.
    pub created: bool,
}

/// What [`remove_hooks`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveReport {
    /// The file was written.
    pub changed: bool,
    /// The backup of the previous file, when it was changed.
    pub backup_path: Option<PathBuf>,
    /// Number of hook entries removed.
    pub removed_entries: usize,
}

/// One PeerHarness hook entry found in the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledHook {
    /// The event key it is listed under.
    pub event: HookEvent,
    /// The event its command runs (normally equal to `event`).
    pub command_event: HookEvent,
    /// The `PEERHARNESS_HOME` it pins, if any.
    pub home: Option<String>,
    /// The full command string.
    pub command: String,
}

/// Result of [`hooks_status`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HookStatus {
    /// The settings file exists.
    pub settings_exists: bool,
    /// Events (in [`HookEvent::ALL`] order, deduplicated) with at least one PeerHarness
    /// entry, for any home.
    pub installed_events: Vec<HookEvent>,
    /// Every PeerHarness entry found.
    pub entries: Vec<InstalledHook>,
    /// Number of other hook entries (any event, any type).
    pub foreign_hook_count: usize,
}

impl HookStatus {
    /// True when every event in [`HookEvent::INSTALLED`] has an entry whose command is
    /// exactly `cmd.render(event)`, i.e. `install_hooks` with `cmd` would change nothing
    /// apart from a possibly different `timeout`/`type` on an entry.
    pub fn is_installed_for(&self, cmd: &HookCommand) -> bool {
        HookEvent::INSTALLED.iter().all(|&e| {
            let want = cmd.render(e);
            self.entries
                .iter()
                .any(|h| h.event == e && h.command == want)
        })
    }
}

/// Installs our `UserPromptSubmit` and `Stop` hooks into the settings file at
/// `settings_path`, backing up an existing file into `backups_dir` first.
///
/// Idempotent: a second call with the same `hook_command` returns `changed: false` and
/// writes nothing (not even a backup). See the module docs for the matching, backup and
/// atomic-write rules.
pub fn install_hooks(
    settings_path: &Path,
    hook_command: &HookCommand,
    backups_dir: &Path,
) -> Result<InstallReport, SettingsError> {
    let target = resolve_target(settings_path)?;
    let original = read_settings_bytes(&target)?;
    let mut doc = match &original {
        None => Doc::Object(Obj::new()),
        Some(bytes) => parse_settings(bytes)?,
    };
    let mut changed = original.is_none();
    {
        let root = doc
            .as_object_mut()
            .ok_or(SettingsError::UnexpectedStructure {
                what: "top level is not an object",
            })?;
        if !root.contains_key("hooks") {
            root.insert("hooks", Doc::Object(Obj::new()));
            changed = true;
        }
        let hooks = root.get_mut("hooks").and_then(Doc::as_object_mut).ok_or(
            SettingsError::UnexpectedStructure {
                what: "\"hooks\" is not an object",
            },
        )?;
        for event in HookEvent::INSTALLED {
            changed |= install_event(hooks, event, hook_command)?;
        }
    }
    if !changed {
        tracing::debug!("claude settings already up to date");
        return Ok(InstallReport {
            changed: false,
            backup_path: None,
            created: false,
        });
    }
    let backup_path = commit(&target, original.as_deref(), &doc, backups_dir)?;
    tracing::debug!(
        created = original.is_none(),
        "claude settings hooks installed"
    );
    Ok(InstallReport {
        changed: true,
        backup_path,
        created: original.is_none(),
    })
}

fn install_event(
    hooks: &mut Obj,
    event: HookEvent,
    cmd: &HookCommand,
) -> Result<bool, SettingsError> {
    let mut changed = false;
    let key = event.event_name();
    if !hooks.contains_key(key) {
        hooks.insert(key, Doc::Array(Vec::new()));
        changed = true;
    }
    let groups = hooks.get_mut(key).and_then(Doc::as_array_mut).ok_or(
        SettingsError::UnexpectedStructure {
            what: "an event under \"hooks\" is not an array",
        },
    )?;
    let want_cmd = cmd.render(event);
    let want_entry = cmd.entry_doc(event);
    let is_ours = |entry: &Doc| -> bool {
        let Some(c) = entry_command(entry) else {
            return false;
        };
        c == want_cmd
            || parse_our_command(c)
                .is_some_and(|p| p.event == event && p.home.as_deref() == cmd.home())
    };

    // (group index, entry index) of our entries, in order.
    let mut found = Vec::new();
    for (gi, group) in groups.iter().enumerate() {
        if let Some(list) = group.get("hooks").and_then(Doc::as_array) {
            for (hi, entry) in list.iter().enumerate() {
                if is_ours(entry) {
                    found.push((gi, hi));
                }
            }
        }
    }
    let Some((&(keep_g, keep_h), dups)) = found.split_first() else {
        let mut group = Obj::new();
        group.insert("hooks", Doc::Array(vec![want_entry]));
        groups.push(Doc::Object(group));
        return Ok(true);
    };
    // Update the first entry in place if needed.
    if let Some(slot) = groups
        .get_mut(keep_g)
        .and_then(|g| g.get_mut("hooks"))
        .and_then(Doc::as_array_mut)
        .and_then(|l| l.get_mut(keep_h))
    {
        if *slot != want_entry {
            *slot = want_entry;
            changed = true;
        }
    }
    // Remove duplicates, back to front so indices stay valid.
    let mut touched_groups = HashSet::new();
    for &(gi, hi) in dups.iter().rev() {
        if let Some(list) = groups
            .get_mut(gi)
            .and_then(|g| g.get_mut("hooks"))
            .and_then(Doc::as_array_mut)
        {
            if hi < list.len() {
                list.remove(hi);
                touched_groups.insert(gi);
                changed = true;
            }
        }
    }
    drop_emptied_groups(groups, &touched_groups);
    Ok(changed)
}

/// Removes, in descending index order, groups in `touched` whose `hooks` array is now
/// empty.
fn drop_emptied_groups(groups: &mut Vec<Doc>, touched: &HashSet<usize>) {
    let mut idx: Vec<usize> = touched.iter().copied().collect();
    idx.sort_unstable_by(|a, b| b.cmp(a));
    for gi in idx {
        let empty = groups
            .get(gi)
            .and_then(|g| g.get("hooks"))
            .and_then(Doc::as_array)
            .is_some_and(Vec::is_empty);
        if empty {
            groups.remove(gi);
        }
    }
}

/// Removes every PeerHarness hook entry (any home, any event key) from the settings
/// file, backing it up into `backups_dir` first. Groups, event arrays and the `hooks`
/// object that become empty because of the removal are dropped; ones that were already
/// empty are kept. A missing file is not an error (`changed: false`).
///
/// Use [`remove_hooks_for`] to remove only the entries of one PeerHarness home (for
/// example when several homes share one machine, as in the demo).
pub fn remove_hooks(
    settings_path: &Path,
    backups_dir: &Path,
) -> Result<RemoveReport, SettingsError> {
    remove_matching(settings_path, backups_dir, |c| {
        parse_our_command(c).is_some()
    })
}

/// Like [`remove_hooks`], but removes only the entries that belong to `hook_command`'s
/// home: entries whose command is exactly `hook_command.render(event)` for some event
/// (this also finds an install made from a renamed binary), or that are recognised
/// PeerHarness commands pinning the same `PEERHARNESS_HOME` (or none, when
/// `hook_command` has no home). Entries for other homes and foreign entries are kept.
pub fn remove_hooks_for(
    settings_path: &Path,
    hook_command: &HookCommand,
    backups_dir: &Path,
) -> Result<RemoveReport, SettingsError> {
    let exact: Vec<String> = HookEvent::ALL
        .iter()
        .map(|&e| hook_command.render(e))
        .collect();
    remove_matching(settings_path, backups_dir, |c| {
        exact.iter().any(|x| x == c)
            || parse_our_command(c).is_some_and(|p| p.home.as_deref() == hook_command.home())
    })
}

/// Removes every hook entry whose `command` satisfies `is_ours`.
fn remove_matching(
    settings_path: &Path,
    backups_dir: &Path,
    is_ours: impl Fn(&str) -> bool,
) -> Result<RemoveReport, SettingsError> {
    let target = resolve_target(settings_path)?;
    let unchanged = RemoveReport {
        changed: false,
        backup_path: None,
        removed_entries: 0,
    };
    let Some(original) = read_settings_bytes(&target)? else {
        return Ok(unchanged);
    };
    let mut doc = parse_settings(&original)?;
    let root = doc
        .as_object_mut()
        .ok_or(SettingsError::UnexpectedStructure {
            what: "top level is not an object",
        })?;
    let mut removed = 0usize;
    let mut hooks_emptied = false;
    if let Some(hooks) = root.get_mut("hooks").and_then(Doc::as_object_mut) {
        let mut emptied_keys = Vec::new();
        for (key, groups) in hooks.iter_mut() {
            let Some(groups) = groups.as_array_mut() else {
                continue;
            };
            let mut touched = HashSet::new();
            for (gi, group) in groups.iter_mut().enumerate() {
                let Some(list) = group.get_mut("hooks").and_then(Doc::as_array_mut) else {
                    continue;
                };
                let before = list.len();
                list.retain(|e| entry_command(e).is_none_or(|c| !is_ours(c)));
                if list.len() != before {
                    removed += before - list.len();
                    touched.insert(gi);
                }
            }
            if !touched.is_empty() {
                drop_emptied_groups(groups, &touched);
                if groups.is_empty() {
                    emptied_keys.push(key.to_owned());
                }
            }
        }
        for k in &emptied_keys {
            hooks.remove(k);
        }
        hooks_emptied = !emptied_keys.is_empty() && hooks.is_empty();
    }
    if hooks_emptied {
        root.remove("hooks");
    }
    if removed == 0 {
        return Ok(unchanged);
    }
    let backup_path = commit(&target, Some(&original), &doc, backups_dir)?;
    tracing::debug!(removed, "claude settings hooks removed");
    Ok(RemoveReport {
        changed: true,
        backup_path,
        removed_entries: removed,
    })
}

/// Reports which PeerHarness hooks are present. Read-only. A missing file gives
/// `HookStatus::default()`; malformed JSON is an error. Wrongly shaped parts of the
/// file are skipped rather than reported.
pub fn hooks_status(settings_path: &Path) -> Result<HookStatus, SettingsError> {
    let Some(bytes) = read_settings_bytes(settings_path)? else {
        return Ok(HookStatus::default());
    };
    let doc = parse_settings(&bytes)?;
    let mut status = HookStatus {
        settings_exists: true,
        ..HookStatus::default()
    };
    let Some(hooks) = doc.get("hooks").and_then(Doc::as_object) else {
        return Ok(status);
    };
    for (key, groups) in hooks.iter() {
        let key_event = HookEvent::from_event_name(key);
        let Some(groups) = groups.as_array() else {
            continue;
        };
        for group in groups {
            let Some(list) = group.get("hooks").and_then(Doc::as_array) else {
                continue;
            };
            for entry in list {
                let parsed = entry_command(entry).and_then(|c| Some((c, parse_our_command(c)?)));
                match (parsed, key_event) {
                    (Some((c, p)), Some(ev)) => status.entries.push(InstalledHook {
                        event: ev,
                        command_event: p.event,
                        home: p.home,
                        command: c.to_owned(),
                    }),
                    // Ours but under an event key we do not know: still not foreign.
                    (Some(_), None) => {}
                    (None, _) => status.foreign_hook_count += 1,
                }
            }
        }
    }
    status.installed_events = HookEvent::ALL
        .into_iter()
        .filter(|e| status.entries.iter().any(|h| h.event == *e))
        .collect();
    Ok(status)
}

/// Follows a symlinked settings path to its target so the link survives the rewrite.
fn resolve_target(settings_path: &Path) -> Result<PathBuf, SettingsError> {
    match fs::symlink_metadata(settings_path) {
        Ok(m) if m.file_type().is_symlink() => {
            fs::canonicalize(settings_path).map_err(io_err("resolve settings symlink"))
        }
        _ => Ok(settings_path.to_path_buf()),
    }
}

fn read_settings_bytes(path: &Path) -> Result<Option<Vec<u8>>, SettingsError> {
    match read_capped(path, MAX_SETTINGS_BYTES).map_err(io_err("read settings"))? {
        CappedRead::Missing => Ok(None),
        CappedRead::Bytes(b) => Ok(Some(b)),
        CappedRead::TooLarge => Err(SettingsError::TooLarge {
            max: MAX_SETTINGS_BYTES,
        }),
        CappedRead::NotRegularFile => Err(SettingsError::NotAFile),
    }
}

/// Parses settings JSON in file order, rejecting duplicate keys. Whitespace-only content is treated as
/// an empty object.
fn parse_settings(bytes: &[u8]) -> Result<Doc, SettingsError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Doc::Object(Obj::new()));
    }
    serde_json::from_slice::<Doc>(bytes).map_err(|e| {
        let (line, column) = (e.line(), e.column());
        if e.is_data() && e.to_string().starts_with(DUPLICATE_KEY_MSG) {
            SettingsError::DuplicateKey { line, column }
        } else {
            SettingsError::Malformed { line, column }
        }
    })
}

fn render_settings(doc: &Doc) -> Result<Vec<u8>, SettingsError> {
    let mut out =
        serde_json::to_vec_pretty(doc).map_err(|_| SettingsError::UnexpectedStructure {
            what: "settings could not be serialized",
        })?;
    out.push(b'\n');
    Ok(out)
}

/// Backs up `original` (if any), checks for concurrent modification, and atomically
/// writes `doc` to `target`. Returns the backup path.
fn commit(
    target: &Path,
    original: Option<&[u8]>,
    doc: &Doc,
    backups_dir: &Path,
) -> Result<Option<PathBuf>, SettingsError> {
    let bytes = render_settings(doc)?;
    let backup = match original {
        Some(orig) => Some(write_backup(backups_dir, orig)?),
        None => None,
    };
    let dir = parent_dir(target);
    ensure_private_dir(&dir).map_err(io_err("create settings directory"))?;
    let current = read_settings_bytes(target)?;
    if current.as_deref() != original {
        return Err(SettingsError::ConcurrentModification);
    }
    let mode = existing_mode(target).unwrap_or(PRIVATE_FILE_MODE);
    write_atomic(target, &bytes, mode).map_err(io_err("write settings"))?;
    Ok(backup)
}

/// Writes `bytes` to `backups_dir/claude-settings-<UTC>.json` (0600, never overwriting
/// an existing backup: `-1`, `-2`, ... are appended on collision).
fn write_backup(backups_dir: &Path, bytes: &[u8]) -> Result<PathBuf, SettingsError> {
    ensure_private_dir(backups_dir).map_err(io_err("create backups directory"))?;
    let stamp: String = Timestamp::now()
        .to_string()
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    for n in 0..1000u32 {
        let name = if n == 0 {
            format!("{BACKUP_PREFIX}{stamp}.json")
        } else {
            format!("{BACKUP_PREFIX}{stamp}-{n}.json")
        };
        let path = backups_dir.join(name);
        match write_new_private(&path, bytes) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io_err("write settings backup")(e)),
        }
    }
    Err(SettingsError::Io {
        op: "write settings backup",
        kind: io::ErrorKind::AlreadyExists,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(home: Option<&str>) -> HookCommand {
        HookCommand::new(Path::new("/opt/ph bin/peerharness"), home.map(Path::new)).unwrap()
    }

    #[test]
    fn render_shapes() {
        assert_eq!(
            cmd(None).render(HookEvent::Stop),
            "'/opt/ph bin/peerharness' hook stop"
        );
        assert_eq!(
            cmd(Some("/x y")).render(HookEvent::UserPromptSubmit),
            "PEERHARNESS_HOME='/x y' '/opt/ph bin/peerharness' hook user-prompt-submit"
        );
        let q = HookCommand::new(Path::new("/a'b/peerharness"), Some(Path::new("/h'"))).unwrap();
        assert_eq!(
            q.render(HookEvent::Stop),
            r"PEERHARNESS_HOME='/h'\''' '/a'\''b/peerharness' hook stop"
        );
        assert_eq!(cmd(None).render_program(), "'/opt/ph bin/peerharness'");
        assert_eq!(
            cmd(Some("/x y")).render_program(),
            "PEERHARNESS_HOME='/x y' '/opt/ph bin/peerharness'"
        );
    }

    #[test]
    fn new_validates_paths() {
        assert!(matches!(
            HookCommand::new(Path::new("peerharness"), None),
            Err(SettingsError::RelativePath {
                which: "executable"
            })
        ));
        assert!(matches!(
            HookCommand::new(Path::new("/bin/peerharness"), Some(Path::new("rel"))),
            Err(SettingsError::RelativePath { which: "home" })
        ));
        assert!(matches!(
            HookCommand::new(Path::new("/bin/peer\nharness"), None),
            Err(SettingsError::ControlCharInPath { .. })
        ));
    }

    #[test]
    fn rendered_commands_parse_as_ours() {
        for home in [None, Some("/x y"), Some("/we'ird \"$HOME\" `x`")] {
            let c = cmd(home);
            for e in HookEvent::ALL {
                let p = parse_our_command(&c.render(e)).unwrap();
                assert_eq!(p.event, e);
                assert_eq!(p.home.as_deref(), home);
            }
        }
    }

    #[test]
    fn foreign_commands_are_not_ours() {
        for c in [
            "/usr/bin/other hook stop",
            "peerharness-notifier hook stop",
            "/bin/peerharness hook stop; rm -rf ~",
            "/bin/peerharness hook stop && curl x",
            "/bin/peerharness hook bogus",
            "/bin/peerharness hook",
            "/bin/peerharness hook stop extra",
            "FOO=1 /bin/peerharness hook stop",
            "/bin/peerharness status",
            "echo /bin/peerharness hook stop",
            "",
        ] {
            assert_eq!(parse_our_command(c), None, "{c:?}");
        }
        assert!(parse_our_command("/bin/peerharness hook stop").is_some());
        assert!(parse_our_command("peerharness hook user-prompt-submit").is_some());
    }

    #[test]
    fn dup_check() {
        assert!(parse_settings(br#"{"a":1,"b":{"c":1,"d":[{"e":1}]}}"#).is_ok());
        assert!(matches!(
            parse_settings(br#"{"a":1,"a":2}"#),
            Err(SettingsError::DuplicateKey { .. })
        ));
        assert!(matches!(
            parse_settings(br#"{"a":{"x":[{"k":1,"k":1}]}}"#),
            Err(SettingsError::DuplicateKey { .. })
        ));
        assert!(matches!(
            parse_settings(b"{,}"),
            Err(SettingsError::Malformed { .. })
        ));
        assert!(matches!(
            parse_settings(b"{} // comment"),
            Err(SettingsError::Malformed { .. })
        ));
        assert_eq!(parse_settings(b"  \n").unwrap(), Doc::Object(Obj::new()));
    }

    #[test]
    fn claude_settings_path() {
        assert_eq!(
            claude_user_settings_path(Path::new("/home/a"), None),
            PathBuf::from("/home/a/.claude/settings.json")
        );
        assert_eq!(
            claude_user_settings_path(Path::new("/home/a"), Some(Path::new("/cfg"))),
            PathBuf::from("/cfg/settings.json")
        );
    }
}
