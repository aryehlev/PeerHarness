//! One entry in another coding agent's configuration file: the MCP server that runs
//! `peerharness mcp` (ADR-050).
//!
//! Codex keeps its servers in TOML (`~/.codex/config.toml`, `[mcp_servers.<name>]`); Pi,
//! Antigravity and opencode keep theirs in JSON (`mcpServers.<name>`, or `mcp.<name>`).
//! The rules are the ones [`crate::settings`] follows for Claude Code's settings:
//!
//! * Only an entry that is exactly what PeerHarness would write is ever changed or
//!   removed. An entry of the same name with any other content is the owner's, and is
//!   reported as [`Entry::Other`] and left alone.
//! * Every change is idempotent, backs the file up first, checks that nobody changed it
//!   meanwhile and replaces it atomically.
//! * A file that does not parse (a JSON file with comments, for example) is never
//!   rewritten: nothing is changed, and the caller shows the entry for the owner to add.
//! * A TOML file is never re-serialized, which would lose its comments and layout: the
//!   entry is appended as one block between two marker comments, and removing it takes
//!   out exactly that block. The result is parsed again before it is written.
//!
//! Errors carry static text and I/O kinds only, never the file's content.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ph_core::Timestamp;
use serde_json::Value;

use crate::fsutil::{
    ensure_private_dir, existing_mode, parent_dir, read_capped, write_atomic, write_new_private,
    CappedRead, PRIVATE_FILE_MODE,
};
use crate::json_doc::{Doc, Obj, DUPLICATE_KEY_MSG};

/// Largest configuration file this module reads.
pub const MAX_AGENT_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// File name prefix of the backups made before a change.
pub const AGENT_BACKUP_PREFIX: &str = "agent-config-";

/// The first line of the block appended to a TOML file.
pub const TOML_BEGIN: &str = "# BEGIN peerharness: the PeerHarness tools (`peerharness watch codex --remove` takes this block out)";
/// The last line of that block.
pub const TOML_END: &str = "# END peerharness";

/// What a configuration file holds under the server's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Nothing (or no file).
    Absent,
    /// Exactly what PeerHarness would write.
    Same,
    /// Something else: the owner's own entry, or one for another binary or home.
    Other,
}

/// What a change did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Edit {
    /// Whether the file was written.
    pub changed: bool,
    /// The backup of the previous file, when there was one.
    pub backup_path: Option<PathBuf>,
}

/// Errors. `Display` is actionable and never includes file contents.
#[derive(Debug, thiserror::Error)]
pub enum AgentConfigError {
    /// The file does not parse (it may hold comments), so it is not rewritten.
    #[error("the agent's configuration file could not be parsed (it may hold comments or be malformed); nothing was changed")]
    Malformed,
    /// The file has a duplicate key, which a rewrite would silently drop.
    #[error("the agent's configuration file contains a duplicate key; nothing was changed")]
    DuplicateKey,
    /// Valid, but not the documented shape where the entry goes.
    #[error(
        "the agent's configuration file has an unexpected structure ({what}); nothing was changed"
    )]
    UnexpectedStructure {
        /// Which part (static text).
        what: &'static str,
    },
    /// An entry of that name that PeerHarness did not write is in the way.
    #[error("the agent's configuration already has a server of that name that PeerHarness did not write; nothing was changed")]
    Taken,
    /// Larger than [`MAX_AGENT_CONFIG_BYTES`].
    #[error("the agent's configuration file is larger than {max} bytes; nothing was changed")]
    TooLarge {
        /// The limit.
        max: u64,
    },
    /// The path is not a regular file.
    #[error("the agent's configuration path is not a regular file; nothing was changed")]
    NotAFile,
    /// The file changed while it was being updated.
    #[error("the agent's configuration file changed while PeerHarness was updating it; retry. It was not overwritten")]
    ConcurrentModification,
    /// A filesystem operation failed.
    #[error("{op} failed: {kind}")]
    Io {
        /// What was being done (static text).
        op: &'static str,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
}

pub(crate) type Result<T> = std::result::Result<T, AgentConfigError>;

pub(crate) fn io_err(op: &'static str) -> impl FnOnce(io::Error) -> AgentConfigError {
    move |e| AgentConfigError::Io { op, kind: e.kind() }
}

/// Follows a symlinked file to its target, so that the link survives the rewrite.
pub(crate) fn resolve_target(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            fs::canonicalize(path).map_err(io_err("resolve configuration symlink"))
        }
        _ => Ok(path.to_path_buf()),
    }
}

pub(crate) fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    match read_capped(path, MAX_AGENT_CONFIG_BYTES).map_err(io_err("read configuration"))? {
        CappedRead::Missing => Ok(None),
        CappedRead::Bytes(b) => Ok(Some(b)),
        CappedRead::TooLarge => Err(AgentConfigError::TooLarge {
            max: MAX_AGENT_CONFIG_BYTES,
        }),
        CappedRead::NotRegularFile => Err(AgentConfigError::NotAFile),
    }
}

/// Backs up `original`, checks that the file still holds it, and writes `bytes`.
pub(crate) fn commit(
    target: &Path,
    original: Option<&[u8]>,
    bytes: &[u8],
    backups_dir: &Path,
) -> Result<Option<PathBuf>> {
    let backup = match original {
        Some(orig) => Some(write_backup(backups_dir, target, orig)?),
        None => None,
    };
    ensure_private_dir(&parent_dir(target)).map_err(io_err("create configuration directory"))?;
    if read(target)?.as_deref() != original {
        return Err(AgentConfigError::ConcurrentModification);
    }
    let mode = existing_mode(target).unwrap_or(PRIVATE_FILE_MODE);
    write_atomic(target, bytes, mode).map_err(io_err("write configuration"))?;
    Ok(backup)
}

/// `backups_dir/agent-config-<UTC>-<file name>` (0600, never overwriting a backup).
fn write_backup(backups_dir: &Path, target: &Path, bytes: &[u8]) -> Result<PathBuf> {
    ensure_private_dir(backups_dir).map_err(io_err("create backups directory"))?;
    let stamp: String = Timestamp::now()
        .to_string()
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    let file: String = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
        .collect();
    for n in 0..1000u32 {
        let name = if n == 0 {
            format!("{AGENT_BACKUP_PREFIX}{stamp}-{file}")
        } else {
            format!("{AGENT_BACKUP_PREFIX}{stamp}-{n}-{file}")
        };
        let path = backups_dir.join(name);
        match write_new_private(&path, bytes) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io_err("write configuration backup")(e)),
        }
    }
    Err(AgentConfigError::Io {
        op: "write configuration backup",
        kind: io::ErrorKind::AlreadyExists,
    })
}

// ---------------------------------------------------------------------------------
// JSON

pub(crate) fn parse_json(bytes: &[u8]) -> Result<Doc> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Doc::Object(Obj::new()));
    }
    // `Doc::parse`: a number elsewhere in the file keeps the text it had (ADR-051).
    Doc::parse(bytes).map_err(|e| {
        if e.is_data() && e.to_string().starts_with(DUPLICATE_KEY_MSG) {
            AgentConfigError::DuplicateKey
        } else {
            AgentConfigError::Malformed
        }
    })
}

pub(crate) fn to_doc(value: &Value) -> Result<Doc> {
    serde_json::from_value::<Doc>(value.clone()).map_err(|_| {
        AgentConfigError::UnexpectedStructure {
            what: "the entry could not be built",
        }
    })
}

/// The object at `at` below the top level, if every step is an object.
fn object_at<'a>(doc: &'a Doc, at: &[&str]) -> Result<Option<&'a Obj>> {
    let mut cur = doc
        .as_object()
        .ok_or(AgentConfigError::UnexpectedStructure {
            what: "top level is not an object",
        })?;
    for key in at {
        match cur.get(key) {
            None => return Ok(None),
            Some(d) => {
                cur = d.as_object().ok_or(AgentConfigError::UnexpectedStructure {
                    what: "the servers' place is not an object",
                })?;
            }
        }
    }
    Ok(Some(cur))
}

fn json_entry_in(doc: &Doc, at: &[&str], name: &str, want: &Doc) -> Result<Entry> {
    Ok(match object_at(doc, at)?.and_then(|o| o.get(name)) {
        None => Entry::Absent,
        Some(d) if d == want => Entry::Same,
        Some(_) => Entry::Other,
    })
}

/// What the JSON file at `path` holds under `at` → `name`, compared with `want`.
pub fn json_entry(path: &Path, at: &[&str], name: &str, want: &Value) -> Result<Entry> {
    let Some(bytes) = read(path)? else {
        return Ok(Entry::Absent);
    };
    json_entry_in(&parse_json(&bytes)?, at, name, &to_doc(want)?)
}

/// Adds `want` under `at` → `name` in the JSON file at `path` (created with `{}` and
/// `first` members when it does not exist). An identical entry is left as it is; any
/// other entry of that name is [`AgentConfigError::Taken`].
pub fn add_json_entry(
    path: &Path,
    at: &[&str],
    name: &str,
    want: &Value,
    first: &[(&str, Value)],
    backups_dir: &Path,
) -> Result<Edit> {
    let target = resolve_target(path)?;
    let original = read(&target)?;
    let mut doc = match &original {
        None => {
            let mut o = Obj::new();
            for (k, v) in first {
                o.insert(k, to_doc(v)?);
            }
            Doc::Object(o)
        }
        Some(b) => parse_json(b)?,
    };
    let want_doc = to_doc(want)?;
    match json_entry_in(&doc, at, name, &want_doc)? {
        Entry::Same => return Ok(Edit::default()),
        Entry::Other => return Err(AgentConfigError::Taken),
        Entry::Absent => {}
    }
    let mut cur = doc
        .as_object_mut()
        .ok_or(AgentConfigError::UnexpectedStructure {
            what: "top level is not an object",
        })?;
    for key in at {
        if !cur.contains_key(key) {
            cur.insert(key, Doc::Object(Obj::new()));
        }
        cur = cur.get_mut(key).and_then(Doc::as_object_mut).ok_or(
            AgentConfigError::UnexpectedStructure {
                what: "the servers' place is not an object",
            },
        )?;
    }
    cur.insert(name, want_doc);
    let mut bytes =
        serde_json::to_vec_pretty(&doc).map_err(|_| AgentConfigError::UnexpectedStructure {
            what: "the file could not be serialized",
        })?;
    bytes.push(b'\n');
    let backup_path = commit(&target, original.as_deref(), &bytes, backups_dir)?;
    Ok(Edit {
        changed: true,
        backup_path,
    })
}

/// Removes `at` → `name` from the JSON file at `path` when it is exactly `want`. An
/// object on the way that this leaves empty is kept: it may be the owner's.
pub fn remove_json_entry(
    path: &Path,
    at: &[&str],
    name: &str,
    want: &Value,
    backups_dir: &Path,
) -> Result<Edit> {
    let target = resolve_target(path)?;
    let Some(original) = read(&target)? else {
        return Ok(Edit::default());
    };
    let mut doc = parse_json(&original)?;
    if json_entry_in(&doc, at, name, &to_doc(want)?)? != Entry::Same {
        return Ok(Edit::default());
    }
    let mut cur = doc
        .as_object_mut()
        .ok_or(AgentConfigError::UnexpectedStructure {
            what: "top level is not an object",
        })?;
    for key in at {
        cur = cur.get_mut(key).and_then(Doc::as_object_mut).ok_or(
            AgentConfigError::UnexpectedStructure {
                what: "the servers' place is not an object",
            },
        )?;
    }
    cur.remove(name);
    let mut bytes =
        serde_json::to_vec_pretty(&doc).map_err(|_| AgentConfigError::UnexpectedStructure {
            what: "the file could not be serialized",
        })?;
    bytes.push(b'\n');
    let backup_path = commit(&target, Some(&original), &bytes, backups_dir)?;
    Ok(Edit {
        changed: true,
        backup_path,
    })
}

// ---------------------------------------------------------------------------------
// TOML

/// A stdio MCP server in a TOML file: `[<table>.<name>]` with `command` and `args`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TomlServer {
    /// The table that holds the servers (`mcp_servers` for Codex).
    pub table: String,
    /// The server's name, a bare TOML key.
    pub name: String,
    /// The program.
    pub command: String,
    /// Its arguments.
    pub args: Vec<String>,
}

impl TomlServer {
    /// The block appended to the file, between [`TOML_BEGIN`] and [`TOML_END`].
    pub fn block(&self) -> String {
        let args: Vec<String> = self
            .args
            .iter()
            .map(|a| toml::Value::String(a.clone()).to_string())
            .collect();
        format!(
            "{TOML_BEGIN}\n[{}.{}]\ncommand = {}\nargs = [{}]\n{TOML_END}\n",
            self.table,
            self.name,
            toml::Value::String(self.command.clone()),
            args.join(", ")
        )
    }

    fn entry_in(&self, text: &str) -> Result<Entry> {
        let table: toml::Table = text.parse().map_err(|_| AgentConfigError::Malformed)?;
        let Some(servers) = table.get(&self.table) else {
            return Ok(Entry::Absent);
        };
        let servers = servers
            .as_table()
            .ok_or(AgentConfigError::UnexpectedStructure {
                what: "the servers' table is not a table",
            })?;
        let Some(entry) = servers.get(&self.name) else {
            return Ok(Entry::Absent);
        };
        let same = entry.as_table().is_some_and(|t| {
            t.len() == 2
                && t.get("command").and_then(toml::Value::as_str) == Some(self.command.as_str())
                && t.get("args")
                    .and_then(toml::Value::as_array)
                    .is_some_and(|a| {
                        a.len() == self.args.len()
                            && a.iter()
                                .zip(&self.args)
                                .all(|(x, y)| x.as_str() == Some(y.as_str()))
                    })
        });
        Ok(if same { Entry::Same } else { Entry::Other })
    }
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| AgentConfigError::Malformed)
}

/// What the TOML file at `path` holds for `server`.
pub fn toml_entry(path: &Path, server: &TomlServer) -> Result<Entry> {
    match read(path)? {
        None => Ok(Entry::Absent),
        Some(b) => server.entry_in(utf8(&b)?),
    }
}

/// Appends `server` to the TOML file at `path` (created when it does not exist). An
/// identical entry is left as it is; any other entry of that name is
/// [`AgentConfigError::Taken`]. A file where the block would not parse (the servers are
/// an inline table, say) is not changed.
pub fn add_toml_entry(path: &Path, server: &TomlServer, backups_dir: &Path) -> Result<Edit> {
    let target = resolve_target(path)?;
    let original = read(&target)?;
    let text = match &original {
        Some(b) => utf8(b)?.to_owned(),
        None => String::new(),
    };
    match server.entry_in(&text)? {
        Entry::Same => return Ok(Edit::default()),
        Entry::Other => return Err(AgentConfigError::Taken),
        Entry::Absent => {}
    }
    let mut next = text;
    if !next.is_empty() {
        if !next.ends_with('\n') {
            next.push('\n');
        }
        next.push('\n');
    }
    next.push_str(&server.block());
    if server.entry_in(&next)? != Entry::Same {
        return Err(AgentConfigError::UnexpectedStructure {
            what: "the entry would not be read back as written",
        });
    }
    let backup_path = commit(&target, original.as_deref(), next.as_bytes(), backups_dir)?;
    Ok(Edit {
        changed: true,
        backup_path,
    })
}

/// Takes the block that [`add_toml_entry`] appended out of the TOML file at `path`,
/// when it is there exactly as written. Anything else is left as it is.
pub fn remove_toml_entry(path: &Path, server: &TomlServer, backups_dir: &Path) -> Result<Edit> {
    let target = resolve_target(path)?;
    let Some(original) = read(&target)? else {
        return Ok(Edit::default());
    };
    let text = utf8(&original)?;
    let block = server.block();
    let Some(at) = text.find(&block) else {
        return Ok(Edit::default());
    };
    let mut before = text[..at].to_owned();
    // The blank line `add_toml_entry` put in front of the block goes with it.
    if before.ends_with("\n\n") {
        before.pop();
    }
    let next = format!("{before}{}", &text[at + block.len()..]);
    if server.entry_in(&next)? != Entry::Absent {
        return Ok(Edit::default());
    }
    let backup_path = commit(&target, Some(&original), next.as_bytes(), backups_dir)?;
    Ok(Edit {
        changed: true,
        backup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server() -> TomlServer {
        TomlServer {
            table: "mcp_servers".into(),
            name: "peerharness".into(),
            command: "/opt/ph bin/peerharness".into(),
            args: vec!["--home".into(), "/h \"x\"".into(), "mcp".into()],
        }
    }

    #[test]
    fn a_json_entry_is_added_once_and_removed_only_when_it_is_ours() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cfg").join("mcp.json");
        let backups = tmp.path().join("backups");
        let at = ["mcpServers"];
        let want = json!({"command": "/p", "args": ["mcp"]});

        assert_eq!(
            json_entry(&path, &at, "peerharness", &want).unwrap(),
            Entry::Absent
        );
        let e = add_json_entry(&path, &at, "peerharness", &want, &[], &backups).unwrap();
        assert!(e.changed && e.backup_path.is_none());
        assert_eq!(
            json_entry(&path, &at, "peerharness", &want).unwrap(),
            Entry::Same
        );
        // Idempotent: nothing written, no backup.
        let e = add_json_entry(&path, &at, "peerharness", &want, &[], &backups).unwrap();
        assert!(!e.changed);

        // The owner's own servers and keys are kept, in their order.
        std::fs::write(
            &path,
            r#"{"theme": "dark", "mcpServers": {"other": {"command": "x"}}}"#,
        )
        .unwrap();
        let e = add_json_entry(&path, &at, "peerharness", &want, &[], &backups).unwrap();
        assert!(e.changed && e.backup_path.is_some());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.find("theme").unwrap() < text.find("other").unwrap());
        assert!(text.find("other").unwrap() < text.find("peerharness").unwrap());

        // An entry of that name with other content is the owner's: never replaced or
        // removed.
        let theirs = json!({"command": "/elsewhere", "args": ["mcp"]});
        assert_eq!(
            json_entry(&path, &at, "peerharness", &theirs).unwrap(),
            Entry::Other
        );
        assert!(matches!(
            add_json_entry(&path, &at, "peerharness", &theirs, &[], &backups),
            Err(AgentConfigError::Taken)
        ));
        assert!(
            !remove_json_entry(&path, &at, "peerharness", &theirs, &backups)
                .unwrap()
                .changed
        );

        let e = remove_json_entry(&path, &at, "peerharness", &want, &backups).unwrap();
        assert!(e.changed);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v,
            json!({"theme": "dark", "mcpServers": {"other": {"command": "x"}}})
        );
    }

    /// The file is the owner's. A number in it comes back with the text it had
    /// (ADR-051): serde_json would write `1e5` as `100000.0` and round a long one.
    #[test]
    fn a_number_elsewhere_in_a_json_file_keeps_its_text() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mcp.json");
        let backups = tmp.path().join("backups");
        let want = json!({"command": "/p", "args": ["mcp"]});
        std::fs::write(
            &path,
            r#"{"limits": [1e5, 1.10, -0, 0.1234567890123456789, 12345678901234567890123], "mcpServers": {"other": {"command": "x", "timeout": 30.0}}}"#,
        )
        .unwrap();
        let squeezed = |p: &Path| -> String {
            std::fs::read_to_string(p)
                .unwrap()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        };
        let numbers = r#""limits":[1e5,1.10,-0,0.1234567890123456789,12345678901234567890123]"#;
        add_json_entry(&path, &["mcpServers"], "peerharness", &want, &[], &backups).unwrap();
        let text = squeezed(&path);
        assert!(text.contains(numbers), "{text}");
        assert!(text.contains(r#""timeout":30.0"#), "{text}");
        remove_json_entry(&path, &["mcpServers"], "peerharness", &want, &backups).unwrap();
        let text = squeezed(&path);
        assert!(text.contains(numbers), "{text}");
        assert!(text.contains(r#""timeout":30.0"#), "{text}");
    }

    #[test]
    fn a_json_file_that_does_not_parse_is_never_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opencode.jsonc");
        let with_comments = "{\n  // mine\n  \"mcp\": {}\n}\n";
        std::fs::write(&path, with_comments).unwrap();
        let want = json!({"type": "local"});
        assert!(matches!(
            add_json_entry(&path, &["mcp"], "peerharness", &want, &[], tmp.path()),
            Err(AgentConfigError::Malformed)
        ));
        std::fs::write(&path, r#"{"a": 1, "a": 2}"#).unwrap();
        assert!(matches!(
            add_json_entry(&path, &["mcp"], "peerharness", &want, &[], tmp.path()),
            Err(AgentConfigError::DuplicateKey)
        ));
        std::fs::write(&path, r#"{"mcp": []}"#).unwrap();
        assert!(matches!(
            add_json_entry(&path, &["mcp"], "peerharness", &want, &[], tmp.path()),
            Err(AgentConfigError::UnexpectedStructure { .. })
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"mcp": []}"#);
    }

    #[test]
    fn a_new_json_file_starts_with_the_members_given() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opencode.json");
        let want = json!({"type": "local", "command": ["/p", "mcp"], "enabled": true});
        add_json_entry(
            &path,
            &["mcp"],
            "peerharness",
            &want,
            &[("$schema", json!("https://opencode.ai/config.json"))],
            tmp.path(),
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.find("$schema").unwrap() < text.find("mcp").unwrap());
    }

    #[test]
    fn a_toml_block_is_appended_and_taken_out_with_the_rest_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let backups = tmp.path().join("backups");
        let s = server();
        let mine = "# my settings\nmodel = \"x\"   # keep this comment\n\n[mcp_servers.other]\ncommand = \"o\"\n";
        std::fs::write(&path, mine).unwrap();

        let e = add_toml_entry(&path, &s, &backups).unwrap();
        assert!(e.changed && e.backup_path.is_some());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(mine));
        assert!(text.contains(TOML_BEGIN) && text.ends_with(&format!("{TOML_END}\n")));
        assert_eq!(toml_entry(&path, &s).unwrap(), Entry::Same);
        // A quote in a path is escaped, and read back as it was.
        let t: toml::Table = text.parse().unwrap();
        assert_eq!(
            t["mcp_servers"]["peerharness"]["args"][1].as_str(),
            Some("/h \"x\"")
        );
        assert!(!add_toml_entry(&path, &s, &backups).unwrap().changed);

        let e = remove_toml_entry(&path, &s, &backups).unwrap();
        assert!(e.changed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), mine);
        assert_eq!(toml_entry(&path, &s).unwrap(), Entry::Absent);

        // A new file holds the block alone.
        let fresh = tmp.path().join("new").join("config.toml");
        add_toml_entry(&fresh, &s, &backups).unwrap();
        assert_eq!(std::fs::read_to_string(&fresh).unwrap(), s.block());
        remove_toml_entry(&fresh, &s, &backups).unwrap();
        assert_eq!(std::fs::read_to_string(&fresh).unwrap(), "");
    }

    #[test]
    fn a_toml_entry_that_is_not_ours_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let s = server();
        // The owner's own entry of that name.
        let theirs = "[mcp_servers.peerharness]\ncommand = \"peerharness\"\nargs = [\"mcp\"]\n";
        std::fs::write(&path, theirs).unwrap();
        assert_eq!(toml_entry(&path, &s).unwrap(), Entry::Other);
        assert!(matches!(
            add_toml_entry(&path, &s, tmp.path()),
            Err(AgentConfigError::Taken)
        ));
        assert!(!remove_toml_entry(&path, &s, tmp.path()).unwrap().changed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), theirs);

        // Servers as an inline table: a block would not parse, so nothing is written.
        let inline = "mcp_servers = { other = { command = \"o\" } }\n";
        std::fs::write(&path, inline).unwrap();
        assert!(add_toml_entry(&path, &s, tmp.path()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), inline);

        // A file that does not parse is not touched.
        std::fs::write(&path, "this is = = not toml").unwrap();
        assert!(matches!(
            add_toml_entry(&path, &s, tmp.path()),
            Err(AgentConfigError::Malformed)
        ));

        // Our block edited by hand is no longer ours to remove.
        std::fs::write(&path, "").unwrap();
        add_toml_entry(&path, &s, tmp.path()).unwrap();
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("args = [", "startup_timeout_sec = 20\nargs = [");
        std::fs::write(&path, &edited).unwrap();
        assert!(!remove_toml_entry(&path, &s, tmp.path()).unwrap().changed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    }
}
