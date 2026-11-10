//! Carrying a circle's signed records between nodes without a network: as one JSON
//! lines file, or as a directory holding one small file per record.
//!
//! The directory form exists so that a team can keep its circle in a place it already
//! shares, typically a git repository. Each record is a file named by its own hash
//! (`event-<hex>.json`, `bundle-<hex>.json`), so two members who add records at the same
//! time add different files and nothing ever needs merging.
//!
//! Nothing read here is trusted. File names are only a convenience: every line goes
//! through `governance::ingest`, which verifies it, and a file whose content does not
//! verify is simply not stored. Reading is bounded, takes regular files only and never
//! follows a symbolic link.
//!
//! A record is parsed the way a frame from the wire is ([`parse_record`]): with the
//! protocol's strict parser, under a size and a depth limit that are applied before
//! anything in it is looked at. Nothing here reads a record with plain `serde_json`,
//! which keeps the last of two members with the same name and so would hand the checks
//! that follow a different object from the one in the file.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ph_core::Digest;
use ph_protocol::jcs::{self, ParseLimits};
use ph_protocol::limits::MAX_DEPTH;
use serde_json::Value;

use crate::error::usage;
use crate::home::{read_bounded_file, write_shared_file};

/// Most bytes read from one file or one directory.
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// Most bytes of one record: a line of a file, or a record file in a directory (an
/// event is at most 64 KiB and a bundle at most 256 KiB before JSON escaping).
pub const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

/// The limits one record is parsed under: [`MAX_ENTRY_BYTES`], and one level of nesting
/// more than a signed object may have, for the object that wraps it. The event inside
/// is held to the protocol's own limits again when it is verified.
pub const RECORD_LIMITS: ParseLimits = ParseLimits {
    max_bytes: MAX_ENTRY_BYTES as usize,
    max_depth: MAX_DEPTH + 1,
};

/// Most entries looked at in a directory.
pub const MAX_DIR_ENTRIES: usize = 100_000;

/// The explanation written next to the records.
pub const README_NAME: &str = "README.md";

const README_TEXT: &str = "# PeerHarness records\n\
\n\
This directory holds the signed records of a PeerHarness circle: its charter (the rules\n\
of the vote and the roll of members), proposals, ballots, and the text of the rules that\n\
were voted on. There is one file per record, named by its hash.\n\
\n\
- Do not edit these files. Every node verifies each one and ignores what does not verify.\n\
- Bring your node and this directory in line with\n\
  `peerharness events sync <this directory> --circle <name>`, then commit what it added.\n\
- Anyone who can read this directory can read the roll, the proposals and the ballots.\n";

/// What was read from a file or a directory.
#[derive(Debug, Default)]
pub struct Source {
    /// One record per element (`{"event": …}` or `{"bundle": …}`), as it was read:
    /// neither parsed ([`parse_record`]) nor verified.
    pub lines: Vec<String>,
    /// Directory entries that were not read: other files, links, oversized files.
    pub ignored: usize,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `name` is a record file name: `event-<64 hex>.json` or `bundle-<64 hex>.json`.
pub fn is_entry_name(name: &str) -> bool {
    name.strip_suffix(".json")
        .and_then(|stem| {
            stem.strip_prefix("event-")
                .or_else(|| stem.strip_prefix("bundle-"))
        })
        .is_some_and(is_hex64)
}

/// One record as a file or a directory carries it: strictly parsed, and not verified.
pub enum Record {
    /// `{"event": <envelope>}`: the envelope object, to be offered to
    /// `governance::ingest`.
    Event(Value),
    /// `{"bundle": {"digest": …, "skill_md": …}}`: the text of a rule and the digest it
    /// is offered under.
    Bundle { digest: Digest, skill_md: String },
}

/// Parses one record, the way a frame from the wire is parsed: at most
/// [`MAX_ENTRY_BYTES`] (checked before anything is parsed), integers only, no member
/// twice at any level, and nothing but the one member a record has. `{"event": …}`
/// beside a `"bundle": null`, or beside a member this version does not know, is not a
/// record. Whether the event verifies is for `governance::ingest` to say.
pub fn parse_record(line: &str) -> Option<Record> {
    let Ok(Value::Object(members)) = jcs::parse_strict(line.as_bytes(), RECORD_LIMITS) else {
        return None;
    };
    let mut members = members.into_iter();
    let (Some((name, value)), None) = (members.next(), members.next()) else {
        return None;
    };
    match (name.as_str(), value) {
        ("event", event @ Value::Object(_)) => Some(Record::Event(event)),
        ("bundle", Value::Object(bundle)) if bundle.len() == 2 => Some(Record::Bundle {
            digest: bundle.get("digest")?.as_str()?.parse().ok()?,
            skill_md: bundle.get("skill_md")?.as_str()?.to_owned(),
        }),
        _ => None,
    }
}

/// The file name a line is kept under in a directory, taken from the line's own
/// content: the event id or the bundle digest it states.
pub fn entry_name(line: &str) -> Option<String> {
    let (kind, id) = match parse_record(line)? {
        Record::Event(event) => ("event", event.get("event_id")?.as_str()?.to_owned()),
        Record::Bundle { digest, .. } => ("bundle", digest.to_string()),
    };
    let hex = id.strip_prefix("sha256:")?;
    is_hex64(hex).then(|| format!("{kind}-{hex}.json"))
}

/// Reads the records offered at `path`: the lines of a JSON lines file, or the record
/// files of a directory in name order.
pub fn read_source(path: &Path) -> Result<Source> {
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_dir() {
        let bytes = read_bounded_file(path, MAX_SOURCE_BYTES)?;
        let text = String::from_utf8(bytes).map_err(|_| usage("that file is not UTF-8 text"))?;
        return Ok(Source {
            lines: text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect(),
            ignored: 0,
        });
    }
    let mut names: Vec<String> = Vec::new();
    let mut source = Source::default();
    for (seen, entry) in fs::read_dir(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .enumerate()
    {
        if seen >= MAX_DIR_ENTRIES {
            return Err(usage(format!(
                "{} holds more than {MAX_DIR_ENTRIES} entries",
                path.display()
            )));
        }
        let entry = entry.with_context(|| format!("cannot read {}", path.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == README_NAME || name == ".gitattributes" || name == ".gitkeep" {
            continue;
        }
        // `file_type` does not follow links: a link is never read, wherever it points.
        let regular = entry.file_type().is_ok_and(|t| t.is_file());
        if regular && is_entry_name(&name) {
            names.push(name);
        } else {
            source.ignored += 1;
        }
    }
    names.sort();
    let mut total: u64 = 0;
    for name in names {
        let file = path.join(&name);
        let Ok(bytes) = read_bounded_file(&file, MAX_ENTRY_BYTES) else {
            source.ignored += 1;
            continue;
        };
        total += bytes.len() as u64;
        if total > MAX_SOURCE_BYTES {
            return Err(usage(format!(
                "{} holds more than {MAX_SOURCE_BYTES} bytes of records",
                path.display()
            )));
        }
        match String::from_utf8(bytes) {
            // One record per file: anything after the first line is not read.
            Ok(text) => match text.lines().map(str::trim).find(|l| !l.is_empty()) {
                Some(line) => source.lines.push(line.to_owned()),
                None => source.ignored += 1,
            },
            Err(_) => source.ignored += 1,
        }
    }
    Ok(source)
}

/// Writes each line into `dir` under its content-derived name, unless a file with exactly
/// that content is already there. A file of that name with other content is replaced: the
/// lines given here were verified by this node, and whatever was there was not. Creates
/// the directory and its README when missing. Returns how many files were written.
pub fn write_dir(dir: &Path, lines: &[String]) -> Result<usize> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let readme = dir.join(README_NAME);
    if fs::symlink_metadata(&readme).is_err() {
        write_shared_file(&readme, README_TEXT.as_bytes())?;
    }
    let mut written = 0;
    for line in lines {
        let Some(name) = entry_name(line) else {
            continue;
        };
        let path = dir.join(name);
        let content = format!("{line}\n");
        let same = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
            && fs::read(&path).is_ok_and(|old| old == content.as_bytes());
        if same {
            continue;
        }
        // Never write through a link or onto a directory someone put in the way.
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.is_dir() {
                continue;
            }
            fs::remove_file(&path).with_context(|| format!("cannot replace {}", path.display()))?;
        }
        write_shared_file(&path, content.as_bytes())?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_line(hex: &str) -> String {
        format!(r#"{{"event":{{"event_id":"sha256:{hex}","type":"VOTE"}}}}"#)
    }

    #[test]
    fn names_come_from_content() {
        let hex = "ab".repeat(32);
        assert_eq!(
            entry_name(&event_line(&hex)).unwrap(),
            format!("event-{hex}.json")
        );
        let bundle = format!(r#"{{"bundle":{{"digest":"sha256:{hex}","skill_md":"x"}}}}"#);
        assert_eq!(entry_name(&bundle).unwrap(), format!("bundle-{hex}.json"));
        // Nothing that could leave the directory or collide with another kind.
        for bad in [
            r#"{"event":{"event_id":"sha256:../../x"}}"#.to_owned(),
            r#"{"event":{"event_id":"abc"}}"#.to_owned(),
            event_line(&"AB".repeat(32)),
            event_line("abcd"),
            r#"{"other":1}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert!(entry_name(&bad).is_none(), "{bad}");
        }
        assert!(is_entry_name(&format!("event-{hex}.json")));
        assert!(is_entry_name(&format!("bundle-{hex}.json")));
        assert!(!is_entry_name(&format!("event-{hex}.txt")));
        assert!(!is_entry_name(&format!("vote-{hex}.json")));
        assert!(!is_entry_name("event-abc.json"));
        assert!(!is_entry_name(README_NAME));
    }

    #[test]
    fn a_record_is_one_member_in_strict_json() {
        let hex = "ab".repeat(32);
        let event = event_line(&hex);
        assert!(matches!(
            parse_record(&event),
            Some(Record::Event(v)) if v["event_id"] == format!("sha256:{hex}")
        ));
        let bundle = format!(r#"{{"bundle":{{"digest":"sha256:{hex}","skill_md":"x"}}}}"#);
        assert!(matches!(
            parse_record(&bundle),
            Some(Record::Bundle { digest, skill_md })
                if digest.to_string() == format!("sha256:{hex}") && skill_md == "x"
        ));
        // Whitespace is not content: what is signed is the canonical form.
        assert!(parse_record(r#" { "event" : { "a" : 1 } } "#).is_some());

        let inner = r#"{"event_id":"sha256:00","type":"VOTE"}"#;
        for bad in [
            // A member twice: in the record, and inside the event.
            format!(r#"{{"event":{{}},"event":{inner}}}"#),
            r#"{"event":{"type":"VOTE","type":"PROPOSAL"}}"#.to_owned(),
            format!(
                r#"{{"bundle":{{"digest":"sha256:{hex}","digest":"sha256:{hex}","skill_md":"x"}}}}"#
            ),
            // A member a record does not have, and an explicit null.
            format!(r#"{{"event":{inner},"note":"x"}}"#),
            format!(r#"{{"event":{inner},"bundle":null}}"#),
            format!(r#"{{"bundle":{{"digest":"sha256:{hex}","skill_md":"x","name":"y"}}}}"#),
            format!(r#"{{"bundle":{{"digest":"sha256:{hex}","skill_md":null}}}}"#),
            format!(r#"{{"bundle":{{"digest":"sha256:{hex}"}}}}"#),
            r#"{"bundle":{"digest":"abc","skill_md":"x"}}"#.to_owned(),
            // Not an object where one belongs, or nothing at all.
            r#"{"event":"x"}"#.to_owned(),
            r#"{"event":null}"#.to_owned(),
            r#"{"bundle":[]}"#.to_owned(),
            r#"{"other":{}}"#.to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            // Numbers that are not integers, and data after the record.
            r#"{"event":{"n":1.5}}"#.to_owned(),
            r#"{"event":{"n":1e3}}"#.to_owned(),
            format!("{event}{event}"),
            "not json".to_owned(),
        ] {
            assert!(parse_record(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_record_is_held_to_a_size_and_a_depth_before_it_is_read() {
        // The size counts the line as it is, padding included.
        let pad = |len: usize| {
            let event = r#"{"a":1}}"#;
            let head = r#"{"event":"#;
            format!(
                "{head}{}{event}",
                " ".repeat(len - head.len() - event.len())
            )
        };
        let limit = RECORD_LIMITS.max_bytes;
        assert_eq!(limit as u64, MAX_ENTRY_BYTES);
        assert_eq!(pad(limit).len(), limit);
        assert!(parse_record(&pad(limit)).is_some());
        assert!(parse_record(&pad(limit + 1)).is_none());

        // An event may be as deep as the protocol lets a signed object be, inside the
        // one object that wraps it, and no deeper.
        let nested = |depth: usize| {
            format!(
                r#"{{"event":{}1{}}}"#,
                r#"{"a":"#.repeat(depth),
                "}".repeat(depth)
            )
        };
        assert!(parse_record(&nested(MAX_DEPTH)).is_some());
        assert!(parse_record(&nested(MAX_DEPTH + 1)).is_none());
    }

    #[test]
    fn a_directory_round_trips_and_ignores_everything_else() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("circle");
        let a = event_line(&"11".repeat(32));
        let b = event_line(&"22".repeat(32));
        assert_eq!(write_dir(&dir, &[b.clone(), a.clone()]).unwrap(), 2);
        // Writing the same lines again writes nothing.
        assert_eq!(write_dir(&dir, &[a.clone(), b.clone()]).unwrap(), 0);
        assert!(dir.join(README_NAME).is_file());

        // Things that do not belong: other files, a subdirectory, a link with a record's
        // name pointing outside, and a record file with no content.
        fs::write(dir.join("notes.txt"), "hello").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join(format!("event-{}.json", "44".repeat(32))), "\n").unwrap();
        #[cfg(unix)]
        {
            let outside = tmp.path().join("outside.json");
            fs::write(&outside, event_line(&"33".repeat(32))).unwrap();
            std::os::unix::fs::symlink(
                &outside,
                dir.join(format!("event-{}.json", "33".repeat(32))),
            )
            .unwrap();
        }
        let source = read_source(&dir).unwrap();
        assert_eq!(source.lines, vec![a.clone(), b.clone()]);
        assert_eq!(source.ignored, if cfg!(unix) { 4 } else { 3 });

        // A changed record file is put right by the next write.
        let path = dir.join(entry_name(&a).unwrap());
        fs::write(&path, "tampered\n").unwrap();
        assert_eq!(write_dir(&dir, std::slice::from_ref(&a)).unwrap(), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{a}\n"));
    }

    #[test]
    fn a_file_source_is_its_lines() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("x.jsonl");
        fs::write(&file, "one\n\n  two  \n").unwrap();
        let source = read_source(&file).unwrap();
        assert_eq!(source.lines, ["one", "two"]);
        assert!(read_source(&tmp.path().join("missing")).is_err());
    }
}
