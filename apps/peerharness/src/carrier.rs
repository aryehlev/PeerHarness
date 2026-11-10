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

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::error::usage;
use crate::home::{read_bounded_file, write_shared_file};

/// Most bytes read from one file or one directory.
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// Most bytes of one record file in a directory (an event is at most 64 KiB and a
/// bundle at most 256 KiB before JSON escaping).
pub const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

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
    /// One JSON object per element (`{"event": …}` or `{"bundle": …}`), unverified.
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

/// The file name a line is kept under in a directory, taken from the line's own
/// content: the event id or the bundle digest it states.
pub fn entry_name(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line).ok()?;
    let (kind, id) = if let Some(ev) = v.get("event") {
        ("event", ev.get("event_id")?.as_str()?)
    } else {
        ("bundle", v.get("bundle")?.get("digest")?.as_str()?)
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
