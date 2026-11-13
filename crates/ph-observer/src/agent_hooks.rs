//! PeerHarness's hook entries in another coding agent's hooks file (ADR-053).
//!
//! Several agents run a command when their user submits a prompt and when a turn ends,
//! as Claude Code does, and keep those commands in a JSON file: an object of event
//! names, each an array of entries. The files differ in where that object is (`hooks`,
//! or the top level), in what the events are called and in what an entry looks like, so
//! the caller gives the [`Place`] and the entries it wants; this module only puts them
//! in and takes them out.
//!
//! The rules are those of [`crate::settings`] and [`crate::agent_config`]:
//!
//! * **Which entries are ours.** An element of an event's array is PeerHarness's when
//!   its command (its `command` or `bash` member, or the `command` of the one hook in
//!   its `hooks` array) is exactly `[PEERHARNESS_HOME=<home>] <.../peerharness> hook
//!   <event> <agent>` for the same home and the same agent. Everything else is the
//!   owner's and is never changed, moved or removed.
//! * [`add_hooks`] replaces such an element in place, so a moved binary is updated
//!   rather than added a second time, and appends a new one at the end of the array.
//!   The position of every other element is kept (Codex ties a hook's trust to it).
//! * [`remove_hooks`] takes out every such element, and the arrays and the object of
//!   events that this emptied. When what is left is no more than the members
//!   PeerHarness starts a new file with, the file is removed: it holds nothing of its
//!   owner's.
//! * Every change is idempotent, backs the file up first, checks that nobody changed it
//!   meanwhile and replaces it atomically. A file that does not parse (one with
//!   comments, say) is never rewritten.
//!
//! Errors are [`AgentConfigError`]: static text and I/O kinds, never the file's content.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::agent_config::{
    commit, io_err, parse_json, read, resolve_target, to_doc, AgentConfigError, Edit, Result,
};
use crate::fsutil::parent_dir;
use crate::json_doc::{Doc, Obj};
use crate::settings::parse_agent_command;

/// Where an agent keeps its hooks.
#[derive(Clone, Debug)]
pub struct Place<'a> {
    /// The JSON file.
    pub path: &'a Path,
    /// The members from the top level down to the object of events (`["hooks"]`, or
    /// nothing when the events are the top level).
    pub at: &'a [&'a str],
    /// Members a file PeerHarness creates starts with (`"version": 1`, say).
    pub first: &'a [(&'a str, Value)],
    /// How many directories above the file exist only for it (a plugin's folder):
    /// they are removed with the file when they are empty.
    pub own_dirs: usize,
}

/// Whose entries are looked for: the pinned home of the hook command, and the agent.
#[derive(Clone, Copy, Debug)]
pub struct Ours<'a> {
    /// The `PEERHARNESS_HOME` the commands pin, if any.
    pub home: Option<&'a str>,
    /// The agent's id, the last word of the commands.
    pub agent: &'a str,
}

/// What a hooks file holds of PeerHarness's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hooks {
    /// No entry of ours (or no file).
    Absent,
    /// Exactly the wanted entries, once each.
    Installed,
    /// Entries of ours that are not the wanted ones: another binary's path, an event
    /// that is no longer wanted, or one of several missing.
    Outdated,
}

fn element_command(element: &Doc) -> Option<&str> {
    let obj = element.as_object()?;
    if let Some(c) = obj.get("command").or_else(|| obj.get("bash")) {
        return c.as_str();
    }
    match obj.get("hooks")?.as_array()?.as_slice() {
        [one] => one.as_object()?.get("command")?.as_str(),
        _ => None,
    }
}

fn is_ours(element: &Doc, ours: Ours<'_>) -> bool {
    element_command(element)
        .and_then(parse_agent_command)
        .is_some_and(|(home, agent)| home.as_deref() == ours.home && agent == ours.agent)
}

const NOT_AN_OBJECT: AgentConfigError = AgentConfigError::UnexpectedStructure {
    what: "the hooks' place is not an object",
};

/// The object of events, if every step down to it is an object.
fn events<'d>(doc: &'d Doc, at: &[&str]) -> Result<Option<&'d Obj>> {
    let mut cur = doc
        .as_object()
        .ok_or(AgentConfigError::UnexpectedStructure {
            what: "top level is not an object",
        })?;
    for key in at {
        match cur.get(key) {
            None => return Ok(None),
            Some(d) => cur = d.as_object().ok_or(NOT_AN_OBJECT)?,
        }
    }
    Ok(Some(cur))
}

/// The object of events, created on the way down where it is missing.
fn events_mut<'d>(doc: &'d mut Doc, at: &[&str]) -> Result<&'d mut Obj> {
    let mut cur = doc
        .as_object_mut()
        .ok_or(AgentConfigError::UnexpectedStructure {
            what: "top level is not an object",
        })?;
    for key in at {
        if !cur.contains_key(key) {
            cur.insert(key, Doc::Object(Obj::new()));
        }
        cur = cur
            .get_mut(key)
            .and_then(Doc::as_object_mut)
            .ok_or(NOT_AN_OBJECT)?;
    }
    Ok(cur)
}

fn wanted(want: &[(&str, Value)]) -> Result<Vec<(String, Doc)>> {
    want.iter()
        .map(|(event, entry)| Ok(((*event).to_owned(), to_doc(entry)?)))
        .collect()
}

fn state_in(doc: &Doc, at: &[&str], ours: Ours<'_>, want: &[(String, Doc)]) -> Result<Hooks> {
    let Some(events) = events(doc, at)? else {
        return Ok(Hooks::Absent);
    };
    let mut found = 0usize;
    let mut as_wanted = 0usize;
    for (event, list) in events.iter() {
        let Some(list) = list.as_array() else {
            continue;
        };
        let mine: Vec<&Doc> = list.iter().filter(|e| is_ours(e, ours)).collect();
        found += mine.len();
        if let ([one], Some((_, entry))) = (mine.as_slice(), want.iter().find(|(e, _)| e == event))
        {
            if *one == entry {
                as_wanted += 1;
            }
        }
    }
    Ok(if found == 0 {
        Hooks::Absent
    } else if found == want.len() && as_wanted == want.len() {
        Hooks::Installed
    } else {
        Hooks::Outdated
    })
}

/// What the file at `place` holds of PeerHarness's, compared with `want` (event name
/// and entry). Read-only.
pub fn hooks(place: &Place<'_>, ours: Ours<'_>, want: &[(&str, Value)]) -> Result<Hooks> {
    let Some(bytes) = read(place.path)? else {
        return Ok(Hooks::Absent);
    };
    state_in(&parse_json(&bytes)?, place.at, ours, &wanted(want)?)
}

fn serialize(doc: &Doc) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(doc).map_err(|_| AgentConfigError::UnexpectedStructure {
            what: "the file could not be serialized",
        })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The members a file PeerHarness creates starts with, and nothing else.
fn first_only(place: &Place<'_>) -> Result<Doc> {
    let mut o = Obj::new();
    for (k, v) in place.first {
        o.insert(k, to_doc(v)?);
    }
    Ok(Doc::Object(o))
}

/// The file PeerHarness creates before any hook is in it.
fn blank(place: &Place<'_>) -> Result<Doc> {
    let mut doc = first_only(place)?;
    events_mut(&mut doc, place.at)?;
    Ok(doc)
}

/// Removes the object of events when it is empty and is not the top level.
fn drop_empty_events(doc: &mut Doc, at: &[&str]) -> Result<()> {
    let Some((last, above)) = at.split_last() else {
        return Ok(());
    };
    let parent = events_mut(doc, above)?;
    if parent
        .get(last)
        .and_then(Doc::as_object)
        .is_some_and(Obj::is_empty)
    {
        parent.remove(last);
    }
    Ok(())
}

/// Removes our elements from every event's array, and the arrays this emptied.
/// Returns how many elements went.
fn take_out(events: &mut Obj, ours: Ours<'_>, keep: &[(String, Doc)]) -> usize {
    let mut removed = 0;
    let mut emptied = Vec::new();
    for (event, list) in events.iter_mut() {
        if keep.iter().any(|(e, _)| e == event) {
            continue;
        }
        let Some(list) = list.as_array_mut() else {
            continue;
        };
        let before = list.len();
        list.retain(|e| !is_ours(e, ours));
        if list.len() != before {
            removed += before - list.len();
            if list.is_empty() {
                emptied.push(event.to_owned());
            }
        }
    }
    for event in &emptied {
        events.remove(event);
    }
    removed
}

/// Puts the `want`ed entries (event name and entry) into the file at `place`, which is
/// created when it does not exist. Entries of ours that are there already are brought
/// up to date in place; ours under an event that is not wanted are removed.
pub fn add_hooks(
    place: &Place<'_>,
    ours: Ours<'_>,
    want: &[(&str, Value)],
    backups_dir: &Path,
) -> Result<Edit> {
    let target = resolve_target(place.path)?;
    let original = read(&target)?;
    let mut doc = match &original {
        None => blank(place)?,
        Some(b) => parse_json(b)?,
    };
    let want = wanted(want)?;
    if state_in(&doc, place.at, ours, &want)? == Hooks::Installed {
        return Ok(Edit::default());
    }
    let events = events_mut(&mut doc, place.at)?;
    take_out(events, ours, &want);
    for (event, entry) in &want {
        if !events.contains_key(event) {
            events.insert(event, Doc::Array(Vec::new()));
        }
        let list = events.get_mut(event).and_then(Doc::as_array_mut).ok_or(
            AgentConfigError::UnexpectedStructure {
                what: "an event's hooks are not an array",
            },
        )?;
        match list.iter().position(|e| is_ours(e, ours)) {
            None => list.push(entry.clone()),
            Some(first) => {
                list[first] = entry.clone();
                let mut i = 0;
                list.retain(|e| {
                    i += 1;
                    i - 1 <= first || !is_ours(e, ours)
                });
            }
        }
    }
    let backup_path = commit(&target, original.as_deref(), &serialize(&doc)?, backups_dir)?;
    Ok(Edit {
        changed: true,
        backup_path,
    })
}

/// Takes every entry of ours out of the file at `place`. A file that then holds no
/// more than what PeerHarness starts one with is removed, with the directories of
/// [`Place::own_dirs`] when they are empty.
pub fn remove_hooks(place: &Place<'_>, ours: Ours<'_>, backups_dir: &Path) -> Result<Edit> {
    let target = resolve_target(place.path)?;
    let Some(original) = read(&target)? else {
        return Ok(Edit::default());
    };
    let mut doc = parse_json(&original)?;
    if events(&doc, place.at)?.is_none() {
        return Ok(Edit::default());
    }
    if take_out(events_mut(&mut doc, place.at)?, ours, &[]) == 0 {
        return Ok(Edit::default());
    }
    // The object of events goes when this emptied it, as in Claude Code's settings.
    drop_empty_events(&mut doc, place.at)?;
    if doc != first_only(place)? {
        let backup_path = commit(&target, Some(&original), &serialize(&doc)?, backups_dir)?;
        return Ok(Edit {
            changed: true,
            backup_path,
        });
    }
    // Nothing of the owner's is left in it. The backup is made by a commit of the same
    // bytes, which also checks that nobody changed the file meanwhile.
    let backup_path = commit(&target, Some(&original), &original, backups_dir)?;
    fs::remove_file(&target).map_err(io_err("remove hooks file"))?;
    let mut dir = parent_dir(&target);
    for _ in 0..place.own_dirs {
        // Fails, and stops, at the first directory that holds anything else.
        if fs::remove_dir(&dir).is_err() {
            break;
        }
        dir = parent_dir(&dir);
    }
    Ok(Edit {
        changed: true,
        backup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    const OURS: Ours<'static> = Ours {
        home: Some("/h"),
        agent: "codex",
    };

    fn cmd(exe: &str, event: &str, agent: &str) -> String {
        format!("PEERHARNESS_HOME='/h' '{exe}' hook {event} {agent}")
    }

    fn group(command: &str) -> Value {
        json!({"hooks": [{"type": "command", "command": command, "timeout": 5}]})
    }

    fn want(exe: &str) -> Vec<(&'static str, Value)> {
        vec![
            (
                "UserPromptSubmit",
                group(&cmd(exe, "user-prompt-submit", "codex")),
            ),
            ("Stop", group(&cmd(exe, "stop", "codex"))),
        ]
    }

    fn place<'a>(path: &'a Path, at: &'a [&'a str]) -> Place<'a> {
        Place {
            path,
            at,
            first: &[],
            own_dirs: 0,
        }
    }

    fn read_json(p: &Path) -> Value {
        serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
    }

    #[test]
    fn a_new_file_gets_the_hooks_and_loses_them_again() {
        let t = TempDir::new().unwrap();
        let file = t.path().join("codex/hooks.json");
        let backups = t.path().join("backups");
        let p = place(&file, &["hooks"]);
        let w = want("/bin/peerharness");
        assert_eq!(hooks(&p, OURS, &w).unwrap(), Hooks::Absent);

        let e = add_hooks(&p, OURS, &w, &backups).unwrap();
        assert!(e.changed && e.backup_path.is_none());
        assert_eq!(hooks(&p, OURS, &w).unwrap(), Hooks::Installed);
        assert_eq!(
            read_json(&file),
            json!({"hooks": {"UserPromptSubmit": [w[0].1], "Stop": [w[1].1]}})
        );
        // Idempotent: nothing is written, no backup is made.
        assert_eq!(add_hooks(&p, OURS, &w, &backups).unwrap(), Edit::default());

        // The file held nothing else, so it goes; its directory was not ours.
        let e = remove_hooks(&p, OURS, &backups).unwrap();
        assert!(e.changed && e.backup_path.is_some());
        assert!(!file.exists());
        assert!(file.parent().unwrap().is_dir());
        assert_eq!(remove_hooks(&p, OURS, &backups).unwrap(), Edit::default());
    }

    #[test]
    fn the_owners_hooks_keep_their_place_and_their_content() {
        let t = TempDir::new().unwrap();
        let file = t.path().join("hooks.json");
        let theirs = json!({
            "description": "mine",
            "hooks": {
                "Stop": [group("say done")],
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "check"}]}]
            }
        });
        fs::write(&file, serde_json::to_vec_pretty(&theirs).unwrap()).unwrap();
        let backups = t.path().join("backups");
        let p = place(&file, &["hooks"]);
        let w = want("/bin/peerharness");

        let e = add_hooks(&p, OURS, &w, &backups).unwrap();
        assert_eq!(
            fs::read(e.backup_path.unwrap()).unwrap(),
            serde_json::to_vec_pretty(&theirs).unwrap()
        );
        let now = read_json(&file);
        // Theirs first, at the index it had; ours after it.
        assert_eq!(now["hooks"]["Stop"], json!([group("say done"), w[1].1]));
        assert_eq!(now["hooks"]["PreToolUse"], theirs["hooks"]["PreToolUse"]);
        assert_eq!(now["description"], "mine");

        remove_hooks(&p, OURS, &backups).unwrap();
        assert_eq!(read_json(&file), theirs);
    }

    #[test]
    fn a_settings_file_keeps_everything_else_and_loses_the_hooks_member_it_got() {
        let t = TempDir::new().unwrap();
        let file = t.path().join("settings.json");
        fs::write(&file, r#"{"theme": "dark", "n": 1e5}"#).unwrap();
        let backups = t.path().join("backups");
        let p = place(&file, &["hooks"]);
        add_hooks(&p, OURS, &want("/bin/peerharness"), &backups).unwrap();
        assert!(read_json(&file)["hooks"]["Stop"].is_array());
        remove_hooks(&p, OURS, &backups).unwrap();
        // The number keeps the text it had.
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "{\n  \"theme\": \"dark\",\n  \"n\": 1e5\n}\n"
        );
    }

    #[test]
    fn a_moved_binary_is_brought_up_to_date_and_not_added_twice() {
        let t = TempDir::new().unwrap();
        let file = t.path().join("hooks.json");
        let backups = t.path().join("backups");
        let p = place(&file, &["hooks"]);
        add_hooks(&p, OURS, &want("/old/peerharness"), &backups).unwrap();
        let w = want("/new/peerharness");
        assert_eq!(hooks(&p, OURS, &w).unwrap(), Hooks::Outdated);
        assert!(add_hooks(&p, OURS, &w, &backups).unwrap().changed);
        assert_eq!(
            read_json(&file),
            json!({"hooks": {"UserPromptSubmit": [w[0].1], "Stop": [w[1].1]}})
        );
        // An event that is no longer wanted loses our entry.
        let only_prompt = &w[..1];
        assert_eq!(hooks(&p, OURS, only_prompt).unwrap(), Hooks::Outdated);
        add_hooks(&p, OURS, only_prompt, &backups).unwrap();
        assert_eq!(
            read_json(&file),
            json!({"hooks": {"UserPromptSubmit": [w[0].1]}})
        );
    }

    #[test]
    fn another_home_another_agent_and_a_look_alike_are_not_ours() {
        let t = TempDir::new().unwrap();
        let file = t.path().join("hooks.json");
        let others = json!({"hooks": {"Stop": [
            group("PEERHARNESS_HOME='/other' '/bin/peerharness' hook stop codex"),
            group("PEERHARNESS_HOME='/h' '/bin/peerharness' hook stop droid"),
            group("PEERHARNESS_HOME='/h' '/bin/peerharness' hook stop"),
            group("PEERHARNESS_HOME='/h' '/bin/peerharness' hook stop codex; rm -rf x"),
            group("PEERHARNESS_HOME='/h' '/bin/other' hook stop codex"),
            {"hooks": [
                {"type": "command", "command": cmd("/bin/peerharness", "stop", "codex")},
                {"type": "command", "command": "second"}
            ]}
        ]}});
        fs::write(&file, serde_json::to_vec(&others).unwrap()).unwrap();
        let backups = t.path().join("backups");
        let p = place(&file, &["hooks"]);
        assert_eq!(
            hooks(&p, OURS, &want("/bin/peerharness")).unwrap(),
            Hooks::Absent
        );
        assert_eq!(remove_hooks(&p, OURS, &backups).unwrap(), Edit::default());
        assert_eq!(read_json(&file), others);
    }

    #[test]
    fn flat_entries_events_at_the_top_level_and_a_folder_of_our_own() {
        let t = TempDir::new().unwrap();
        let backups = t.path().join("backups");
        let ours = Ours {
            home: None,
            agent: "cursor",
        };
        // Cursor: flat entries under `hooks`, and a version at the top.
        let file = t.path().join("hooks.json");
        let first = [("version", json!(1))];
        let p = Place {
            path: &file,
            at: &["hooks"],
            first: &first,
            own_dirs: 0,
        };
        let entry =
            json!({"command": "'/bin/peerharness' hook user-prompt-submit cursor", "timeout": 5});
        let w = [("beforeSubmitPrompt", entry.clone())];
        add_hooks(&p, ours, &w, &backups).unwrap();
        assert_eq!(
            read_json(&file),
            json!({"version": 1, "hooks": {"beforeSubmitPrompt": [entry]}})
        );
        assert_eq!(hooks(&p, ours, &w).unwrap(), Hooks::Installed);
        remove_hooks(&p, ours, &backups).unwrap();
        assert!(!file.exists());

        // Droid: the events are the top level. Copilot's `bash` member is read too.
        let file = t.path().join("droid.json");
        fs::write(&file, r#"{"Stop": [{"bash": "theirs"}]}"#).unwrap();
        let p = place(&file, &[]);
        let ours = Ours {
            home: None,
            agent: "droid",
        };
        let entry = json!({"type": "command", "bash": "'/bin/peerharness' hook stop droid"});
        add_hooks(&p, ours, &[("Stop", entry.clone())], &backups).unwrap();
        assert_eq!(
            read_json(&file),
            json!({"Stop": [{"bash": "theirs"}, entry]})
        );
        remove_hooks(&p, ours, &backups).unwrap();
        assert_eq!(read_json(&file), json!({"Stop": [{"bash": "theirs"}]}));

        // goose: a plugin folder that exists only for the file goes with it, and the
        // folder above, which is not ours, stays.
        let file = t.path().join("plugins/peerharness/hooks/hooks.json");
        let p = Place {
            path: &file,
            at: &["hooks"],
            first: &[],
            own_dirs: 2,
        };
        let ours = Ours {
            home: None,
            agent: "goose",
        };
        let w = [(
            "UserPromptSubmit",
            group("'/bin/peerharness' hook user-prompt-submit goose"),
        )];
        add_hooks(&p, ours, &w, &backups).unwrap();
        assert!(file.is_file());
        remove_hooks(&p, ours, &backups).unwrap();
        assert!(!t.path().join("plugins/peerharness").exists());
        assert!(t.path().join("plugins").is_dir());
    }

    #[test]
    fn a_file_that_cannot_be_edited_safely_is_left_alone() {
        let t = TempDir::new().unwrap();
        let backups = t.path().join("backups");
        let w = want("/bin/peerharness");
        for (content, at) in [
            ("{ // mine\n \"hooks\": {} }", &["hooks"][..]),
            (r#"{"hooks": []}"#, &["hooks"][..]),
            (r#"{"hooks": {"Stop": {}}}"#, &["hooks"][..]),
            (r#"{"a": 1, "a": 2}"#, &[][..]),
            ("[]", &[][..]),
        ] {
            let file = t.path().join("f.json");
            fs::write(&file, content).unwrap();
            let p = place(&file, at);
            assert!(add_hooks(&p, OURS, &w, &backups).is_err(), "{content}");
            assert_eq!(fs::read_to_string(&file).unwrap(), content);
        }
        assert!(!backups.exists());
    }
}
