//! `observe demo` and `observe import`: synthetic local observations for demos and tests.
//! Text is redacted and bounded on the way in (`NormalizedObservation::from_raw`).

use std::path::Path;

use anyhow::Result;
use ph_core::{
    NormalizedObservation, ObservationId, ObservationKind, ObservationSource, Timestamp,
};
use serde::Deserialize;
use serde_json::json;

use super::Ctx;
use crate::detect::{self, DetectSummary};
use crate::error::usage;
use crate::home::read_bounded_file;
use crate::node::Node;
use crate::output::{Report, Text};

/// The demo repository key.
pub const DEMO_REPO: &str = "demo-repo";

/// The synthetic correction (injected twice).
pub const DEMO_CORRECTION: &str = "No, use pnpm, not npm, for this repo.";

const MAX_IMPORT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_IMPORT_LINES: usize = 10_000;
const MAX_IMPORT_LINE_BYTES: usize = 64 * 1024;
const MAX_REPO_CHARS: usize = 128;

pub fn demo(ctx: &Ctx) -> Result<Report> {
    let node = ctx.open_node()?;
    let now = node.now();
    let retention = node.config.retention.observation_secs();
    let mut stored = 0;
    for i in 0..2 {
        let obs = NormalizedObservation::from_raw(
            ObservationId::random()?,
            now.minus_secs(60 - i * 30),
            ObservationSource::Demo,
            None,
            DEMO_REPO.to_owned(),
            ObservationKind::UserPrompt,
            DEMO_CORRECTION,
        );
        if detect::store_observation(&node.store, &obs, retention)? {
            stored += 1;
        }
    }
    let summary = detect::run_detection(&node.store, Some(DEMO_REPO), retention, now)?;
    Ok(report(
        &node,
        "Injected the synthetic correction \"No, use pnpm, not npm\" twice into repo demo-repo.",
        stored,
        0,
        &summary,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportLine {
    kind: ObservationKind,
    repo: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    created_at: Option<Timestamp>,
}

pub fn import(ctx: &Ctx, file: &Path) -> Result<Report> {
    let node = ctx.open_node()?;
    let now = node.now();
    let retention = node.config.retention.observation_secs();
    let bytes = read_bounded_file(file, MAX_IMPORT_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| usage("the import file is not UTF-8"))?;
    let mut stored = 0usize;
    let mut skipped = 0usize;
    let mut repos: Vec<String> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if n >= MAX_IMPORT_LINES {
            return Err(usage(format!(
                "the import file has more than {MAX_IMPORT_LINES} lines"
            )));
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(obs) = parse_line(line, now) else {
            skipped += 1;
            continue;
        };
        if !repos.contains(&obs.repo_key) {
            repos.push(obs.repo_key.clone());
        }
        if detect::store_observation(&node.store, &obs, retention)? {
            stored += 1;
        }
    }
    let mut summary = DetectSummary::default();
    for r in &repos {
        let s = detect::run_detection(&node.store, Some(r), retention, now)?;
        summary.created.extend(s.created);
        summary.merged.extend(s.merged);
    }
    Ok(report(
        &node,
        &format!("Imported {stored} observation(s)."),
        stored,
        skipped,
        &summary,
    ))
}

/// Parses one import line; `None` for anything malformed (never echoes content).
fn parse_line(line: &str, now: Timestamp) -> Option<NormalizedObservation> {
    if line.len() > MAX_IMPORT_LINE_BYTES {
        return None;
    }
    let l: ImportLine = serde_json::from_str(line).ok()?;
    let repo_ok = !l.repo.is_empty()
        && l.repo.chars().count() <= MAX_REPO_CHARS
        && ph_protocol::text::check_text(
            "repo",
            &l.repo,
            1,
            MAX_REPO_CHARS,
            ph_protocol::text::Lines::Single,
        )
        .is_ok();
    if !repo_ok {
        return None;
    }
    let created = l.created_at.filter(|t| *t <= now).unwrap_or(now);
    let text = match l.kind {
        ObservationKind::UserPrompt if l.text.trim().is_empty() => return None,
        ObservationKind::AgentStop => String::new(),
        _ => l.text,
    };
    Some(NormalizedObservation::from_raw(
        ObservationId::random().ok()?,
        created,
        ObservationSource::Import,
        l.session.as_deref().and_then(ph_observer::session_hash),
        l.repo,
        l.kind,
        &text,
    ))
}

fn report(node: &Node, headline: &str, stored: usize, skipped: usize, s: &DetectSummary) -> Report {
    let ids: Vec<String> = s
        .created
        .iter()
        .chain(&s.merged)
        .map(|i| i.to_string())
        .collect();
    let json = json!({
        "observations_stored": stored,
        "lines_skipped": skipped,
        "candidates_created": s.created.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "candidates_updated": s.merged.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
    });
    let mut t = Text::new();
    t.line(headline);
    if skipped > 0 {
        t.line(format!("Skipped {skipped} malformed line(s)."));
    }
    if ids.is_empty() {
        t.line("No new candidate conventions detected.");
    } else {
        t.line(format!(
            "{} new, {} updated candidate(s): {}",
            s.created.len(),
            s.merged.len(),
            ids.join(", ")
        ));
        t.line("Next: `peerharness inbox`.");
    }
    let _ = node;
    Report::new(json, t.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_lines() {
        let now = Timestamp::now();
        let o = parse_line(
            r#"{"kind":"user_prompt","repo":"demo-repo","text":"No, use pnpm, not npm."}"#,
            now,
        )
        .unwrap();
        assert_eq!(o.repo_key, "demo-repo");
        assert_eq!(o.source, ObservationSource::Import);
        let secret = parse_line(r#"{"kind":"user_prompt","repo":"r","text":"key sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"}"#, now).unwrap();
        assert!(!secret.text.contains("FAKEFAKE"));
        assert!(parse_line(r#"{"kind":"user_prompt","repo":"r","text":""}"#, now).is_none());
        assert!(parse_line(r#"{"kind":"bogus","repo":"r","text":"x"}"#, now).is_none());
        assert!(parse_line(
            r#"{"kind":"user_prompt","repo":"r","text":"x","extra":1}"#,
            now
        )
        .is_none());
        assert!(parse_line(r#"{"kind":"user_prompt","repo":"a\nb","text":"x"}"#, now).is_none());
        assert!(parse_line("not json", now).is_none());
        let stop = parse_line(r#"{"kind":"agent_stop","repo":"r","text":"ignored"}"#, now).unwrap();
        assert!(stop.text.is_empty());
    }

    #[test]
    fn sample_file_parses() {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../demo/sample-events.jsonl"
        );
        let text = std::fs::read_to_string(p).unwrap();
        let now = Timestamp::now();
        let parsed: Vec<_> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| parse_line(l, now))
            .collect();
        assert!(parsed.len() >= 4);
        assert!(parsed.iter().all(Option::is_some));
    }
}
