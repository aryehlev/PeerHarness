//! `peerharness events`: exchanging a circle's signed records as a file or a directory.
//!
//! Every event is signed and names the charter it belongs to, so the carrier does not
//! need to be trusted: email, a shared folder, a git repository or a USB stick all work.
//! The importing node verifies every line through the same path a network peer's events
//! will take (`governance::ingest`).
//!
//! `events sync <dir>` is the form for a place a team already shares (see
//! `crate::carrier`): it imports what the directory holds and writes what it lacks.
//! Writing records out is the person's step (it decides who can read the circle's roll
//! and ballots), so `export` and `sync` refuse inside an agent session. Importing is
//! open to anyone: nothing is taken on trust.

use std::path::Path;

use anyhow::Result;
use serde_json::{json, Value};

use crate::carrier;
use crate::cli::EventsCommand;
use crate::commands::circle::find_circle;
use crate::commands::Ctx;
use crate::consent::human_only;
use crate::governance;
use crate::node::Node;
use crate::output::{safe, Report, Text};

pub fn run(ctx: &Ctx, command: EventsCommand) -> Result<Report> {
    match command {
        EventsCommand::Export { circle, out, dir } => {
            export(ctx, &circle, out.as_deref(), dir.as_deref())
        }
        EventsCommand::Import { file } => {
            let node = ctx.open_node()?;
            let (json, t) = import(&node, &file)?;
            Ok(Report::new(json, t.finish()))
        }
        EventsCommand::Sync { dir, circle } => sync(ctx, &dir, circle.as_deref()),
    }
}

fn export(ctx: &Ctx, circle: &str, out: Option<&Path>, dir: Option<&Path>) -> Result<Report> {
    human_only("writing a circle's records out")?;
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(circle))?;
    let bundles = crate::library::bundle_store(&node.home);
    let lines = governance::export_circle(&node.store, &bundles, &circle.circle_id)?;
    if let Some(dir) = dir {
        let dir = crate::home::absolute(dir)?;
        let written = carrier::write_dir(&dir, &lines)?;
        return Ok(Report::new(
            json!({
                "dir": dir.display().to_string(),
                "records": lines.len(),
                "written": written,
            }),
            format!(
                "Wrote {written} new file(s) for {} to {} ({} record(s) in all).\n\
                 Anyone who can read that directory can read the circle's roll and proposals.",
                safe(&circle.name),
                dir.display(),
                lines.len()
            ),
        ));
    }
    let text = lines.join("\n") + "\n";
    match out {
        Some(path) => {
            let path = crate::home::absolute(path)?;
            crate::home::write_private_file(&path, text.as_bytes())?;
            Ok(Report::new(
                json!({ "written": path.display().to_string(), "lines": lines.len() }),
                format!(
                    "Wrote {} line(s) for {} to {}.\n\
                     It contains the circle's roll and proposals. Give it only to members.",
                    lines.len(),
                    safe(&circle.name),
                    path.display()
                ),
            ))
        }
        // On stdout the lines themselves are the output, in both modes.
        None => Ok(Report::new(json!({ "lines": lines }), text)),
    }
}

/// Verifies and stores what `path` offers, then lets every circle settle: results are
/// published, passed amendments notarized (on the founder's node) and the rules in
/// force applied to the agent's skills directory.
fn import(node: &Node, path: &Path) -> Result<(Value, Text)> {
    let source = carrier::read_source(path)?;
    let bundles = crate::library::bundle_store(&node.home);
    let mut summary = governance::import_lines(
        &node.store,
        &bundles,
        source.lines.iter().map(String::as_str),
        node.now(),
    )?;
    // What the directory reader turned away before a line was made of it.
    summary.add_refused(governance::NOT_A_RECORD, source.not_records);

    let mut t = Text::new();
    t.line(format!(
        "Imported {} new event(s) and {} rule text(s); {} already known, {} not placed (they name a charter or proposal this node does not hold), {} refused.",
        summary.stored, summary.bundles, summary.duplicate, summary.deferred, summary.rejected
    ));
    for (code, n) in &summary.rejection_codes {
        t.line(format!("  refused ({code}): {n}"));
    }
    let installer = governance::user_installer()?;
    let mut installed = Vec::new();
    let mut removed = Vec::new();
    let mut not_removed = Vec::new();
    let mut kept_edited = Vec::new();
    let mut held = Vec::new();
    let mut charters = Vec::new();
    for circle in node.store.circles()? {
        let settled = governance::settle(node, &circle, &installer, &[])?;
        if let Some(seq) = settled.charter_notarized {
            t.line(format!(
                "  {}: an amendment passed; issued charter {seq}. Export again so the others receive it.",
                safe(&circle.name)
            ));
            charters.push(seq);
        }
        if !settled.results_published.is_empty() {
            t.line(format!(
                "  {}: {} proposal(s) passed; published the result(s).",
                safe(&circle.name),
                settled.results_published.len()
            ));
        }
        for skill in &settled.applied.installed {
            t.line(format!(
                "  {}: installed rule {skill} for your agent",
                safe(&circle.name)
            ));
        }
        for skill in &settled.applied.removed {
            t.line(format!("  {}: removed rule {skill}", safe(&circle.name)));
        }
        for skill in &settled.applied.not_removed {
            t.line(format!(
                "  {}: {}",
                safe(&circle.name),
                governance::not_removed_line(skill)
            ));
        }
        for kept in &settled.applied.kept_edited {
            t.line(format!("  {}: {}", safe(&circle.name), kept.line()));
            kept_edited.push(kept.name.clone());
        }
        for kept in &settled.applied.kept_for {
            t.line(format!("  {}: {}", safe(&circle.name), kept.line()));
        }
        for waiting in &settled.applied.asking {
            t.line(format!("  {}: {}", safe(&circle.name), waiting.line()));
        }
        for skill in &settled.applied.conflicts {
            t.line(format!(
                "  {}: rule {skill} was not installed: a skill of that name you manage yourself is in the way",
                safe(&circle.name)
            ));
        }
        for rule in &settled.applied.held {
            t.line(format!(
                "  {}: {}",
                safe(&circle.name),
                rule.line(&circle.name)
            ));
            held.push(rule.json());
        }
        installed.extend(settled.applied.installed);
        removed.extend(settled.applied.removed);
        not_removed.extend(settled.applied.not_removed);
    }
    if source.ignored > 0 {
        t.line(format!(
            "  {} entr{} in the directory {} not record files and {} left alone.",
            source.ignored,
            if source.ignored == 1 { "y" } else { "ies" },
            if source.ignored == 1 { "is" } else { "are" },
            if source.ignored == 1 { "was" } else { "were" },
        ));
    }
    if source.not_read > 0 {
        // Said loudly: records that were not read are records this node may lack.
        t.line(format!(
            "  {} record file(s) in the directory were NOT READ: it holds more than {} MiB \
             of records, or of files with a record's name that are none. What was read \
             before them was imported. Take out the files that are not records and run \
             this again.",
            source.not_read,
            carrier::MAX_SOURCE_BYTES / (1024 * 1024),
        ));
    }
    if summary.stored > 0 {
        t.line("See what needs your vote: `peerharness proposal list`.");
    }
    Ok((
        json!({
            "stored": summary.stored,
            "duplicate": summary.duplicate,
            "deferred": summary.deferred,
            "rejected": summary.rejected,
            "bundles": summary.bundles,
            "ignored": source.ignored,
            "not_read": source.not_read,
            "rejection_codes": summary
                .rejection_codes
                .iter()
                .map(|(code, n)| json!({ "code": code, "count": n }))
                .collect::<Vec<_>>(),
            "installed": installed,
            "removed": removed,
            "not_removed": not_removed,
            "kept_edited": kept_edited,
            "held": held,
            "charters_issued": charters,
        }),
        t,
    ))
}

/// `events sync <dir>`: import the directory, then write what it lacks.
fn sync(ctx: &Ctx, dir: &Path, circle: Option<&str>) -> Result<Report> {
    human_only("writing a circle's records out")?;
    let node = ctx.open_node()?;
    let circle = find_circle(&node, circle)?;
    let dir = crate::home::absolute(dir)?;
    let (mut json, mut t) = if dir.is_dir() {
        import(&node, &dir)?
    } else {
        (json!({}), Text::new())
    };
    // After the import: a charter this node just issued, or a result it just published,
    // goes out in the same run.
    let bundles = crate::library::bundle_store(&node.home);
    let lines = governance::export_circle(&node.store, &bundles, &circle.circle_id)?;
    let written = carrier::write_dir(&dir, &lines)?;
    t.line(format!(
        "Wrote {written} new file(s) for {} to {} ({} record(s) in all).",
        safe(&circle.name),
        dir.display(),
        lines.len()
    ));
    if written > 0 {
        t.line("Share them: commit and push that directory (or copy it to the others).");
        t.line("Anyone who can read it can read the circle's roll, proposals and ballots.");
    }
    json["dir"] = Value::String(dir.display().to_string());
    json["records"] = json!(lines.len());
    json["written"] = json!(written);
    Ok(Report::new(json, t.finish()))
}
