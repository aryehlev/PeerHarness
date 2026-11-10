//! `peerharness events`: exchanging a circle's signed events as a file.
//!
//! Every event is signed and names the charter it belongs to, so the carrier does not
//! need to be trusted: email, a shared folder, a git repository or a USB stick all work.
//! The importing node verifies every line through the same path a network peer's events
//! will take (`governance::ingest`).

use anyhow::Result;
use serde_json::json;

use crate::cli::EventsCommand;
use crate::commands::circle::find_circle;
use crate::commands::Ctx;
use crate::error::usage;
use crate::governance;
use crate::output::{safe, Report, Text};

pub fn run(ctx: &Ctx, command: EventsCommand) -> Result<Report> {
    match command {
        EventsCommand::Export { circle, out } => export(ctx, &circle, out.as_deref()),
        EventsCommand::Import { file } => import(ctx, &file),
    }
}

fn export(ctx: &Ctx, circle: &str, out: Option<&std::path::Path>) -> Result<Report> {
    let node = ctx.open_node()?;
    let circle = find_circle(&node, Some(circle))?;
    let bundles = crate::library::bundle_store(&node.home);
    let lines = governance::export_circle(&node.store, &bundles, &circle.circle_id)?;
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

fn import(ctx: &Ctx, file: &std::path::Path) -> Result<Report> {
    let node = ctx.open_node()?;
    let bytes = crate::home::read_bounded_file(file, 64 * 1024 * 1024)?;
    let text = String::from_utf8(bytes).map_err(|_| usage("that file is not UTF-8 text"))?;
    let bundles = crate::library::bundle_store(&node.home);
    let summary = governance::import_lines(&node.store, &bundles, text.lines(), node.now())?;

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
    let mut charters = Vec::new();
    for circle in node.store.circles()? {
        let settled = governance::settle(&node, &circle, &installer, &[])?;
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
        for (skill, why) in &settled.applied.asking {
            t.line(format!(
                "  {}: rule {skill} is in force and waits for your confirmation ({why})",
                safe(&circle.name)
            ));
        }
        for skill in &settled.applied.conflicts {
            t.line(format!(
                "  {}: rule {skill} was not installed: a skill of that name you manage yourself is in the way",
                safe(&circle.name)
            ));
        }
        installed.extend(settled.applied.installed);
        removed.extend(settled.applied.removed);
    }
    if summary.stored > 0 {
        t.line("See what needs your vote: `peerharness proposal list`.");
    }
    Ok(Report::new(
        json!({
            "stored": summary.stored,
            "duplicate": summary.duplicate,
            "deferred": summary.deferred,
            "rejected": summary.rejected,
            "bundles": summary.bundles,
            "installed": installed,
            "removed": removed,
            "charters_issued": charters,
        }),
        t.finish(),
    ))
}
