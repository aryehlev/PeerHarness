//! `peerharness export --local`: writes everything this node owns as one JSON document.
//!
//! The export contains local observations and candidates, which are private. It goes to
//! stdout, or to a file created with mode 0600. Private keys are never part of it: the
//! database holds keystore references only.

use anyhow::{Context, Result};
use serde_json::json;

use crate::cli::ExportArgs;
use crate::commands::Ctx;
use crate::error::usage;
use crate::output::Report;

pub fn run(ctx: &Ctx, args: ExportArgs) -> Result<Report> {
    if !args.local {
        return Err(usage(
            "pass --local: the only export is this node's own local data",
        ));
    }
    let node = ctx.open_node()?;
    let data = node
        .store
        .export_owned_json()
        .context("cannot export the database")?;
    match args.out {
        Some(path) => {
            let path = crate::home::absolute(&path)?;
            let text = serde_json::to_string_pretty(&data)?;
            crate::home::write_private_file(&path, text.as_bytes())?;
            Ok(Report::new(
                json!({ "written": path.display().to_string(), "bytes": text.len() }),
                format!(
                    "Wrote this node's local data to {} (mode 0600).\n\
                     It contains your local observations and candidates. Keep it private.",
                    path.display()
                ),
            ))
        }
        None => {
            // On stdout the export itself is the report, in both output modes.
            let text = serde_json::to_string_pretty(&data)?;
            Ok(Report::new(data, text))
        }
    }
}
