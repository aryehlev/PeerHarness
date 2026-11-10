//! `watch claude --install | --remove | --status`: opt-in Claude Code hooks, with
//! backups, idempotence and a previewed confirmation for every change.

use anyhow::Result;
use ph_observer::{HookEvent, HookStatus};
use serde_json::json;

use super::{claude_settings_path, hook_command, Ctx};
use crate::cli::WatchClaudeArgs;
use crate::consent::confirm;
use crate::output::{Report, Text};

pub fn claude(ctx: &Ctx, a: WatchClaudeArgs) -> Result<Report> {
    let settings = claude_settings_path(a.settings.as_deref())?;
    let cmd = hook_command(&ctx.home)?;
    let status = ph_observer::hooks_status(&settings).map_err(|e| {
        anyhow::anyhow!("{e}").context(format!("cannot read {}", settings.display()))
    })?;
    let backups = ctx.home.backups_dir();

    if a.install {
        if !ctx.home.is_initialized() {
            return Err(crate::error::usage(
                "this home is not initialized: run `peerharness init` before installing hooks",
            ));
        }
        if status.is_installed_for(&cmd) {
            return Ok(done(
                &settings,
                "install",
                false,
                None,
                &status,
                "Hooks are already installed; nothing changed.",
            ));
        }
        let mut preview = Text::new();
        preview.line(format!("This will edit {}", settings.display()));
        preview.line(
            "and add these Claude Code hooks (existing hooks are kept; a backup is made first):",
        );
        for e in HookEvent::INSTALLED {
            preview.line(format!("  {:<17} {}", e.event_name(), cmd.render(e)));
        }
        preview
            .line("The hook stores redacted observations locally only. Nothing is sent anywhere.");
        confirm(
            &ctx.out,
            &preview.finish(),
            a.yes,
            "installing Claude Code hooks",
        )?;
        let r = ph_observer::install_hooks(&settings, &cmd, &backups).map_err(|e| {
            anyhow::anyhow!("{e}").context(format!("cannot update {}", settings.display()))
        })?;
        let st = ph_observer::hooks_status(&settings).unwrap_or_default();
        return Ok(done(
            &settings,
            "install",
            r.changed,
            r.backup_path.as_deref(),
            &st,
            "Installed the PeerHarness hooks.",
        ));
    }

    if a.remove {
        let ours = status
            .entries
            .iter()
            .filter(|h| h.home.as_deref() == cmd.home())
            .count();
        if ours == 0 {
            return Ok(done(
                &settings,
                "remove",
                false,
                None,
                &status,
                "No PeerHarness hooks for this home; nothing changed.",
            ));
        }
        let preview = format!(
            "This will remove {ours} PeerHarness hook entr{} for this home from {} (a backup is made first; other hooks are kept).",
            if ours == 1 { "y" } else { "ies" },
            settings.display()
        );
        confirm(&ctx.out, &preview, a.yes, "removing Claude Code hooks")?;
        let r = ph_observer::remove_hooks_for(&settings, &cmd, &backups).map_err(|e| {
            anyhow::anyhow!("{e}").context(format!("cannot update {}", settings.display()))
        })?;
        let st = ph_observer::hooks_status(&settings).unwrap_or_default();
        return Ok(done(
            &settings,
            "remove",
            r.changed,
            r.backup_path.as_deref(),
            &st,
            &format!(
                "Removed {} hook entr{}.",
                r.removed_entries,
                if r.removed_entries == 1 { "y" } else { "ies" }
            ),
        ));
    }

    let installed = status.is_installed_for(&cmd);
    let json = json!({
        "settings": settings,
        "settings_exists": status.settings_exists,
        "installed": installed,
        "installed_events": status.installed_events.iter().map(|e| e.event_name()).collect::<Vec<_>>(),
        "peerharness_entries": status.entries.len(),
        "foreign_hooks": status.foreign_hook_count,
    });
    let mut t = Text::new();
    t.kv("settings", settings.display());
    t.kv(
        "installed",
        if installed {
            "yes (this binary and home)"
        } else {
            "no"
        },
    );
    t.kv("PeerHarness entries", status.entries.len());
    t.kv("other hooks", status.foreign_hook_count);
    Ok(Report::new(json, t.finish()))
}

fn done(
    settings: &std::path::Path,
    action: &str,
    changed: bool,
    backup: Option<&std::path::Path>,
    st: &HookStatus,
    headline: &str,
) -> Report {
    let json = json!({
        "action": action,
        "settings": settings,
        "changed": changed,
        "backup": backup,
        "installed_events": st.installed_events.iter().map(|e| e.event_name()).collect::<Vec<_>>(),
        "foreign_hooks": st.foreign_hook_count,
    });
    let mut t = Text::new();
    t.line(headline);
    t.kv("settings", settings.display());
    if let Some(b) = backup {
        t.kv("backup", b.display());
    }
    Report::new(json, t.finish())
}
