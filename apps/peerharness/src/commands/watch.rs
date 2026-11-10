//! `watch claude --install | --remove | --status`: opt-in Claude Code hooks, with
//! backups, idempotence and a previewed confirmation for every change.
//!
//! `--install` also installs the small skill that asks the agent to report corrections
//! with `peerharness note --from-agent` (see `crate::agent_notes`), unless
//! `--no-agent-notes` is given. `--remove` removes both.

use anyhow::Result;
use ph_observer::{HookEvent, HookStatus};
use ph_skills::{InstallOptions, InstallState, UninstallOptions};
use serde_json::json;

use super::{claude_settings_path, hook_command, Ctx};
use crate::agent_notes;
use crate::cli::WatchClaudeArgs;
use crate::consent::confirm;
use crate::output::{Report, Text};

/// Where the reporting skill stands in the agent's skills directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Notes {
    /// Not there.
    Absent,
    /// Exactly the skill this binary and home would install.
    Current,
    /// An older or different version that PeerHarness installed and nobody edited.
    Outdated,
    /// PeerHarness installed it and the owner edited it since.
    Edited,
    /// A skill of that name that PeerHarness does not manage.
    Foreign,
}

impl Notes {
    const fn as_str(self) -> &'static str {
        match self {
            Notes::Absent => "not installed",
            Notes::Current => "installed",
            Notes::Outdated => "installed (an older version)",
            Notes::Edited => "installed, edited by hand",
            Notes::Foreign => "a skill of that name you manage yourself is in the way",
        }
    }
}

fn notes_state(installer: &ph_skills::Installer, expected: &ph_skills::Bundle) -> Notes {
    match installer.status(agent_notes::SKILL_NAME) {
        Ok(InstallState::NotInstalled) | Err(_) => Notes::Absent,
        Ok(InstallState::Unmanaged) => Notes::Foreign,
        Ok(InstallState::Managed { modified: true, .. }) => Notes::Edited,
        Ok(InstallState::Managed { digest, .. }) if digest == expected.digest() => Notes::Current,
        Ok(InstallState::Managed { .. }) => Notes::Outdated,
    }
}

pub fn claude(ctx: &Ctx, a: WatchClaudeArgs) -> Result<Report> {
    let settings = claude_settings_path(a.settings.as_deref())?;
    let cmd = hook_command(&ctx.home)?;
    let status = ph_observer::hooks_status(&settings).map_err(|e| {
        anyhow::anyhow!("{e}").context(format!("cannot read {}", settings.display()))
    })?;
    let backups = ctx.home.backups_dir();
    let installer = crate::governance::user_installer()?;
    let notes_bundle = agent_notes::bundle(&cmd.render_program())?;
    let notes = notes_state(&installer, &notes_bundle);

    if a.install {
        if !ctx.home.is_initialized() {
            return Err(crate::error::usage(
                "this home is not initialized: run `peerharness init` before installing hooks",
            ));
        }
        let want_hooks = !status.is_installed_for(&cmd);
        // Never replace a skill the owner wrote or edited.
        let want_notes = !a.no_agent_notes && matches!(notes, Notes::Absent | Notes::Outdated);
        if !want_hooks && !want_notes {
            return Ok(done(
                &settings,
                "install",
                false,
                None,
                &status,
                notes,
                "Already installed; nothing changed.",
            ));
        }
        let mut preview = Text::new();
        if want_hooks {
            preview.line(format!("This will edit {}", settings.display()));
            preview.line(
                "and add these Claude Code hooks (existing hooks are kept; a backup is made first):",
            );
            for e in HookEvent::INSTALLED {
                preview.line(format!("  {:<17} {}", e.event_name(), cmd.render(e)));
            }
            preview.line(
                "The hook stores redacted observations locally only. Nothing is sent anywhere.",
            );
        }
        if want_notes {
            let dir = installer
                .skill_dir(agent_notes::SKILL_NAME)
                .map_err(|e| anyhow::anyhow!("cannot locate the skills directory: {e}"))?;
            preview.line(format!(
                "This will install the skill {} at {}",
                agent_notes::SKILL_NAME,
                dir.display()
            ));
            preview.line(
                "It asks your agent to write down a rule when you correct it. The agent can only \
                 add a note to your inbox; it cannot approve, share or install anything. \
                 Skip it with --no-agent-notes. Its exact text:",
            );
            preview.line("");
            preview.line(notes_bundle.skill_md().trim_end());
            preview.line("");
        }
        confirm(
            &ctx.out,
            &preview.finish(),
            a.yes,
            "installing Claude Code hooks",
        )?;
        let mut changed = false;
        let mut backup = None;
        if want_hooks {
            let r = ph_observer::install_hooks(&settings, &cmd, &backups).map_err(|e| {
                anyhow::anyhow!("{e}").context(format!("cannot update {}", settings.display()))
            })?;
            changed |= r.changed;
            backup = r.backup_path;
        }
        if want_notes {
            installer
                .install(&notes_bundle, InstallOptions::default())
                .map_err(|e| anyhow::anyhow!("cannot install the reporting skill: {e}"))?;
            changed = true;
        }
        let st = ph_observer::hooks_status(&settings).unwrap_or_default();
        return Ok(done(
            &settings,
            "install",
            changed,
            backup.as_deref(),
            &st,
            notes_state(&installer, &notes_bundle),
            "Installed.",
        ));
    }

    if a.remove {
        let ours = status
            .entries
            .iter()
            .filter(|h| h.home.as_deref() == cmd.home())
            .count();
        // An edited copy is the owner's now: it is left in place and they are told.
        let remove_notes = matches!(notes, Notes::Current | Notes::Outdated);
        if ours == 0 && !remove_notes {
            return Ok(done(
                &settings,
                "remove",
                false,
                None,
                &status,
                notes,
                "No PeerHarness hooks for this home; nothing changed.",
            ));
        }
        let mut preview = Text::new();
        if ours > 0 {
            preview.line(format!(
                "This will remove {ours} PeerHarness hook entr{} for this home from {} (a backup is made first; other hooks are kept).",
                if ours == 1 { "y" } else { "ies" },
                settings.display()
            ));
        }
        if remove_notes {
            preview.line(format!(
                "This will remove the skill {} from your agent's skills.",
                agent_notes::SKILL_NAME
            ));
        }
        confirm(
            &ctx.out,
            &preview.finish(),
            a.yes,
            "removing Claude Code hooks",
        )?;
        let mut changed = false;
        let mut backup = None;
        let mut removed_entries = 0;
        if ours > 0 {
            let r = ph_observer::remove_hooks_for(&settings, &cmd, &backups).map_err(|e| {
                anyhow::anyhow!("{e}").context(format!("cannot update {}", settings.display()))
            })?;
            changed |= r.changed;
            backup = r.backup_path;
            removed_entries = r.removed_entries;
        }
        if remove_notes {
            installer
                .uninstall(agent_notes::SKILL_NAME, UninstallOptions::default())
                .map_err(|e| anyhow::anyhow!("cannot remove the reporting skill: {e}"))?;
            changed = true;
        }
        let st = ph_observer::hooks_status(&settings).unwrap_or_default();
        return Ok(done(
            &settings,
            "remove",
            changed,
            backup.as_deref(),
            &st,
            notes_state(&installer, &notes_bundle),
            &format!(
                "Removed {removed_entries} hook entr{}{}.",
                if removed_entries == 1 { "y" } else { "ies" },
                if remove_notes {
                    " and the reporting skill"
                } else {
                    ""
                }
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
        "agent_notes": notes.as_str(),
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
    t.kv("reporting skill", notes.as_str());
    Ok(Report::new(json, t.finish()))
}

fn done(
    settings: &std::path::Path,
    action: &str,
    changed: bool,
    backup: Option<&std::path::Path>,
    st: &HookStatus,
    notes: Notes,
    headline: &str,
) -> Report {
    let json = json!({
        "action": action,
        "settings": settings,
        "changed": changed,
        "backup": backup,
        "installed_events": st.installed_events.iter().map(|e| e.event_name()).collect::<Vec<_>>(),
        "foreign_hooks": st.foreign_hook_count,
        "agent_notes": notes.as_str(),
    });
    let mut t = Text::new();
    t.line(headline);
    t.kv("settings", settings.display());
    t.kv("reporting skill", notes.as_str());
    if notes == Notes::Edited {
        t.line("  You edited the reporting skill, so it was left as it is.");
    }
    if let Some(b) = backup {
        t.kv("backup", b.display());
    }
    Report::new(json, t.finish())
}
