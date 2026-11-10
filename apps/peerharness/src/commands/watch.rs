//! `watch claude --install | --remove | --status`: opt-in Claude Code hooks, with
//! backups, idempotence and a previewed confirmation for every change.
//!
//! `--install` also installs the small skill that asks the agent to report corrections
//! with `peerharness note --from-agent` (see `crate::agent_notes`), unless
//! `--no-agent-notes` is given. `--remove` removes both.
//!
//! `--install --dialogs` is where the owner allows confirmation windows (ADR-033 for the
//! steps about rules, ADR-037 for the steps about who is in a circle), and `--install
//! --no-dialogs` or `--remove` is where they take that back. Like every change here it
//! is previewed and confirmed in the owner's own terminal: an agent's session cannot
//! turn windows on, with or without a window. Windows that were turned on before
//! ADR-037 cover the steps about rules only, until the owner runs `--install --dialogs`
//! again and confirms the longer list.

use anyhow::Result;
use ph_observer::{HookEvent, HookStatus};
use ph_skills::{InstallOptions, InstallState, UninstallOptions};
use serde_json::json;

use super::{claude_settings_path, hook_command, Ctx};
use crate::agent_notes;
use crate::cli::WatchClaudeArgs;
use crate::config::{Asked, Config};
use crate::consent::confirm;
use crate::output::{Report, Text};
use crate::window::Window;

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
    // The owner's setting, and what this command would make it.
    let mut config = if ctx.home.is_initialized() {
        Some(Config::load(&ctx.home)?)
    } else {
        None
    };
    let asked_now = config.as_ref().map_or(Asked::Nothing, |c| c.agent.asked());
    let asked_after = match (a.install, a.remove) {
        (true, _) if a.no_windows => Asked::Nothing,
        // `--windows` always means every step this build can ask in a window.
        (true, _) if a.windows => Asked::All,
        (false, true) => Asked::Nothing,
        _ => asked_now,
    };
    let windows_now = asked_now != Asked::Nothing;
    // The reporting skill says what the agent may start, so it follows the setting.
    let notes_bundle = agent_notes::bundle(&cmd.render_program(), asked_after)?;
    let notes = notes_state(&installer, &notes_bundle);

    if a.install {
        let Some(config) = config.as_mut() else {
            return Err(crate::error::usage(
                "this home is not initialized: run `peerharness init` before installing hooks",
            ));
        };
        if a.windows && Window::find().is_none() {
            return Err(crate::error::usage(
                "confirmation windows need macOS in this build: nothing was changed",
            ));
        }
        let want_windows = asked_after != asked_now;
        let want_hooks = !status.is_installed_for(&cmd);
        // Never replace a skill the owner wrote or edited.
        let want_notes = !a.no_agent_notes && matches!(notes, Notes::Absent | Notes::Outdated);
        if !want_hooks && !want_notes && !want_windows {
            return Ok(done(
                &settings,
                "install",
                false,
                None,
                &status,
                Setup {
                    notes,
                    asked: asked_now,
                },
                "Already installed; nothing changed.",
            ));
        }
        let mut preview = Text::new();
        if want_windows && asked_after != Asked::Nothing {
            preview.line(match asked_now {
                Asked::Rules => {
                    "Your agent may already put three decisions about rules in front of you. \
                     This adds four: keeping a rule for yourself, and three about who is in a \
                     circle. All seven:"
                }
                Asked::RulesAndCircle => {
                    "Your agent may already put six decisions in front of you. This adds one: \
                     keeping a rule for yourself. All seven:"
                }
                _ => "This lets your agent put seven decisions in front of you while you work with it:",
            });
            preview.line("  keeping a rule it noted, for your own agent (`keep`),");
            preview.line("  proposing a rule to a circle,");
            preview.line("  your ballot on a proposed rule,");
            preview.line("  installing a rule that passed and waits for you,");
            preview.line("  proposing to admit someone to a circle you are in (`circle invite`),");
            preview.line("  your ballot on admitting someone,");
            preview.line("  joining a circle that admitted you (`circle join`).");
            preview.line(
                "Each one opens a window on your screen that shows exactly what would be shared, \
                 signed, installed or joined. Nothing happens unless you click Proceed in that \
                 window. Your agent cannot answer it and --yes does not skip it. Every other \
                 decision still needs your own terminal.",
            );
            preview.line(
                "When you ask it to, your agent may also found a circle, exchange with the \
                 members of your circles and keep this node reachable, over the public network \
                 too (`--internet`). That network's servers then see this device's public key \
                 and IP address, and never a circle, a roll or anything said in one.",
            );
            preview.line("Turn it off with `peerharness setup --no-dialogs`.");
            preview.line("");
        }
        if want_windows && asked_after == Asked::Nothing {
            preview.line(
                "This turns confirmation windows off: every decision needs your own terminal again.",
            );
            preview.line("");
        }
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
            preview.line(if asked_after != Asked::Nothing {
                "It asks your agent to write down a rule when you correct it, and tells it which \
                 steps it may start when you ask. The agent cannot approve, share, install or \
                 join anything: that is your click in the window. \
                 Skip it with --no-agent-notes. Its exact text:"
            } else {
                "It asks your agent to write down a rule when you correct it. The agent can only \
                 add a note to your inbox; it cannot approve, share or install anything. \
                 Skip it with --no-agent-notes. Its exact text:"
            });
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
        if want_windows {
            // The setting first: if a later step fails, windows that were turned off
            // are off.
            config.agent.set_asked(asked_after);
            config.save(&ctx.home)?;
            changed = true;
        }
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
            Setup {
                notes: notes_state(&installer, &notes_bundle),
                asked: asked_after,
            },
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
        if ours == 0 && !remove_notes && !windows_now {
            return Ok(done(
                &settings,
                "remove",
                false,
                None,
                &status,
                Setup {
                    notes,
                    asked: Asked::Nothing,
                },
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
        if windows_now {
            preview.line(
                "This turns confirmation windows off: every decision needs your own terminal again.",
            );
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
        if let Some(config) = config.as_mut().filter(|_| windows_now) {
            config.agent.set_asked(Asked::Nothing);
            config.save(&ctx.home)?;
            changed = true;
        }
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
            Setup {
                notes: notes_state(&installer, &notes_bundle),
                asked: Asked::Nothing,
            },
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
        "windows": windows_now,
        "circle_windows": asked_now >= Asked::RulesAndCircle,
        "own_windows": asked_now >= Asked::All,
        "windows_available": Window::find().is_some(),
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
    t.kv("windows", windows_label(asked_now));
    Ok(Report::new(json, t.finish()))
}

fn windows_label(asked: Asked) -> &'static str {
    match (asked, Window::find().is_some()) {
        (Asked::Nothing, _) => "off (every decision needs your own terminal)",
        (_, false) => "on, but this machine has no window PeerHarness can show",
        (Asked::Rules, true) => {
            "on for rules only (run `peerharness setup` again to add inviting and joining)"
        }
        (Asked::RulesAndCircle, true) => {
            "on, but not for keeping a rule for yourself (run `peerharness setup` again to \
             add it)"
        }
        (Asked::All, true) => "on (your agent may put seven decisions in front of you)",
    }
}

/// What the agent has been given after a command: the reporting skill and the windows.
struct Setup {
    notes: Notes,
    asked: Asked,
}

fn done(
    settings: &std::path::Path,
    action: &str,
    changed: bool,
    backup: Option<&std::path::Path>,
    st: &HookStatus,
    setup: Setup,
    headline: &str,
) -> Report {
    let Setup { notes, asked } = setup;
    let json = json!({
        "action": action,
        "settings": settings,
        "changed": changed,
        "backup": backup,
        "installed_events": st.installed_events.iter().map(|e| e.event_name()).collect::<Vec<_>>(),
        "foreign_hooks": st.foreign_hook_count,
        "agent_notes": notes.as_str(),
        "windows": asked != Asked::Nothing,
        "circle_windows": asked >= Asked::RulesAndCircle,
        "own_windows": asked >= Asked::All,
    });
    let mut t = Text::new();
    t.line(headline);
    t.kv("settings", settings.display());
    t.kv("reporting skill", notes.as_str());
    t.kv("windows", windows_label(asked));
    if notes == Notes::Edited {
        t.line("  You edited the reporting skill, so it was left as it is.");
    }
    if action == "install" && asked != Asked::Nothing {
        t.line("`peerharness setup` also gives your agent these steps as tools.");
    }
    if let Some(b) = backup {
        t.kv("backup", b.display());
    }
    Report::new(json, t.finish())
}
