//! Copies of the managed skills for the other coding agents the owner connected
//! (ADR-050).
//!
//! The rules are installed in Claude Code's skills directory, and in a project's
//! `.claude/skills` for a scope the owner placed there (`circle place`), exactly as
//! before: that is where every decision about installing, holding and removing a rule
//! is taken. After each command, and after each settle in the daemon, the directories
//! of the connected agents are made to hold the same managed skills
//! (`ph_skills::mirror`): a copy follows what PeerHarness manages there, the reporting
//! skill included, and nothing else. A skill in an agent's directory that PeerHarness
//! did not put there, and a copy someone edited, are never touched.
//!
//! Copies decide nothing and need no confirmation of their own: what they copy was
//! installed after the confirmation, vote or standing choice it needed, and the owner
//! connected the agent in their own terminal. An agent that is not connected gets
//! nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ph_skills::{BlockedWhy, InstallState, Installer, MirrorReport};
use ph_store::Store;

use crate::agents::Agent;
use crate::commands::Ctx;
use crate::config::Config;

/// One directory that holds copies, the directory it copies, and the agents that read it.
pub struct CopyDir {
    pub agents: Vec<Agent>,
    /// The project directory, for a project's copies.
    pub project: Option<PathBuf>,
    pub source: Installer,
    pub copy: Installer,
}

/// The connected agents this build can find files for.
fn connected(config: &Config) -> Vec<Agent> {
    config
        .agents
        .connected
        .iter()
        .copied()
        .filter(|a| a.paths().is_some())
        .collect()
}

/// The user's directories that hold copies for `agents`, each with the agents that read
/// it. An agent that reads Claude Code's directory itself has none.
pub fn user_dirs(agents: &[Agent]) -> Vec<(PathBuf, Vec<Agent>)> {
    let mut out: Vec<(PathBuf, Vec<Agent>)> = Vec::new();
    for a in agents {
        let Some(dir) = a.paths().and_then(|p| p.skills) else {
            continue;
        };
        match out.iter_mut().find(|(d, _)| *d == dir) {
            Some((_, list)) => list.push(*a),
            None => out.push((dir, vec![*a])),
        }
    }
    out
}

/// The project directories where rules are installed on this machine: the places the
/// owner chose for a scope, and projects a skill was installed into.
fn project_dirs(store: &Store) -> Vec<PathBuf> {
    let mut dirs = BTreeSet::new();
    for c in store.circles().unwrap_or_default() {
        for (_, dir) in store.rule_places(&c.circle_id).unwrap_or_default() {
            dirs.insert(PathBuf::from(dir));
        }
    }
    for i in store.active_installations().unwrap_or_default() {
        if i.install_scope != "project" {
            continue;
        }
        // `<project>/.claude/skills/<name>`.
        let path = Path::new(&i.path);
        let skills = path.parent();
        let claude = skills.and_then(Path::parent);
        if skills.and_then(Path::file_name) == Some("skills".as_ref())
            && claude.and_then(Path::file_name) == Some(".claude".as_ref())
        {
            if let Some(project) = claude.and_then(Path::parent) {
                dirs.insert(project.to_path_buf());
            }
        }
    }
    dirs.into_iter().filter(|d| d.is_absolute()).collect()
}

/// Every directory that holds copies on this node.
pub fn dirs(config: &Config, store: Option<&Store>) -> Vec<CopyDir> {
    let agents = connected(config);
    if agents.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Ok(user) = crate::governance::user_installer() {
        for (dir, list) in user_dirs(&agents) {
            if dir == user.target_root() {
                continue;
            }
            out.push(CopyDir {
                agents: list,
                project: None,
                source: user.clone(),
                copy: Installer::new(dir),
            });
        }
    }
    let in_projects: Vec<Agent> = agents
        .iter()
        .copied()
        .filter(|a| a.project_skills().is_some())
        .collect();
    if let (Some(store), false) = (store, in_projects.is_empty()) {
        for project in project_dirs(store) {
            let mut by_rel: Vec<(&str, Vec<Agent>)> = Vec::new();
            for a in &in_projects {
                let rel = a.project_skills().unwrap_or(".agents/skills");
                match by_rel.iter_mut().find(|(r, _)| *r == rel) {
                    Some((_, l)) => l.push(*a),
                    None => by_rel.push((rel, vec![*a])),
                }
            }
            for (rel, list) in by_rel {
                out.push(CopyDir {
                    agents: list,
                    project: Some(project.clone()),
                    source: Installer::new(project.join(".claude").join("skills"))
                        .confine_to(&project),
                    copy: Installer::new(project.join(rel)).confine_to(&project),
                });
            }
        }
    }
    out
}

/// What one pass did in one directory.
pub struct Synced {
    pub agents: Vec<Agent>,
    pub report: MirrorReport,
}

/// Brings every directory of copies in line with its source. A directory that cannot
/// be listed is skipped: the next pass tries again.
pub fn sync(config: &Config, store: Option<&Store>) -> Vec<Synced> {
    dirs(config, store)
        .into_iter()
        .filter_map(|d| {
            ph_skills::mirror(&d.source, &d.copy)
                .map_err(|e| tracing::debug!(error = %e, "copies not updated"))
                .ok()
                .map(|report| Synced {
                    agents: d.agents,
                    report,
                })
        })
        .collect()
}

/// The lines that name what could not follow, one per skill.
pub fn blocked_lines(synced: &[Synced]) -> Vec<String> {
    let mut lines = Vec::new();
    for s in synced {
        let who = crate::agents::names(&s.agents);
        let dir = s.report.root.display();
        for b in &s.report.blocked {
            lines.push(match b.why {
                BlockedWhy::InTheWay => format!(
                    "{who}: {} was not copied to {dir}: a skill of that name that PeerHarness \
                     did not put there is in the way, and it is left as it is.",
                    b.name
                ),
                BlockedWhy::Edited => format!(
                    "{who}: the copy of {} in {dir} was edited by hand, so it is no longer \
                     kept the same as the rule: it is left as it is. Delete that folder to \
                     have it copied again.",
                    b.name
                ),
                BlockedWhy::Failed => format!(
                    "{who}: {} could not be copied to {dir} or removed from it; it is tried \
                     again after the next command.",
                    b.name
                ),
            });
        }
    }
    lines
}

/// What the user's directory held before a command, when an agent is connected: the
/// pass after the command names what could not follow only when the command changed it.
pub struct Before(Option<Vec<(String, InstallState)>>);

pub fn before(ctx: &Ctx) -> Before {
    if !ctx.home.is_initialized() {
        return Before(None);
    }
    let Ok(config) = Config::load(&ctx.home) else {
        return Before(None);
    };
    if connected(&config).is_empty() {
        return Before(None);
    }
    Before(
        crate::governance::user_installer()
            .ok()
            .and_then(|i| i.list().ok()),
    )
}

/// The pass after a command: copies follow, and what could not follow is named on
/// standard error when the command changed something. It never fails the command.
pub fn follow(ctx: &Ctx, before: Before) {
    let Some(was) = before.0 else {
        return;
    };
    let Ok(node) = ctx.open_node() else {
        return;
    };
    let synced = sync(&node.config, Some(&node.store));
    let now = crate::governance::user_installer()
        .ok()
        .and_then(|i| i.list().ok());
    let changed = now.as_ref() != Some(&was) || synced.iter().any(|s| s.report.changed());
    if changed {
        for line in blocked_lines(&synced) {
            ctx.out.warn(&line);
        }
    }
}
