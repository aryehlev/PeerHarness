//! `peerharness skills`: the local skill library and the owner's own installations.
//!
//! A skill gets into the library when the owner approves a candidate (`review
//! --approve`) or when a rule passes a circle's vote. Installing from here is the owner's
//! personal choice: it is previewed, confirmed, atomic and reversible, and it is
//! independent of any circle (a later repeal does not remove a skill installed here).

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use ph_skills::{
    Bundle, InstallError, InstallOptions, InstallState, Installer, SkillScope, UninstallOptions,
    SKILL_FILE_NAME,
};
use ph_store::{InstallationRow, SkillOrigin, SkillRow};
use serde_json::{json, Value};

use super::Ctx;
use crate::cli::{SkillsCommand, SkillsInstallArgs, SkillsRollbackArgs, SkillsUninstallArgs};
use crate::consent::{confirm, human_only, require_accept_risk};
use crate::error::{refused, usage};
use crate::installs::{self, AGENT_CLAUDE};
use crate::node::Node;
use crate::output::{safe, short_id, Report, Text};

pub fn run(ctx: &Ctx, command: SkillsCommand) -> Result<Report> {
    let node = ctx.open_node()?;
    match command {
        SkillsCommand::List => list(&node),
        SkillsCommand::Show { id } => show(&node, &id),
        SkillsCommand::Install(a) => install(ctx, &node, &a),
        SkillsCommand::Uninstall(a) => uninstall(&node, &a),
        SkillsCommand::Rollback(a) => rollback(ctx, &node, &a),
    }
}

/// The installer for `scope`, rooted at the current directory for project scope.
fn installer_for(scope: SkillScope) -> Result<Installer> {
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    ph_skills::claude_installer(scope, &cwd)
        .map_err(|e| anyhow!("cannot locate the agent's skills directory: {e}"))
}

fn origin_text(s: &SkillRow) -> &'static str {
    match s.origin_kind {
        SkillOrigin::Local => "yours",
        SkillOrigin::Proposal => "from a circle vote",
    }
}

fn skill_json(s: &SkillRow, active: &[InstallationRow]) -> Value {
    json!({
        "id": s.id,
        "name": s.name,
        "bundle_digest": s.bundle_digest,
        "origin": s.origin_kind.as_str(),
        "origin_ref": s.origin_ref,
        "status": s.status.as_str(),
        "installed": installed_at(s, active).iter().map(|i| json!({
            "agent": i.agent,
            "scope": i.install_scope,
            "path": i.path,
        })).collect::<Vec<_>>(),
        "created_at": s.created_at,
    })
}

/// The active installations of exactly this version of the skill.
fn installed_at<'a>(s: &SkillRow, active: &'a [InstallationRow]) -> Vec<&'a InstallationRow> {
    active
        .iter()
        .filter(|i| i.skill_name == s.name && i.bundle_digest == s.bundle_digest)
        .collect()
}

fn list(node: &Node) -> Result<Report> {
    let skills = node.store.skills()?;
    let active = node.store.active_installations()?;
    let mut t = Text::new();
    if skills.is_empty() {
        t.line("No skills in your library yet.");
        t.line("Write a rule down with `peerharness note \"...\"`, then `peerharness review`.");
    } else {
        t.line(format!("Skills in your library ({}):", skills.len()));
        for s in &skills {
            let places = installed_at(s, &active);
            let state = if places.is_empty() {
                "not installed".to_owned()
            } else {
                format!(
                    "installed ({})",
                    places
                        .iter()
                        .map(|i| i.install_scope.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            t.line(format!(
                "  {:>3}  {}  {}  [{}; {state}]",
                s.id,
                s.name,
                short_id(&s.bundle_digest),
                origin_text(s)
            ));
        }
    }
    Ok(Report::new(
        json!({ "skills": skills.iter().map(|s| skill_json(s, &active)).collect::<Vec<_>>() }),
        t.finish(),
    ))
}

fn load_bundle(node: &Node, s: &SkillRow) -> Result<Bundle> {
    crate::library::bundle_store(&node.home)
        .get(&s.bundle_digest)
        .map_err(|_| anyhow!("the content of that skill is missing from this node's bundle store"))
}

fn findings_lines(t: &mut Text, bundle: &Bundle) -> bool {
    let findings = bundle.scan();
    for f in &findings {
        t.line(format!("  scanner, line {}: {}", f.line, f.explanation()));
    }
    let high = ph_skills::has_high_risk(&findings);
    if high {
        t.line("  HIGH RISK findings above. Scanning never proves a text is safe.");
    }
    high
}

fn show(node: &Node, arg: &str) -> Result<Report> {
    let s = crate::ids::resolve_skill(&node.store, arg)?;
    let bundle = load_bundle(node, &s)?;
    let active = node.store.active_installations()?;
    let mut t = Text::new();
    t.line(format!("{} (skill {})", s.name, s.id));
    t.kv("digest", s.bundle_digest);
    t.kv("origin", origin_text(&s));
    t.kv("size", format!("{} bytes", bundle.size()));
    for i in installed_at(&s, &active) {
        t.kv(
            "installed",
            format!("{} scope, {}", i.install_scope, safe(&i.path)),
        );
    }
    t.line("");
    t.line(safe(bundle.skill_md()).trim_end());
    t.line("");
    findings_lines(&mut t, &bundle);
    let history = node.store.installation_history(&s.name)?;
    let mut json = skill_json(&s, &active);
    json["skill_md"] = Value::String(bundle.skill_md().to_owned());
    json["findings"] = bundle
        .scan()
        .iter()
        .map(|f| json!({ "rule": f.rule, "line": f.line, "high": f.severity == ph_skills::Severity::High }))
        .collect();
    json["history"] = history
        .iter()
        .map(|i| {
            json!({
                "scope": i.install_scope,
                "path": i.path,
                "bundle_digest": i.bundle_digest,
                "installed_at": i.installed_at,
                "removed_at": i.removed_at,
            })
        })
        .collect();
    Ok(Report::new(json, t.finish()))
}

/// The SKILL.md currently at `dir`, when it is a regular file of a sane size.
fn installed_text(dir: &Path) -> Option<String> {
    let path = dir.join(SKILL_FILE_NAME);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let bytes =
        crate::home::read_bounded_file(&path, ph_skills::MAX_SKILL_FILE_BYTES as u64).ok()?;
    String::from_utf8(bytes).ok()
}

fn install_error(e: InstallError) -> anyhow::Error {
    match e {
        InstallError::Unmanaged => refused(
            "a skill of that name that PeerHarness does not manage is already there. It was \
             left untouched. Re-run with --force-overwrite-unmanaged to replace it (it is \
             moved to a backup first).",
        ),
        InstallError::Modified => refused(
            "the installed SKILL.md was edited by hand since PeerHarness installed it. It was \
             left untouched. Re-run with --allow-modified to replace it.",
        ),
        other => anyhow!("cannot install the skill: {other}"),
    }
}

/// How one installation was asked for.
struct Request<'a> {
    scope: SkillScope,
    opts: InstallOptions,
    yes: bool,
    accept_risk: bool,
    /// The verb for the preview: "install" or "roll back".
    what: &'a str,
}

/// Previews, confirms and performs one installation of `bundle`, then records it.
/// Returns the skill directory, whether anything changed, and a backup path if a
/// directory was moved aside.
fn install_bundle(
    ctx: &Ctx,
    node: &Node,
    bundle: &Bundle,
    req: &Request<'_>,
) -> Result<(PathBuf, bool, Option<PathBuf>)> {
    let Request {
        scope,
        opts,
        yes,
        accept_risk,
        what,
    } = *req;
    let installer = installer_for(scope)?;
    let name = bundle.name();
    let dir = installer
        .skill_dir(name)
        .map_err(|e| anyhow!("cannot locate the skill directory: {e}"))?;
    let state = installer
        .status(name)
        .map_err(|e| anyhow!("cannot inspect the skill directory: {e}"))?;
    if matches!(state, InstallState::Managed { digest, modified: false } if digest == bundle.digest())
    {
        // Already exactly this version: make sure the records agree and stop.
        let outcome = installer.install(bundle, opts).map_err(install_error)?;
        installs::record_install(&node.store, scope, bundle, &outcome, node.now())?;
        return Ok((outcome.path, false, None));
    }

    let mut t = Text::new();
    t.line(format!(
        "This will {what} the skill {name} for your agent at {}",
        dir.display()
    ));
    match (state, installed_text(&dir)) {
        (InstallState::NotInstalled, _) | (_, None) => {
            t.line("");
            t.line(safe(bundle.skill_md()).trim_end());
        }
        (st, Some(old)) => {
            t.line(match st {
                InstallState::Unmanaged => {
                    "replacing a skill PeerHarness does not manage (moved to a backup first):"
                }
                _ => "replacing the installed version:",
            });
            t.line("");
            let diff = ph_skills::unified_diff(&old, bundle.skill_md(), "installed", "new");
            if diff.is_empty() {
                t.line("(the text is identical)");
            } else {
                t.line(diff.trim_end());
            }
        }
    }
    t.line("");
    let high = findings_lines(&mut t, bundle);
    ctx.out.note(t.finish().trim_end());
    require_accept_risk(high, accept_risk)?;
    confirm(&ctx.out, "", yes, "installing the skill")?;

    let outcome = installer.install(bundle, opts).map_err(install_error)?;
    installs::record_install(&node.store, scope, bundle, &outcome, node.now())?;
    Ok((outcome.path, !outcome.unchanged, outcome.backup_path))
}

fn install(ctx: &Ctx, node: &Node, a: &SkillsInstallArgs) -> Result<Report> {
    human_only("installing a skill")?;
    let s = crate::ids::resolve_skill(&node.store, &a.id)?;
    let bundle = load_bundle(node, &s)?;
    let scope = a.scope.skill_scope();
    let opts = InstallOptions {
        force_overwrite_unmanaged: a.force_overwrite_unmanaged,
        allow_modified: a.allow_modified,
    };
    let (path, changed, backup) = install_bundle(
        ctx,
        node,
        &bundle,
        &Request {
            scope,
            opts,
            yes: a.yes,
            accept_risk: a.accept_risk,
            what: "install",
        },
    )?;
    let mut t = Text::new();
    if changed {
        t.line(format!("Installed {} at {}.", s.name, path.display()));
        t.line("Your agent reads it from its next session.");
    } else {
        t.line(format!(
            "{} is already installed at {}.",
            s.name,
            path.display()
        ));
    }
    if let Some(b) = &backup {
        t.line(format!(
            "The previous directory was moved to {}.",
            b.display()
        ));
    }
    t.line(format!(
        "Remove it with `peerharness skills uninstall {}`.",
        s.name
    ));
    Ok(Report::new(
        json!({
            "skill_name": s.name,
            "bundle_digest": s.bundle_digest,
            "scope": scope.as_str(),
            "path": path,
            "changed": changed,
            "backup": backup,
        }),
        t.finish(),
    ))
}

/// The scope to act on: the one given, or the scope of the only active installation.
fn pick_scope(
    node: &Node,
    name: &str,
    given: Option<crate::cli::ScopeArg>,
) -> Result<(SkillScope, Option<InstallationRow>)> {
    let mut rows: Vec<InstallationRow> = node
        .store
        .active_installations()?
        .into_iter()
        .filter(|i| i.skill_name == name && i.agent == AGENT_CLAUDE)
        .collect();
    if let Some(g) = given {
        let scope = g.skill_scope();
        let row = rows.into_iter().find(|i| i.install_scope == scope.as_str());
        return Ok((scope, row));
    }
    match rows.len() {
        0 => Ok((SkillScope::User, None)),
        1 => {
            let row = rows.remove(0);
            let scope = SkillScope::from_str(&row.install_scope)
                .map_err(|_| anyhow!("an installation record names an unknown scope"))?;
            Ok((scope, Some(row)))
        }
        _ => Err(usage(
            "that skill is installed in more than one scope: pass --scope user or --scope project",
        )),
    }
}

fn uninstall(node: &Node, a: &SkillsUninstallArgs) -> Result<Report> {
    let s = crate::ids::resolve_skill(&node.store, &a.id)?;
    let (scope, _) = pick_scope(node, &s.name, a.scope)?;
    let installer = installer_for(scope)?;
    let state = installer
        .status(&s.name)
        .map_err(|e| anyhow!("cannot inspect the skill directory: {e}"))?;
    let InstallState::Managed { digest, .. } = state else {
        return Err(usage(match state {
            InstallState::Unmanaged => {
                "a skill of that name is there, but PeerHarness does not manage it: it was left untouched"
            }
            _ => "that skill is not installed in this scope",
        }));
    };
    // A rule in force that the owner follows would be installed again at the next
    // import: the way to keep it off this machine is the opt-out.
    if scope == SkillScope::User {
        for circle in node.store.circles()? {
            let id = &circle.circle_id;
            let (_, rules, _) = crate::governance::rule_set(&node.store, id)?;
            let Some(rule) = rules.get(&s.name).filter(|r| r.bundle_digest() == digest) else {
                continue;
            };
            if node.store.is_rule_opted_out(id, &s.name)? {
                continue;
            }
            // Not when that rule is held because of this very skill (a copy of the
            // rule's text that the owner kept and then edited): taking it out is the
            // way out the hold names, and what follows is the rule as it passed.
            let target = crate::governance::rule_target(&node.store, id, &installer, rule.scope())?;
            if crate::governance::held(&node.store, id, &target, rule)?.is_some() {
                continue;
            }
            return Err(usage(format!(
                "{} is a rule in force in {}. To keep it off this machine, opt out: \
                 `peerharness rule opt-out {} --circle {}`",
                s.name, circle.name, s.name, circle.name
            )));
        }
    }
    let gone = installer
        .uninstall(
            &s.name,
            UninstallOptions {
                allow_modified: a.allow_modified,
            },
        )
        .map_err(|e| match e {
            InstallError::Modified => refused(
                "the installed SKILL.md was edited by hand. It was left untouched. Re-run \
                 with --allow-modified to remove it anyway.",
            ),
            other => anyhow!("cannot uninstall the skill: {other}"),
        })?;
    installs::record_uninstall(
        &node.store,
        scope,
        &s.name,
        &gone.removed_digest,
        &gone.path,
        node.now(),
    )?;
    Ok(Report::new(
        json!({
            "skill_name": s.name,
            "scope": scope.as_str(),
            "path": gone.path,
            "removed_digest": gone.removed_digest,
        }),
        format!(
            "Removed {} from {}. It stays in your library.",
            s.name,
            gone.path.display()
        ),
    ))
}

fn rollback(ctx: &Ctx, node: &Node, a: &SkillsRollbackArgs) -> Result<Report> {
    human_only("rolling a skill back")?;
    let s = crate::ids::resolve_skill(&node.store, &a.id)?;
    let (scope, row) = pick_scope(node, &s.name, a.scope)?;
    let row = row.ok_or_else(|| usage("that skill is not installed in this scope"))?;
    let previous = row.previous_digest.ok_or_else(|| {
        usage("there is no earlier version of that skill on this node to roll back to")
    })?;
    let bundle = crate::library::bundle_store(&node.home)
        .get(&previous)
        .map_err(|_| anyhow!("the earlier version is missing from this node's bundle store"))?;
    let (path, changed, _) = install_bundle(
        ctx,
        node,
        &bundle,
        &Request {
            scope,
            opts: InstallOptions::default(),
            yes: a.yes,
            accept_risk: a.accept_risk,
            what: "roll back",
        },
    )?;
    Ok(Report::new(
        json!({
            "skill_name": s.name,
            "scope": scope.as_str(),
            "path": path,
            "bundle_digest": previous,
            "changed": changed,
        }),
        format!(
            "Rolled {} back to {} at {}.",
            s.name,
            short_id(&previous),
            path.display()
        ),
    ))
}
