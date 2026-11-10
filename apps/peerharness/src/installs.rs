//! Bookkeeping for skills installed into the agent's native skills directory.
//!
//! The files are written and removed by `ph_skills::Installer`. This module keeps the
//! `installations` and `skills` tables in step with what the installer did, for both
//! ways a skill gets installed: the owner's own `skills install`, and a rule that passed
//! a circle's vote (`governance::apply_rules`).

use anyhow::Result;
use ph_core::{Digest, Timestamp};
use ph_skills::{Bundle, InstallOutcome, SkillScope};
use ph_store::{NewInstallation, NewSkill, SkillOrigin, SkillStatus, Store};

/// The only agent supported so far.
pub const AGENT_CLAUDE: &str = "claude";

fn set_status(
    store: &Store,
    name: &str,
    digest: &Digest,
    status: SkillStatus,
    now: Timestamp,
) -> Result<()> {
    for row in store.skills_by_name(name)? {
        if row.bundle_digest == *digest && row.status != status {
            store.set_skill_status(row.id, status, now)?;
        }
    }
    Ok(())
}

/// Makes sure the library lists `bundle` as a skill adopted from a circle's proposal.
/// A skill the owner already holds under the same name and digest keeps its origin.
pub fn ensure_circle_skill(
    store: &Store,
    bundle: &Bundle,
    proposal_id: &ph_core::EventId,
    now: Timestamp,
) -> Result<()> {
    store.insert_skill(&NewSkill {
        name: bundle.name().to_owned(),
        bundle_digest: bundle.digest(),
        origin_kind: SkillOrigin::Proposal,
        origin_ref: proposal_id.to_string(),
        status: SkillStatus::Available,
        created_at: now,
    })?;
    Ok(())
}

/// Records a successful install: an `installations` row (unless the same version was
/// already recorded at that path) and the skill's status. The version it replaced, if
/// any, is marked uninstalled.
pub fn record_install(
    store: &Store,
    scope: SkillScope,
    bundle: &Bundle,
    outcome: &InstallOutcome,
    now: Timestamp,
) -> Result<()> {
    let path = outcome.path.to_string_lossy().into_owned();
    let name = bundle.name();
    let digest = bundle.digest();
    let already = store
        .active_installation_at(name, AGENT_CLAUDE, scope.as_str(), &path)?
        .is_some_and(|row| row.bundle_digest == digest);
    if !already {
        store.record_install(&NewInstallation {
            skill_name: name.to_owned(),
            agent: AGENT_CLAUDE.to_owned(),
            install_scope: scope.as_str().to_owned(),
            path,
            bundle_digest: digest,
            // Only a version this node still holds can be rolled back to.
            previous_digest: outcome
                .previous_digest
                .filter(|p| *p != digest && store.bundle(p).ok().flatten().is_some()),
            installed_at: now,
        })?;
    }
    if let Some(prev) = outcome.previous_digest.filter(|p| *p != digest) {
        set_status(store, name, &prev, SkillStatus::Uninstalled, now)?;
    }
    set_status(store, name, &digest, SkillStatus::Installed, now)
}

/// Records that the installed `digest` of `name` was removed from `path`.
pub fn record_uninstall(
    store: &Store,
    scope: SkillScope,
    name: &str,
    digest: &Digest,
    path: &std::path::Path,
    now: Timestamp,
) -> Result<()> {
    let path = path.to_string_lossy();
    if let Some(row) = store.active_installation_at(name, AGENT_CLAUDE, scope.as_str(), &path)? {
        store.mark_installation_removed(row.id, now)?;
    }
    let still_installed = store
        .active_installations()?
        .iter()
        .any(|i| i.skill_name == name && i.bundle_digest == *digest);
    if !still_installed {
        set_status(store, name, digest, SkillStatus::Uninstalled, now)?;
    }
    Ok(())
}
