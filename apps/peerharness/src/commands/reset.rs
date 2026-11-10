//! `peerharness reset`: delete this node.
//!
//! Without `--confirm` it only says what would go. With it, the keystore entries of
//! this home (the device key, and the root key of every circle founded here) are
//! deleted and the home directory is removed. That cannot be undone, and for a founder
//! it is final for the circle as well: without its root key the roll can never change
//! again.
//!
//! What it leaves alone, and says so: skills installed in the agent's directory and the
//! hooks in the agent's settings, which belong to the agent's configuration.

use anyhow::{anyhow, Context, Result};
use ph_identity::{root_key_label, DeviceIdentity};
use serde_json::json;

use crate::cli::ResetArgs;
use crate::commands::Ctx;
use crate::consent::human_only;
use crate::daemon_info::DaemonLock;
use crate::error::{refused, usage};
use crate::home::Home;
use crate::node::{open_keystore_no_unlock, Node};
use crate::output::{safe, Report, Text};

/// Refuses anything that does not look like a PeerHarness home of its own: a link, a
/// path with fewer than two components, or the user's home directory itself.
fn check_deletable(home: &Home) -> Result<()> {
    let root = home.root();
    let meta = std::fs::symlink_metadata(root)
        .with_context(|| format!("cannot read {}", root.display()))?;
    if !meta.is_dir() {
        return Err(refused(format!(
            "{} is not a plain directory (it may be a link): nothing was deleted",
            root.display()
        )));
    }
    let too_short = root.components().count() < 3;
    let is_user_home = crate::home::user_home().is_some_and(|h| h == root);
    if too_short || is_user_home {
        return Err(refused(format!(
            "{} is not a directory PeerHarness may delete",
            root.display()
        )));
    }
    Ok(())
}

pub fn run(ctx: &Ctx, args: ResetArgs) -> Result<Report> {
    let home = &ctx.home;
    if !home.is_initialized() {
        return Err(usage(format!(
            "{} is not an initialized PeerHarness home: there is nothing to reset",
            home.root().display()
        )));
    }
    let node = Node::open(home)?;
    let backend = node.backend()?;
    let circles = node.store.circles()?;
    let founded: Vec<_> = circles.iter().filter(|c| c.is_founder).collect();
    let installed = node.store.active_installations()?.len();
    let candidates = node.store.candidates(&[])?.len();
    let skills = node.store.skills()?.len();

    let mut t = Text::new();
    t.line(format!(
        "Resetting deletes this node: {}",
        home.root().display()
    ));
    t.line(format!(
        "  the device key ({}), which is this node's identity and signs your ballots",
        node.device_key().fingerprint()
    ));
    for c in &founded {
        t.line(format!(
            "  the root key of the circle {}, which you founded: without it nobody can \
             ever be admitted to or removed from that circle again",
            safe(&c.name)
        ));
    }
    t.line(format!(
        "  the database: {} circle(s), {candidates} candidate rule(s), {skills} skill(s) in your library",
        circles.len()
    ));
    t.line("It cannot be undone. Your ballots already cast stay on the other members' nodes.");
    t.line("Left in place:");
    t.line(format!(
        "  {installed} skill(s) installed for your agent (`peerharness skills uninstall`, `peerharness rule opt-out`)"
    ));
    t.line(
        "  the hooks and the reporting skill, if installed (`peerharness watch claude --remove`)",
    );
    let summary = json!({
        "home": home.root(),
        "circles": circles.len(),
        "founded_circles": founded.len(),
        "candidates": candidates,
        "skills": skills,
        "installed_skills_left": installed,
    });

    if !args.confirm {
        t.line("Nothing was deleted. To do it: `peerharness reset --confirm`.");
        let mut json = summary;
        json["deleted"] = json!(false);
        return Ok(Report::new(json, t.finish()));
    }

    human_only("deleting this node and its keys")?;
    if DaemonLock::is_held(home) {
        return Err(refused(
            "a daemon is running for this home: stop it first. Nothing was deleted.",
        ));
    }
    check_deletable(home)?;

    // Keys first: an OS keychain entry would otherwise outlive the home that names it.
    let keystore = open_keystore_no_unlock(home, backend)?;
    let mut labels = vec![DeviceIdentity::LABEL.to_owned()];
    labels.extend(founded.iter().map(|c| root_key_label(&c.circle_id)));
    let mut keys_deleted = 0;
    for label in &labels {
        if keystore
            .delete(label)
            .map_err(|e| anyhow!("cannot delete a key from the keystore: {e}"))?
        {
            keys_deleted += 1;
        }
    }
    drop(keystore);
    drop(node);
    std::fs::remove_dir_all(home.root())
        .with_context(|| format!("cannot remove {}", home.root().display()))?;

    let mut json = summary;
    json["deleted"] = json!(true);
    json["keys_deleted"] = json!(keys_deleted);
    Ok(Report::new(
        json,
        format!(
            "Deleted {} and {keys_deleted} key(s). This node no longer exists.",
            home.root().display()
        ),
    ))
}
