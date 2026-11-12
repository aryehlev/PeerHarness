//! `peerharness reset`: delete this node.
//!
//! Without `--confirm` it only says what would go. With it, the keystore entries of
//! this home (the device key, and the root key of every circle founded here) are
//! deleted, and so is what PeerHarness put into the home directory. That cannot be
//! undone, and for a founder it is final for the circle as well: without its root key
//! the roll can never change again.
//!
//! It deletes PeerHarness's own files and folders and nothing else
//! (`Home::delete_own`, ADR-051). A home is whatever folder its owner named, and that
//! can be a folder with other work in it. What is not PeerHarness's stays, the folder
//! stays with it, and both the account and the report say so. The home directory of
//! the user, and any folder that holds it, is refused under every spelling.
//!
//! A node whose database cannot be read, because it is damaged or a newer version
//! wrote it, can still be deleted. What it held cannot be listed then, and the account
//! says that instead.
//!
//! What it leaves alone, and says so with the command that removes each: skills
//! installed in the agent's directory, the hooks in the agent's settings, the
//! registration of the MCP server with Claude Code, and for each other connected agent
//! its copies of the rules and its tools entry (ADR-050). All three belong to the agent's
//! configuration. The registration is named whether or not there is one: PeerHarness
//! does not read Claude Code's configuration to find out.
//!
//! The commands that take an installed skill out need the node. Before the reset they
//! are named; after it they could no longer run, so the report names the folders
//! instead, which are then the owner's to delete by hand.

use anyhow::{anyhow, Context, Result};
use ph_identity::{root_key_label, DeviceIdentity, KeystoreBackend};
use ph_store::InstallationRow;
use serde_json::json;

use crate::cli::ResetArgs;
use crate::commands::Ctx;
use crate::config::Config;
use crate::consent::human_only;
use crate::daemon_info::DaemonLock;
use crate::error::{refused, usage};
use crate::home::Home;
use crate::node::{open_keystore_no_unlock, Node};
use crate::output::{safe, Report, Text};

/// Refuses anything that is not plainly a folder for a node: a link, a path with fewer
/// than two components, the user's home directory, or a folder that holds it.
///
/// The paths are compared as the file system resolves them. `~/Documents/..` and a
/// path through a linked folder name the same directory as `~`, and compared as text
/// they would not.
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
    let real =
        std::fs::canonicalize(root).with_context(|| format!("cannot read {}", root.display()))?;
    let too_short = real.components().count() < 3;
    let holds_user_home = crate::home::user_home().is_some_and(|h| {
        // A home directory that does not exist cannot be resolved: compare its name.
        let h = std::fs::canonicalize(&h).unwrap_or(h);
        h.starts_with(&real) || h.starts_with(root)
    });
    if too_short || holds_user_home {
        return Err(refused(format!(
            "{} is your home directory or holds it, or is too close to the root of the \
             disk: PeerHarness deletes nothing there. Nothing was deleted. What it keeps \
             there is `config.toml`, `peerharness.db` and the folders `keys`, `bundles`, \
             `backups` and `spool`",
            root.display()
        )));
    }
    Ok(())
}

/// What a node holds, read from its database.
struct Held {
    fingerprint: String,
    circles: usize,
    /// The circles founded here, as (label of the root key, name).
    founded: Vec<(String, String)>,
    candidates: usize,
    skills: usize,
    installations: Vec<InstallationRow>,
    backend: KeystoreBackend,
}

impl Held {
    fn of(node: &Node) -> Result<Self> {
        let circles = node.store.circles()?;
        Ok(Self {
            fingerprint: node.device_key().fingerprint().to_string(),
            circles: circles.len(),
            founded: circles
                .iter()
                .filter(|c| c.is_founder)
                .map(|c| (root_key_label(&c.circle_id), c.name.clone()))
                .collect(),
            candidates: node.store.candidates(&[])?.len(),
            skills: node.store.skills()?.len(),
            installations: node.store.active_installations()?,
            backend: node.backend()?,
        })
    }
}

/// The names in `names`, for a line: the first few, made safe for a terminal, and how
/// many more there are.
fn listed(names: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut out = names
        .iter()
        .take(SHOWN)
        .map(|n| safe(n))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        out.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    out
}

pub fn run(ctx: &Ctx, args: ResetArgs) -> Result<Report> {
    let home = &ctx.home;
    if !home.is_initialized() {
        return Err(usage(format!(
            "{} is not an initialized PeerHarness home: there is nothing to reset",
            home.root().display()
        )));
    }
    if args.confirm {
        human_only("deleting this node and its keys")?;
    }
    check_deletable(home)?;

    // A database that cannot be read does not keep its owner from deleting the node.
    // The handle is dropped again at once: nothing below needs it, and the files are
    // about to go.
    let held = match Node::open(home) {
        Ok(node) => Some(Held::of(&node)?),
        Err(_) => None,
    };
    // Without the database, the keystore is the one the config file names.
    let backend = match &held {
        Some(h) => Some(h.backend),
        None => Config::load(home).ok().map(|c| c.node.keystore),
    };
    let stays = home.foreign_entries()?;

    let mut t = Text::new();
    t.line(format!(
        "Resetting deletes this node: {}",
        home.root().display()
    ));
    match &held {
        Some(h) => {
            t.line(format!(
                "  the device key ({}), which is this node's identity and signs your ballots",
                h.fingerprint
            ));
            for (_, name) in &h.founded {
                t.line(format!(
                    "  the root key of the circle {}, which you founded: without it nobody can \
                     ever be admitted to or removed from that circle again",
                    safe(name)
                ));
            }
            t.line(format!(
                "  the database: {} circle(s), {} candidate rule(s), {} skill(s) in your library",
                h.circles, h.candidates, h.skills
            ));
        }
        None => {
            t.line("  the device key, which is this node's identity and signs your ballots");
            t.line(
                "  the database, which cannot be read (it is damaged, or a newer version of \
                 PeerHarness wrote it): what it holds cannot be listed here",
            );
            t.line(
                "  the root key of every circle founded here, if its key file is in this \
                 folder: without it nobody can ever be admitted to or removed from that \
                 circle again",
            );
            if backend != Some(KeystoreBackend::File)
                && backend != Some(KeystoreBackend::InsecureDev)
            {
                t.line(
                    "  Not found without the database: root keys in the keychain of the \
                     operating system. They stay there under the service `peerharness`.",
                );
            }
        }
    }
    t.line(
        "  In that folder it deletes what PeerHarness put there and nothing else: \
         `config.toml`, the database, and the folders `keys`, `bundles`, `backups` and \
         `spool` with what they hold.",
    );
    if !stays.is_empty() {
        t.line(format!(
            "  {} other item(s) in that folder are not PeerHarness's. They stay, and so \
             does the folder: {}",
            stays.len(),
            listed(&stays)
        ));
    }
    t.line("It cannot be undone. Your ballots already cast stay on the other members' nodes.");
    // What belongs to the agent's configuration, or is the program itself, stays. Each
    // line names the way to remove it. The commands for an installed skill need the
    // node: they are named here, before the reset, and not after it. `watch claude
    // --remove` and Claude Code's own command work at any time.
    t.line("Left in place:");
    match &held {
        Some(h) => t.line(format!(
            "  {} skill(s) installed for your agent (`peerharness skills uninstall`, \
             `peerharness rule opt-out`: both need this node, so run them before the reset)",
            h.installations.len()
        )),
        None => t.line(
            "  every skill installed for your agent: each is a folder for you to delete by \
             hand, because the commands that take one out need the database",
        ),
    };
    let left = [
        "  the hooks and the reporting skill, if installed (`peerharness watch claude --remove`)"
            .to_owned(),
        format!(
            "  the registration of the PeerHarness tools with Claude Code, if `peerharness \
             setup` made one (`{}`)",
            super::setup::UNREGISTER
        ),
        "  the peerharness program, which is one file: delete it where it was installed".to_owned(),
    ];
    // The other agents: their copies and tools entries need the node to be found, so
    // the command is named before the reset. Which agents are connected stands in the
    // config file, which is read without the database.
    let connected = Config::load(home)
        .map(|c| c.agents.connected)
        .unwrap_or_default();
    let left: Vec<String> = left
        .into_iter()
        .chain(connected.iter().map(|a| {
            format!(
                "  for {}, the copies of your rules and its tools entry (`peerharness \
                 watch {} --remove`: run it before the reset)",
                a.name(),
                a.id()
            )
        }))
        .collect();
    for line in &left {
        t.line(line);
    }
    let installed = held.as_ref().map(|h| h.installations.len());
    let summary = json!({
        "home": home.root(),
        "database_readable": held.is_some(),
        "circles": held.as_ref().map(|h| h.circles),
        "founded_circles": held.as_ref().map(|h| h.founded.len()),
        "candidates": held.as_ref().map(|h| h.candidates),
        "skills": held.as_ref().map(|h| h.skills),
        "installed_skills_left": installed,
        "not_peerharness_left": stays,
    });

    if !args.confirm {
        t.line("Nothing was deleted. To do it: `peerharness reset --confirm`.");
        let mut json = summary;
        json["deleted"] = json!(false);
        return Ok(Report::new(json, t.finish()));
    }

    if DaemonLock::is_held(home) {
        return Err(refused(
            "a daemon is running for this home: stop it first. Nothing was deleted.",
        ));
    }

    // Keys first: an OS keychain entry would otherwise outlive the home that names it.
    // A key file goes with the `keys` folder in any case.
    let mut keys_deleted = 0;
    if let Some(backend) = backend {
        let keystore = open_keystore_no_unlock(home, backend)?;
        let mut labels = vec![DeviceIdentity::LABEL.to_owned()];
        if let Some(h) = &held {
            labels.extend(h.founded.iter().map(|(label, _)| label.clone()));
        }
        for label in &labels {
            if keystore
                .delete(label)
                .map_err(|e| anyhow!("cannot delete a key from the keystore: {e}"))?
            {
                keys_deleted += 1;
            }
        }
    }
    let home_removed = home.delete_own()?;

    let mut json = summary;
    json["deleted"] = json!(true);
    json["keys_deleted"] = json!(keys_deleted);
    json["home_removed"] = json!(home_removed);
    let mut t = Text::new();
    if home_removed {
        t.line(format!(
            "Deleted {} and {keys_deleted} key(s). This node no longer exists.",
            home.root().display()
        ));
    } else {
        t.line(format!(
            "Deleted what PeerHarness kept in {} and {keys_deleted} key(s). This node no \
             longer exists.",
            home.root().display()
        ));
        t.line(format!(
            "The folder itself stays, with {} item(s) that are not PeerHarness's: {}",
            stays.len(),
            listed(&stays)
        ));
    }
    t.line("Still in place:");
    let installations = held.map(|h| h.installations).unwrap_or_default();
    if installed == Some(0) {
        t.line("  no skill installed for your agent");
    } else if installations.is_empty() {
        t.line(
            "  every skill installed for your agent: the database could not be read, so \
             they are not listed. Each is a folder for you to delete by hand.",
        );
    } else {
        // The commands that take a skill out needed the node that is gone now.
        t.line(format!(
            "  {} skill(s) installed for your agent. The commands that take one \
             out needed this node, so each is now a folder for you to delete by hand:",
            installations.len()
        ));
        for row in &installations {
            t.line(format!("      {}", safe(&row.path)));
        }
    }
    for line in &left {
        t.line(line);
    }
    json["installed_skill_folders_left"] =
        json!(installations.iter().map(|r| &r.path).collect::<Vec<_>>());
    Ok(Report::new(json, t.finish()))
}
