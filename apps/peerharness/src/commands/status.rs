//! `peerharness status`: mode, identity, circles, hooks and local counts. Never unlocks.

use anyhow::Result;
use ph_core::CandidateStatus;
use serde_json::json;

use super::{claude_settings_path, hook_command, Ctx};
use crate::daemon_info::DaemonInfo;
use crate::detect;
use crate::output::{safe, Report, Text};

pub fn run(ctx: &Ctx) -> Result<Report> {
    let node = ctx.open_node()?;
    let retention = node.config.retention.observation_secs();
    detect::drain_spool(&node.home.spool_path(), &node.store, retention);

    let circles = node.store.circles()?;
    let me = node.device_key();
    // Membership is the roll of the current charter (ADR-026): what this node shows is
    // what it would answer a peer.
    let mut standing: Vec<(usize, &'static str)> = Vec::new();
    for c in &circles {
        let charter = node.store.current_charter(&c.circle_id)?;
        let members = charter.as_ref().map_or(0, |ch| ch.content.roll.len());
        let on_roll = charter
            .as_ref()
            .is_some_and(|ch| ch.content.member_of(&me).is_some());
        let state = if node.store.is_revoked(&c.circle_id, &me)? {
            "this device was revoked"
        } else if !on_roll {
            "you are not on the roll"
        } else if node.store.circle_left_at(&c.circle_id)?.is_some() {
            "you left on this machine; still on the roll"
        } else {
            "member"
        };
        standing.push((members, state));
    }
    let circles_json: Vec<_> = circles
        .iter()
        .zip(&standing)
        .map(|(c, (members, state))| {
            json!({
                "name": c.name,
                "circle_id": c.circle_id,
                "is_founder": c.is_founder,
                "root_fingerprint": c.root_key.fingerprint(),
                "members": members,
                "self_active": *state == "member",
                "standing": state,
                "adoption_mode": c.adoption_mode,
            })
        })
        .collect();

    let mut by_status = serde_json::Map::new();
    let candidates = node.store.candidates(&[])?;
    for s in CandidateStatus::ALL {
        let n = candidates.iter().filter(|c| c.status == s).count();
        if n > 0 {
            by_status.insert(s.as_str().to_owned(), json!(n));
        }
    }
    let skills = node.store.skills()?;
    let installs = node.store.active_installations()?;
    let peers = node.store.peers()?.len();
    let observations = node.store.observation_count()?;

    let settings = claude_settings_path(None).ok();
    let hooks = match (&settings, hook_command(&node.home)) {
        (Some(p), Ok(cmd)) => match ph_observer::hooks_status(p) {
            Ok(st) => json!({
                "settings": p,
                "installed": st.is_installed_for(&cmd),
                "events": st.installed_events.iter().map(|e| e.event_name()).collect::<Vec<_>>(),
            }),
            Err(e) => json!({ "settings": p, "installed": false, "error": e.to_string() }),
        },
        _ => json!({ "installed": false }),
    };
    let daemon = DaemonInfo::running(&node.home);

    let mode = if circles.is_empty() {
        "personal"
    } else {
        "circle"
    };
    let json = json!({
        "mode": mode,
        "home": node.home.root(),
        "device_key": me,
        "fingerprint": me.fingerprint(),
        "peer_id": node.peer_id().to_string(),
        "keystore": node.identity.keystore_backend,
        "circles": circles_json,
        "candidates": by_status,
        "observations": observations,
        "skills": skills.len(),
        "active_installations": installs.len(),
        "known_peers": peers,
        "hooks": hooks,
        "daemon": daemon.as_ref().map(|d| json!({"pid": d.pid, "listen_addrs": d.listen_addrs})),
    });

    let mut t = Text::new();
    t.line(format!("PeerHarness node ({mode} mode)"));
    t.kv("home", node.home.root().display());
    t.kv("device key", me);
    t.kv("fingerprint", me.fingerprint());
    t.kv("peer id", node.peer_id());
    t.kv("keystore", &node.identity.keystore_backend);
    t.kv(
        "daemon",
        daemon.as_ref().map_or("not running".to_owned(), |d| {
            format!("running (pid {})", d.pid)
        }),
    );
    t.kv(
        "claude hooks",
        if hooks["installed"].as_bool() == Some(true) {
            "installed"
        } else {
            "not installed (`peerharness watch claude --install`)"
        },
    );
    t.kv("observations", observations);
    let cand_summary = if by_status.is_empty() {
        "none".to_owned()
    } else {
        by_status
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    t.kv("candidates", cand_summary);
    t.kv(
        "skills",
        format!("{} ({} installed)", skills.len(), installs.len()),
    );
    t.kv("known peers", peers);
    if circles.is_empty() {
        t.kv("circles", "none");
    } else {
        t.line("  circles:");
        for (c, (members, state)) in circles.iter().zip(&standing) {
            t.line(format!(
                "    {} ({}) root {} - {members} member(s), mode {}{}",
                safe(&c.name),
                if c.is_founder { "founder" } else { "joined" },
                c.root_key.fingerprint(),
                c.adoption_mode,
                if *state == "member" {
                    String::new()
                } else {
                    format!(" - {state}")
                }
            ));
        }
    }
    Ok(Report::new(json, t.finish()))
}
