//! `peerharness status`: mode, identity, circles, hooks and local counts. Never unlocks.

use anyhow::Result;
use ph_core::{CandidateStatus, MembershipOracle};
use serde_json::json;

use super::{claude_settings_path, hook_command, Ctx};
use crate::daemon_info::DaemonInfo;
use crate::detect;
use crate::output::{safe, Report, Text};

pub fn run(ctx: &Ctx) -> Result<Report> {
    let node = ctx.open_node()?;
    let now = node.now();
    let retention = node.config.retention.observation_secs();
    detect::drain_spool(&node.home.spool_path(), &node.store, retention);

    let circles = node.store.circles()?;
    let reg = crate::events::build_registry(&node.store, now)?;
    let me = node.device_key();
    let circles_json: Vec<_> = circles
        .iter()
        .map(|c| {
            let members = reg.members(&c.circle_id, now);
            json!({
                "name": c.name,
                "circle_id": c.circle_id,
                "is_founder": c.is_founder,
                "root_fingerprint": c.root_key.fingerprint(),
                "active_members": members.iter().filter(|m| m.active).count(),
                "self_active": reg.is_active_member(&c.circle_id, &me, now),
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
    let pending = node.store.pending_outbox_count()?;
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
        "pending_outbox": pending,
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
    t.kv("pending outbox", pending);
    if circles.is_empty() {
        t.kv("circles", "none");
    } else {
        t.line("  circles:");
        for c in &circles {
            let members = reg.members(&c.circle_id, now);
            t.line(format!(
                "    {} ({}) root {} - {} active member(s)",
                safe(&c.name),
                if c.is_founder { "founder" } else { "member" },
                c.root_key.fingerprint(),
                members.iter().filter(|m| m.active).count()
            ));
        }
    }
    Ok(Report::new(json, t.finish()))
}
