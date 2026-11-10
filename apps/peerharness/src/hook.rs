//! `peerharness hook <event>`: invoked by Claude Code.
//!
//! Rules (architecture section 1, app brief "Hook"):
//! * ALWAYS exit 0, never block, never prompt, never unlock a key;
//! * print NOTHING for UserPromptSubmit (its stdout becomes model context);
//! * never read `transcript_path`;
//! * exit at once when the home is not initialized or `PEERHARNESS_ADVISORY_CHILD` is set;
//! * store a bounded, redacted observation with a short busy timeout, falling back to the
//!   spool file;
//! * for Stop, print a throttled `systemMessage` when proposals wait for the owner's
//!   vote or new candidates wait for review. It carries a count and nothing else, and
//!   Claude Code shows it to the person, not to the model.

use std::io::Write;
use std::path::PathBuf;

use ph_core::{CandidateStatus, ObservationId, Timestamp};
use ph_observer::{HookEvent, HookOutput};
use ph_store::Store;

use crate::config::Config;
use crate::detect;
use crate::home::Home;

/// SQLite busy timeout for hooks.
pub const HOOK_BUSY_TIMEOUT_MS: u64 = 250;

/// Notification topic for "candidates to review".
pub const CANDIDATE_TOPIC: &str = "candidates";

/// Notification topic for "proposals that wait for your vote".
pub const VOTE_TOPIC: &str = "votes";

/// Notification history kept for throttling.
const NOTIFICATION_HISTORY_SECS: i64 = 30 * 86_400;

/// Runs the hook and exits the process with status 0, whatever happens.
pub fn run_and_exit(home_arg: Option<PathBuf>, event_arg: Option<&str>) -> ! {
    // A panic must not print anything (stdout or stderr) nor change the exit status.
    std::panic::set_hook(Box::new(|_| {}));
    let output =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(home_arg, event_arg)))
            .unwrap_or_default();
    if !output.is_silent() {
        let mut out = std::io::stdout().lock();
        let _ = output.write_to(&mut out);
        let _ = out.flush();
    }
    std::process::exit(HookOutput::EXIT_CODE)
}

fn run(home_arg: Option<PathBuf>, event_arg: Option<&str>) -> HookOutput {
    if std::env::var_os(ph_learning::providers::ADVISORY_CHILD_ENV).is_some() {
        return HookOutput::silent();
    }
    let Some(event) = event_arg.and_then(HookEvent::from_cli_arg) else {
        return HookOutput::silent();
    };
    let Ok(home) = Home::resolve(home_arg.as_deref()) else {
        return HookOutput::silent();
    };
    if !home.is_initialized() {
        return HookOutput::silent();
    }
    let now = Timestamp::now();
    let observation = ph_observer::read_bounded_stdin()
        .and_then(|b| ph_observer::parse_hook_payload(&b))
        .ok()
        .and_then(|payload| {
            let id = ObservationId::random().ok()?;
            ph_observer::normalize(&payload, Some(event), id, now)
        });
    let config = Config::load(&home).unwrap_or_default();
    let retention = config.retention.observation_secs();

    let store = Store::open_with_busy_timeout(home.db_path(), HOOK_BUSY_TIMEOUT_MS).ok();
    let mut stored = false;
    if let Some(obs) = &observation {
        stored = store
            .as_ref()
            .is_some_and(|s| detect::store_observation(s, obs, retention).is_ok());
        if !stored {
            let _ = ph_observer::append_observation(&home.spool_path(), obs);
        }
    }
    let Some(store) = store else {
        return HookOutput::silent();
    };
    match event {
        HookEvent::UserPromptSubmit => {
            if let (true, Some(obs)) = (stored, &observation) {
                let _ = detect::run_detection(&store, Some(&obs.repo_key), retention, now);
            }
            // Never any output for UserPromptSubmit.
            HookOutput::silent()
        }
        HookEvent::Stop => {
            detect::drain_spool(&home.spool_path(), &store, retention);
            if let Some(obs) = &observation {
                let _ = detect::run_detection(&store, Some(&obs.repo_key), retention, now);
            }
            stop_notice(&store, &config, now)
        }
        HookEvent::PostToolUseFailure => HookOutput::silent(),
    }
}

fn stop_notice(store: &Store, config: &Config, now: Timestamp) -> HookOutput {
    // Other members wait for a ballot; a note waits for nobody. Votes come first.
    let votes = store
        .identity()
        .ok()
        .flatten()
        .and_then(|id| crate::governance::awaiting_vote(store, &id.device_key).ok())
        .map_or(0, |waiting| waiting.len());
    let notes = store
        .candidates(&[CandidateStatus::Detected])
        .map_or(0, |new| new.len());
    if votes == 0 && notes == 0 {
        return HookOutput::silent();
    }
    let Ok(policy) = config.notifications.policy() else {
        return HookOutput::silent();
    };
    let _ = store.purge_notifications_before(now.minus_secs(NOTIFICATION_HISTORY_SECS));
    // What the daemon showed on the desktop (ADR-036) is counted by its own limits,
    // not by the hook's.
    let history: Vec<(String, Timestamp)> = store
        .notifications()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| !n.topic.starts_with(crate::notify::DESKTOP_PREFIX))
        .map(|n| (n.topic, n.shown_at))
        .collect();
    // One message per turn. Each topic has its own cooldown, so a note that was
    // announced today does not keep a vote from being announced.
    for (topic, count, text) in [
        (VOTE_TOPIC, votes, vote_notice_text as fn(usize) -> String),
        (CANDIDATE_TOPIC, notes, notice_text),
    ] {
        if count == 0 {
            continue;
        }
        let out = HookOutput::stop_notice_if_allowed(&text(count), &policy, &history, topic, now);
        if out.is_silent() {
            continue;
        }
        if store.record_notification(topic, now).is_err() {
            // Without a record the throttle cannot hold: stay silent.
            return HookOutput::silent();
        }
        return out;
    }
    HookOutput::silent()
}

/// The Stop notice text.
pub fn notice_text(n: usize) -> String {
    if n == 1 {
        "PeerHarness: 1 possible convention to review — run `peerharness inbox`".to_owned()
    } else {
        format!("PeerHarness: {n} possible conventions to review — run `peerharness inbox`")
    }
}

/// The Stop notice text for proposals that wait for the owner's vote.
pub fn vote_notice_text(n: usize) -> String {
    if n == 1 {
        "PeerHarness: 1 proposal waits for your vote — run `peerharness inbox`".to_owned()
    } else {
        format!("PeerHarness: {n} proposals wait for your vote — run `peerharness inbox`")
    }
}

/// If the raw arguments invoke `hook`, returns `(home, event)` without clap, so that even
/// malformed hook invocations exit 0 silently.
pub fn detect_hook_invocation(
    args: &[std::ffi::OsString],
) -> Option<(Option<PathBuf>, Option<String>)> {
    let mut home: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        let a = args[i].to_string_lossy();
        if a == "--home" {
            home = args.get(i + 1).map(PathBuf::from);
            i += 2;
            continue;
        }
        if let Some(h) = a.strip_prefix("--home=") {
            home = Some(PathBuf::from(h));
            i += 1;
            continue;
        }
        if a == "--json"
            || a == "--verbose"
            || (a.starts_with('-')
                && a.trim_start_matches('-').chars().all(|c| c == 'v')
                && a.len() > 1
                && !a.starts_with("--"))
        {
            i += 1;
            continue;
        }
        if a == "hook" {
            let event = args.get(i + 1).map(|e| e.to_string_lossy().into_owned());
            let home = home.or_else(|| std::env::var_os("PEERHARNESS_HOME").map(PathBuf::from));
            return Some((home, event));
        }
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_notices_carry_a_count_and_nothing_else() {
        assert_eq!(
            vote_notice_text(1),
            "PeerHarness: 1 proposal waits for your vote — run `peerharness inbox`"
        );
        assert_eq!(
            vote_notice_text(3),
            "PeerHarness: 3 proposals wait for your vote — run `peerharness inbox`"
        );
        assert!(notice_text(2).contains("2 possible conventions to review"));
        assert_ne!(VOTE_TOPIC, CANDIDATE_TOPIC);
    }

    #[test]
    fn hook_invocation_detection() {
        let (h, e) = detect_hook_invocation(&args(&["ph", "hook", "stop"])).unwrap();
        assert_eq!(e.as_deref(), Some("stop"));
        let _ = h;
        let (h, e) = detect_hook_invocation(&args(&[
            "ph", "--home", "/x", "-vv", "hook", "bogus", "--x",
        ]))
        .unwrap();
        assert_eq!(h, Some(PathBuf::from("/x")));
        assert_eq!(e.as_deref(), Some("bogus"));
        let (_, e) = detect_hook_invocation(&args(&["ph", "--home=/y", "hook"])).unwrap();
        assert_eq!(e, None);
        assert!(detect_hook_invocation(&args(&["ph", "status"])).is_none());
        assert!(detect_hook_invocation(&args(&["ph", "circle", "create", "hook"])).is_none());
    }

    #[test]
    fn notice_texts() {
        assert_eq!(
            notice_text(1),
            "PeerHarness: 1 possible convention to review — run `peerharness inbox`"
        );
        assert!(notice_text(3).contains("3 possible conventions"));
    }
}
