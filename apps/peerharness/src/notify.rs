//! A notification of the operating system when a proposal that needs the owner's vote
//! reaches this node (ADR-036). Only a running `daemon --notify` shows one.
//!
//! The Stop hook tells the owner at the end of a turn with their agent (ADR-035). This
//! is the same news when it arrives: the daemon looks every few seconds at what waits
//! for the owner's vote ([`crate::governance::awaiting_vote`]) and shows one
//! notification for what is new.
//!
//! What it holds to:
//!
//! * a count and nothing else. No title, name or other text written by another member
//!   goes to the notification program or to the daemon's output;
//! * never twice for the same proposal, also across restarts: what was announced is
//!   recorded in the `notifications` table under a topic of its own
//!   ([`DESKTOP_PREFIX`]), which the Stop hook's own throttle does not count;
//! * a member who floods the circle cannot flood the screen: arrivals within
//!   [`SPACING_SECS`] are announced together, and at most [`DAILY_CAP`] proposals are
//!   announced in a day. The owner's quiet hours are kept, and `max_per_day = 0` in the
//!   configuration turns it off;
//! * a notification that cannot be shown is not tried again by this daemon.
//!
//! macOS only (`/usr/bin/osascript`, `display notification`). Debug builds also accept
//! `PEERHARNESS_TEST_NOTIFY_BIN`, a program that stands in for the notification in
//! tests and gets the text on standard input; release builds do not read it.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use ph_core::{EventId, Timestamp};
use ph_observer::NotifyPolicy;

use crate::node::Node;

/// How often the daemon looks.
pub const LOOK_EVERY: Duration = Duration::from_secs(3);

/// Topic prefix of what this module records in the `notifications` table.
pub const DESKTOP_PREFIX: &str = "desktop:";

/// Seconds between two notifications. Proposals that arrive closer together are
/// announced in one.
pub const SPACING_SECS: i64 = 60;

/// Most proposals announced in any 24 hours.
pub const DAILY_CAP: usize = 10;

/// Environment variable naming the stand-in notification program (debug builds only).
#[cfg(debug_assertions)]
pub const TEST_NOTIFY_ENV: &str = "PEERHARNESS_TEST_NOTIFY_BIN";

/// How long the notification program may take.
const SHOW_WAIT: Duration = Duration::from_secs(10);

fn topic(id: &EventId) -> String {
    format!("{DESKTOP_PREFIX}vote:{id}")
}

/// What to tell the owner now.
#[derive(Debug, PartialEq, Eq)]
pub struct News {
    /// The proposals this notification announces.
    pub proposals: Vec<EventId>,
    /// The text: a count of everything that waits, and where to look.
    pub text: String,
}

/// The text for `n` proposals that wait for the owner's vote.
pub fn vote_text(n: usize) -> String {
    if n == 1 {
        "1 proposal waits for your vote. Run: peerharness inbox".to_owned()
    } else {
        format!("{n} proposals wait for your vote. Run: peerharness inbox")
    }
}

/// Which of the `waiting` proposals to announce at `now`, given what was shown before
/// (`history`: topic and time of every recorded notification).
fn to_announce(
    waiting: &[EventId],
    history: &[(String, Timestamp)],
    policy: &NotifyPolicy,
    now: Timestamp,
) -> Vec<EventId> {
    let new: Vec<EventId> = waiting
        .iter()
        .filter(|id| {
            let topic = topic(id);
            !history.iter().any(|(t, _)| *t == topic)
        })
        .copied()
        .collect();
    if new.is_empty() || policy.max_per_day == 0 {
        return Vec::new();
    }
    // Only the owner's quiet hours are asked of the hook's policy: its daily number and
    // cooldown are about the hook's own notices.
    let hours = NotifyPolicy {
        max_per_day: u32::MAX,
        topic_cooldown_secs: 0,
        quiet_hours: policy.quiet_hours,
    };
    if !ph_observer::should_notify(&hours, &[], "desktop", now) {
        return Vec::new();
    }
    let ours = || {
        history
            .iter()
            .filter(|(t, _)| t.starts_with(DESKTOP_PREFIX))
            .map(|(_, at)| *at)
    };
    if ours().any(|at| now.secs_since(at) < SPACING_SECS) {
        return Vec::new();
    }
    let today = ours()
        .filter(|at| now.secs_since(*at) < ph_core::timestamp::SECS_PER_DAY)
        .count();
    new.into_iter()
        .take(DAILY_CAP.saturating_sub(today))
        .collect()
}

/// Looks at what waits for the owner's vote and returns what to announce, if anything.
/// Reads the store only.
pub fn news(node: &Node) -> Result<Option<News>> {
    let waiting: Vec<EventId> = crate::governance::awaiting_vote(&node.store, &node.device_key())?
        .iter()
        .map(|(_, p)| p.event_id())
        .collect();
    if waiting.is_empty() {
        return Ok(None);
    }
    let history: Vec<(String, Timestamp)> = node
        .store
        .notifications()?
        .into_iter()
        .map(|n| (n.topic, n.shown_at))
        .collect();
    let policy = node.config.notifications.policy()?;
    let proposals = to_announce(&waiting, &history, &policy, node.now());
    if proposals.is_empty() {
        return Ok(None);
    }
    Ok(Some(News {
        proposals,
        text: vote_text(waiting.len()),
    }))
}

/// Records that `proposals` were announced, so that they are not announced again.
pub fn record(node: &Node, proposals: &[EventId]) -> Result<()> {
    let now = node.now();
    for id in proposals {
        node.store.record_notification(&topic(id), now)?;
    }
    Ok(())
}

/// The notification this machine can show.
#[derive(Clone, Debug)]
#[cfg_attr(
    not(any(target_os = "macos", debug_assertions)),
    allow(dead_code) // never built where there is no notification program
)]
pub struct Desktop {
    program: PathBuf,
    /// Whether the program is `osascript` and takes a script, or the tests' stand-in,
    /// which takes the text itself.
    script: bool,
}

/// Where macOS keeps `osascript` (see `crate::window`).
#[cfg(target_os = "macos")]
const OSASCRIPT: &str = "/usr/bin/osascript";

impl Desktop {
    /// The notification of this machine, or `None` when this build has none.
    pub fn find() -> Option<Self> {
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os(TEST_NOTIFY_ENV).filter(|p| !p.is_empty()) {
            return Some(Self {
                program: PathBuf::from(p),
                script: false,
            });
        }
        #[cfg(target_os = "macos")]
        if std::path::Path::new(OSASCRIPT).is_file() {
            return Some(Self {
                program: PathBuf::from(OSASCRIPT),
                script: true,
            });
        }
        None
    }

    /// Shows `text`. Returns whether the notification program accepted it, which is not
    /// proof that the person saw it. Blocks for at most [`SHOW_WAIT`].
    pub fn show(&self, text: &str) -> bool {
        let mut command = Command::new(&self.program);
        let input = if self.script {
            // `-` reads the script from standard input.
            command.arg("-");
            applescript(text)
        } else {
            text.to_owned()
        };
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(input.as_bytes()).is_ok());
        let deadline = Instant::now() + SHOW_WAIT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return wrote && status.success(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }
}

/// The AppleScript that shows `text` as a notification titled "PeerHarness".
fn applescript(text: &str) -> String {
    format!(
        "display notification {} with title {}\n",
        crate::window::applescript_literal(text),
        crate::window::applescript_literal("PeerHarness"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ph_core::Digest;
    use ph_observer::QuietHours;

    fn id(n: u8) -> EventId {
        EventId::from(Digest::sha256(&[n]))
    }

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix_seconds(1_800_000_000 + secs).unwrap()
    }

    fn shown(n: u8, secs: i64) -> (String, Timestamp) {
        (topic(&id(n)), at(secs))
    }

    #[test]
    fn the_text_is_a_count_and_where_to_look() {
        assert_eq!(
            vote_text(1),
            "1 proposal waits for your vote. Run: peerharness inbox"
        );
        assert_eq!(
            vote_text(4),
            "4 proposals wait for your vote. Run: peerharness inbox"
        );
        let script = applescript("1 proposal waits");
        assert_eq!(
            script,
            "display notification \"1 proposal waits\" with title \"PeerHarness\"\n"
        );
    }

    #[test]
    fn a_proposal_is_announced_once() {
        let policy = NotifyPolicy::default();
        let now = at(10_000);
        assert!(to_announce(&[], &[], &policy, now).is_empty());
        assert_eq!(to_announce(&[id(1)], &[], &policy, now), [id(1)]);
        // Announced an hour ago: not again, and not after a restart either, since this
        // is read from the store.
        let history = [shown(1, 10_000 - 3600)];
        assert!(to_announce(&[id(1)], &history, &policy, now).is_empty());
        // Another proposal is news; the one already announced is not repeated.
        assert_eq!(
            to_announce(&[id(1), id(2)], &history, &policy, now),
            [id(2)]
        );
        // What the Stop hook showed does not count as announced here.
        let hook = [
            ("votes".to_owned(), at(9_990)),
            ("candidates".to_owned(), at(9_995)),
        ];
        assert_eq!(to_announce(&[id(3)], &hook, &policy, now), [id(3)]);
    }

    #[test]
    fn arrivals_are_spaced_capped_and_keep_quiet_hours() {
        let policy = NotifyPolicy::default();
        let now = at(100_000);
        // One was shown 30 seconds ago: the next waits, and is announced a minute on.
        let just = [shown(1, 100_000 - 30)];
        assert!(to_announce(&[id(2)], &just, &policy, now).is_empty());
        assert_eq!(
            to_announce(&[id(2)], &just, &policy, at(100_000 + 31)),
            [id(2)]
        );

        // Ten were announced in the last day: no more today, whoever sends them.
        let day: Vec<_> = (0..10)
            .map(|n| shown(n, 100_000 - 3600 - i64::from(n)))
            .collect();
        assert!(to_announce(&[id(50)], &day, &policy, now).is_empty());
        // A day later there is room again.
        assert_eq!(
            to_announce(&[id(50)], &day, &policy, at(100_000 + 86_400)),
            [id(50)]
        );
        // With room for three, three of five are announced now.
        let seven: Vec<_> = (0..7)
            .map(|n| shown(n, 100_000 - 3600 - i64::from(n)))
            .collect();
        let five = [id(20), id(21), id(22), id(23), id(24)];
        assert_eq!(to_announce(&five, &seven, &policy, now).len(), 3);

        // The owner's settings: off, and quiet hours.
        let off = NotifyPolicy {
            max_per_day: 0,
            ..NotifyPolicy::default()
        };
        assert!(to_announce(&[id(1)], &[], &off, now).is_empty());
        let hour = (now.unix_seconds() / 3600 % 24) as u8;
        let quiet = NotifyPolicy {
            quiet_hours: Some(QuietHours::new(hour, (hour + 1) % 24).unwrap()),
            ..NotifyPolicy::default()
        };
        assert!(to_announce(&[id(1)], &[], &quiet, now).is_empty());
        let later = at(100_000 + 2 * 3600);
        assert_eq!(to_announce(&[id(1)], &[], &quiet, later), [id(1)]);
    }
}
