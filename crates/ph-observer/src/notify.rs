//! Notification throttle (specification 7.2: "default <=2 unsolicited question
//! notifications/day, inbox for the rest, per-topic cooldown and quiet-hours settings").
//!
//! [`should_notify`] and [`evaluate`] are pure: the caller supplies the history of shown
//! notifications (the `notifications` table: `(topic, shown_at)`) and the current time,
//! and records a new row whenever it actually shows one.

use ph_core::{ParseError, Timestamp};
use serde::{Deserialize, Serialize};

/// Length of the rolling window for [`NotifyPolicy::max_per_day`], in seconds.
pub const DAY_WINDOW_SECS: i64 = ph_core::timestamp::SECS_PER_DAY;

/// Largest accepted UTC offset for [`QuietHours`], in minutes (±14 h).
pub const MAX_UTC_OFFSET_MINUTES: i16 = 14 * 60;

/// Throttle settings. `Default` is the specification default: 2 per day, 24 h per-topic
/// cooldown, no quiet hours.
///
/// Deserializes from a config table with every field optional, for example in TOML:
/// `max_per_day = 2`, `topic_cooldown_secs = 86400`,
/// `quiet_hours = { start_hour = 22, end_hour = 7, utc_offset_minutes = 120 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyPolicy {
    /// Maximum notifications in any rolling 24 h window. `0` disables notifications.
    pub max_per_day: u32,
    /// Minimum seconds between two notifications with the same topic. `<= 0` disables
    /// the cooldown.
    pub topic_cooldown_secs: i64,
    /// Local hours during which nothing is shown.
    pub quiet_hours: Option<QuietHours>,
}

impl Default for NotifyPolicy {
    fn default() -> Self {
        Self {
            max_per_day: 2,
            topic_cooldown_secs: DAY_WINDOW_SECS,
            quiet_hours: None,
        }
    }
}

/// A daily quiet window `[start_hour, end_hour)` in local time, where local time is UTC
/// plus `utc_offset_minutes`. `start_hour > end_hour` wraps midnight (for example
/// 22 to 7). `start_hour == end_hour` is rejected as ambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "QuietHoursRepr", into = "QuietHoursRepr")]
pub struct QuietHours {
    start_hour: u8,
    end_hour: u8,
    utc_offset_minutes: i16,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuietHoursRepr {
    start_hour: u8,
    end_hour: u8,
    #[serde(default)]
    utc_offset_minutes: i16,
}

impl TryFrom<QuietHoursRepr> for QuietHours {
    type Error = ParseError;
    fn try_from(r: QuietHoursRepr) -> Result<Self, ParseError> {
        QuietHours::new(r.start_hour, r.end_hour)?.with_utc_offset_minutes(r.utc_offset_minutes)
    }
}

impl From<QuietHours> for QuietHoursRepr {
    fn from(q: QuietHours) -> Self {
        Self {
            start_hour: q.start_hour,
            end_hour: q.end_hour,
            utc_offset_minutes: q.utc_offset_minutes,
        }
    }
}

impl QuietHours {
    /// A quiet window in UTC hours (`0..=23` each, and `start != end`).
    pub fn new(start_hour: u8, end_hour: u8) -> Result<Self, ParseError> {
        if start_hour > 23 || end_hour > 23 {
            return Err(ParseError::new("quiet hours", "hours must be 0-23"));
        }
        if start_hour == end_hour {
            return Err(ParseError::new(
                "quiet hours",
                "start and end hour must differ",
            ));
        }
        Ok(Self {
            start_hour,
            end_hour,
            utc_offset_minutes: 0,
        })
    }

    /// Interprets the hours in local time `UTC + minutes` (within ±14 h).
    pub fn with_utc_offset_minutes(mut self, minutes: i16) -> Result<Self, ParseError> {
        if !(-MAX_UTC_OFFSET_MINUTES..=MAX_UTC_OFFSET_MINUTES).contains(&minutes) {
            return Err(ParseError::new(
                "quiet hours",
                "utc offset must be within +-14 hours",
            ));
        }
        self.utc_offset_minutes = minutes;
        Ok(self)
    }

    /// Start hour (inclusive).
    pub const fn start_hour(&self) -> u8 {
        self.start_hour
    }

    /// End hour (exclusive).
    pub const fn end_hour(&self) -> u8 {
        self.end_hour
    }

    /// Offset of local time from UTC, in minutes.
    pub const fn utc_offset_minutes(&self) -> i16 {
        self.utc_offset_minutes
    }

    /// True when `now` falls inside the quiet window.
    pub fn contains(&self, now: Timestamp) -> bool {
        let local = now
            .unix_seconds()
            .saturating_add(i64::from(self.utc_offset_minutes) * 60);
        let hour = u8::try_from(local.rem_euclid(DAY_WINDOW_SECS) / 3600).unwrap_or(0);
        if self.start_hour < self.end_hour {
            self.start_hour <= hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Why [`evaluate`] allowed or refused a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyDecision {
    /// Show it (and record it).
    Allow,
    /// `now` is inside the quiet hours.
    QuietHours,
    /// [`NotifyPolicy::max_per_day`] notifications were already shown in the last 24 h.
    DailyLimit,
    /// The same topic was shown within [`NotifyPolicy::topic_cooldown_secs`].
    TopicCooldown,
}

impl NotifyDecision {
    /// A stable code for logs and `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            NotifyDecision::Allow => "allow",
            NotifyDecision::QuietHours => "quiet_hours",
            NotifyDecision::DailyLimit => "daily_limit",
            NotifyDecision::TopicCooldown => "topic_cooldown",
        }
    }
}

/// Topics compare after trimming and ASCII lowercasing.
fn same_topic(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Decides whether a notification for `topic` may be shown at `now`.
///
/// `history` holds `(topic, shown_at)` of previously shown notifications, in any order.
/// Checks, in order: quiet hours, the rolling 24 h limit, the topic cooldown. Entries
/// dated in the future (clock moved back) count as recent, so a clock change can only
/// make the throttle stricter.
pub fn evaluate(
    policy: &NotifyPolicy,
    history: &[(String, Timestamp)],
    topic: &str,
    now: Timestamp,
) -> NotifyDecision {
    if policy.quiet_hours.is_some_and(|q| q.contains(now)) {
        return NotifyDecision::QuietHours;
    }
    let recent = history
        .iter()
        .filter(|(_, t)| now.secs_since(*t) < DAY_WINDOW_SECS)
        .count();
    if recent >= usize::try_from(policy.max_per_day).unwrap_or(usize::MAX) {
        return NotifyDecision::DailyLimit;
    }
    if policy.topic_cooldown_secs > 0
        && history.iter().any(|(t_topic, t)| {
            same_topic(t_topic, topic) && now.secs_since(*t) < policy.topic_cooldown_secs
        })
    {
        return NotifyDecision::TopicCooldown;
    }
    NotifyDecision::Allow
}

/// `evaluate(..) == NotifyDecision::Allow`.
pub fn should_notify(
    policy: &NotifyPolicy,
    history: &[(String, Timestamp)],
    topic: &str,
    now: Timestamp,
) -> bool {
    evaluate(policy, history, topic, now) == NotifyDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_hours_validation() {
        assert!(QuietHours::new(24, 1).is_err());
        assert!(QuietHours::new(1, 24).is_err());
        assert!(QuietHours::new(5, 5).is_err());
        let q = QuietHours::new(22, 7).unwrap();
        assert!(q.with_utc_offset_minutes(841).is_err());
        assert!(q.with_utc_offset_minutes(-841).is_err());
        assert!(q.with_utc_offset_minutes(-840).is_ok());
    }

    #[test]
    fn policy_serde() {
        let p: NotifyPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, NotifyPolicy::default());
        let p: NotifyPolicy = serde_json::from_str(
            r#"{"max_per_day":3,"quiet_hours":{"start_hour":22,"end_hour":7,"utc_offset_minutes":60}}"#,
        )
        .unwrap();
        assert_eq!(p.max_per_day, 3);
        assert_eq!(p.topic_cooldown_secs, DAY_WINDOW_SECS);
        let q = p.quiet_hours.unwrap();
        assert_eq!(
            (q.start_hour(), q.end_hour(), q.utc_offset_minutes()),
            (22, 7, 60)
        );
        let back: NotifyPolicy = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
        assert!(serde_json::from_str::<NotifyPolicy>(
            r#"{"quiet_hours":{"start_hour":3,"end_hour":3}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<NotifyPolicy>(r#"{"bogus":1}"#).is_err());
    }
}
