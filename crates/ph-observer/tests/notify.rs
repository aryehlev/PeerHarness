//! Notification throttle.

use ph_core::Timestamp;
use ph_observer::{evaluate, should_notify, NotifyDecision, NotifyPolicy, QuietHours};
use proptest::prelude::*;

const H: i64 = 3600;

fn t(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn hist(entries: &[(&str, Timestamp)]) -> Vec<(String, Timestamp)> {
    entries.iter().map(|(a, b)| ((*a).to_owned(), *b)).collect()
}

#[test]
fn defaults() {
    let p = NotifyPolicy::default();
    assert_eq!(p.max_per_day, 2);
    assert_eq!(p.topic_cooldown_secs, 86_400);
    assert_eq!(p.quiet_hours, None);
}

#[test]
fn two_per_rolling_day() {
    let p = NotifyPolicy::default();
    let now = t("2026-11-09T12:00:00Z");
    assert!(should_notify(&p, &[], "a", now));
    let h = hist(&[("a", now.minus_secs(H))]);
    assert!(should_notify(&p, &h, "b", now));
    let h = hist(&[("a", now.minus_secs(H)), ("b", now.minus_secs(2 * H))]);
    assert_eq!(evaluate(&p, &h, "c", now), NotifyDecision::DailyLimit);
    // Rolling window: once the older one is 24 h old, there is room again.
    let h = hist(&[("a", now.minus_secs(H)), ("b", now.minus_secs(24 * H))]);
    assert!(should_notify(&p, &h, "c", now));
    let h = hist(&[("a", now.minus_secs(H)), ("b", now.minus_secs(24 * H - 1))]);
    assert!(!should_notify(&p, &h, "c", now));
}

#[test]
fn per_topic_cooldown() {
    let p = NotifyPolicy {
        max_per_day: 10,
        ..NotifyPolicy::default()
    };
    let now = t("2026-11-09T12:00:00Z");
    let h = hist(&[("pnpm", now.minus_secs(23 * H))]);
    assert_eq!(evaluate(&p, &h, "pnpm", now), NotifyDecision::TopicCooldown);
    assert_eq!(
        evaluate(&p, &h, " PNPM ", now),
        NotifyDecision::TopicCooldown
    );
    assert!(should_notify(&p, &h, "yarn", now));
    let h = hist(&[("pnpm", now.minus_secs(25 * H))]);
    assert!(should_notify(&p, &h, "pnpm", now));
    let p0 = NotifyPolicy {
        max_per_day: 10,
        topic_cooldown_secs: 0,
        quiet_hours: None,
    };
    let h = hist(&[("pnpm", now.minus_secs(1))]);
    assert!(should_notify(&p0, &h, "pnpm", now));
}

#[test]
fn quiet_hours_wrapping_midnight_utc() {
    let p = NotifyPolicy {
        quiet_hours: Some(QuietHours::new(22, 7).unwrap()),
        ..NotifyPolicy::default()
    };
    for (time, quiet) in [
        ("2026-11-09T21:59:59Z", false),
        ("2026-11-09T22:00:00Z", true),
        ("2026-11-09T23:30:00Z", true),
        ("2026-11-10T00:00:00Z", true),
        ("2026-11-10T06:59:59Z", true),
        ("2026-11-10T07:00:00Z", false),
        ("2026-11-10T12:00:00Z", false),
    ] {
        let d = evaluate(&p, &[], "a", t(time));
        assert_eq!(d == NotifyDecision::QuietHours, quiet, "{time}");
    }
}

#[test]
fn quiet_hours_daytime_and_offset() {
    let q = QuietHours::new(9, 17).unwrap();
    assert!(q.contains(t("2026-11-09T09:00:00Z")));
    assert!(q.contains(t("2026-11-09T16:59:59Z")));
    assert!(!q.contains(t("2026-11-09T17:00:00Z")));
    assert!(!q.contains(t("2026-11-09T08:59:59Z")));

    // 22-07 local time at UTC+02:00: 20:30Z is 22:30 local (quiet), 05:00Z is 07:00 local.
    let q = QuietHours::new(22, 7)
        .unwrap()
        .with_utc_offset_minutes(120)
        .unwrap();
    assert!(q.contains(t("2026-11-09T20:30:00Z")));
    assert!(!q.contains(t("2026-11-09T19:59:59Z")));
    assert!(q.contains(t("2026-11-10T04:59:59Z")));
    assert!(!q.contains(t("2026-11-10T05:00:00Z")));
    // Negative offset: UTC-05:30, 03:29Z is 21:59 local.
    let q = QuietHours::new(22, 7)
        .unwrap()
        .with_utc_offset_minutes(-330)
        .unwrap();
    assert!(!q.contains(t("2026-11-10T03:29:00Z")));
    assert!(q.contains(t("2026-11-10T03:30:00Z")));
    // Works at the epoch boundary and before it.
    let q = QuietHours::new(23, 1).unwrap();
    assert!(q.contains(Timestamp::from_unix_seconds(-1).unwrap()));
    assert!(q.contains(Timestamp::from_unix_seconds(0).unwrap()));
}

#[test]
fn future_entries_count_and_zero_disables() {
    let p = NotifyPolicy::default();
    let now = t("2026-11-09T12:00:00Z");
    let h = hist(&[("a", now.plus_days(3)), ("b", now.plus_days(5))]);
    assert_eq!(evaluate(&p, &h, "c", now), NotifyDecision::DailyLimit);
    let off = NotifyPolicy {
        max_per_day: 0,
        ..NotifyPolicy::default()
    };
    assert_eq!(evaluate(&off, &[], "a", now), NotifyDecision::DailyLimit);
}

#[test]
fn quiet_hours_take_precedence() {
    let p = NotifyPolicy {
        quiet_hours: Some(QuietHours::new(0, 23).unwrap()),
        ..NotifyPolicy::default()
    };
    let now = t("2026-11-09T12:00:00Z");
    let h = hist(&[("a", now), ("b", now)]);
    assert_eq!(evaluate(&p, &h, "a", now), NotifyDecision::QuietHours);
    assert_eq!(NotifyDecision::QuietHours.as_str(), "quiet_hours");
}

proptest! {
    /// Simulating a caller that records every allowed notification: no rolling 24 h
    /// window ever holds more than `max_per_day`, and no topic repeats within the
    /// cooldown.
    #[test]
    fn simulated_caller_never_exceeds_limits(
        max in 0u32..5,
        cooldown in 0i64..200_000,
        steps in proptest::collection::vec((0i64..20_000, 0usize..4), 1..200),
    ) {
        let p = NotifyPolicy { max_per_day: max, topic_cooldown_secs: cooldown, quiet_hours: None };
        let topics = ["a", "b", "c", "d"];
        let mut now = Timestamp::from_unix_seconds(1_800_000_000).unwrap();
        let mut shown: Vec<(String, Timestamp)> = Vec::new();
        for (dt, ti) in steps {
            now = now.plus_secs(dt);
            let topic = topics[ti];
            if should_notify(&p, &shown, topic, now) {
                prop_assert!(shown.iter().filter(|(_, s)| now.secs_since(*s) < 86_400).count() < max as usize);
                if cooldown > 0 {
                    prop_assert!(!shown.iter().any(|(tp, s)| tp == topic && now.secs_since(*s) < cooldown));
                }
                shown.push((topic.to_owned(), now));
            }
        }
    }
}
