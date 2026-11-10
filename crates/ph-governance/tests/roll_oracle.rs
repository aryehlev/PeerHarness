//! The roll as the membership statement for the transport: who may connect and read.

mod common;

use common::*;
use ph_core::{Capability, CircleId, DenyReason, MembershipOracle};
use ph_governance::{may_read_event, RollOracle};
use ph_protocol::VoteDecision;

/// alice (1), bob (2, two devices: 2 and 12), carol (3, only `team/backend`).
fn charter() -> ph_protocol::Charter {
    founding(vec![
        entry("alice", &[1], &["*"]),
        entry("bob", &[2, 12], &["*"]),
        entry("carol", &[3], &["team/backend"]),
    ])
}

fn oracle() -> RollOracle {
    let mut o = RollOracle::new();
    o.set_charter(charter());
    o
}

#[test]
fn only_devices_on_the_roll_are_members() {
    let o = oracle();
    let c = circle();
    for seed in [1, 2, 12, 3] {
        assert!(o.is_active_member(&c, &pk(seed), now()), "{seed}");
    }
    // Not on the roll, and the root key itself: a notary, not a member.
    for seed in [9, ROOT] {
        assert!(!o.is_active_member(&c, &pk(seed), now()), "{seed}");
        assert_eq!(
            o.authorize(&c, &pk(seed), &scope("*"), Capability::Read, now()),
            Err(DenyReason::NotMember)
        );
    }
    // An unknown circle answers exactly like a stranger in a known one.
    let other = CircleId::derive(&pk(77));
    assert!(!o.is_active_member(&other, &pk(1), now()));
    assert_eq!(
        o.authorize(&other, &pk(1), &scope("*"), Capability::Read, now()),
        Err(DenyReason::NotMember)
    );
    assert!(RollOracle::new()
        .authorize(&c, &pk(1), &scope("*"), Capability::Read, now())
        .is_err());
}

#[test]
fn scopes_come_from_the_roll_entry_and_members_get_no_admin_power() {
    let o = oracle();
    let c = circle();
    assert!(o
        .authorize(&c, &pk(1), &scope("team/finance"), Capability::Read, now())
        .is_ok());
    assert!(o
        .authorize(&c, &pk(3), &scope("team/backend"), Capability::Read, now())
        .is_ok());
    assert!(o
        .authorize(
            &c,
            &pk(3),
            &scope("team/backend/api"),
            Capability::Vote,
            now()
        )
        .is_ok());
    for s in ["team/finance", "*", "team"] {
        assert_eq!(
            o.authorize(&c, &pk(3), &scope(s), Capability::Read, now()),
            Err(DenyReason::ScopeDenied),
            "{s}"
        );
    }
    // The roll has no owners: nobody on it may issue credentials or revoke.
    for cap in [Capability::Invite, Capability::Revoke] {
        assert_eq!(
            o.authorize(&c, &pk(1), &scope("*"), cap, now()),
            Err(DenyReason::CapabilityDenied)
        );
    }
}

#[test]
fn a_revoked_device_is_denied_and_removal_takes_effect_with_the_new_charter() {
    let c = circle();
    let mut o = oracle();
    o.revoke(c, pk(12));
    assert!(o.is_revoked(&c, &pk(12)));
    assert!(!o.is_active_member(&c, &pk(12), now()));
    assert_eq!(
        o.authorize(&c, &pk(12), &scope("*"), Capability::Read, now()),
        Err(DenyReason::Revoked)
    );
    // The member's other device is unaffected.
    assert!(o.is_active_member(&c, &pk(2), now()));

    // A new charter without carol: her device is a stranger from then on.
    let mut next = charter().content.clone();
    next.roll.retain(|e| e.member != "carol");
    let after = successor(
        &charter(),
        next,
        ph_core::EventId::from_digest(digest(b"r")),
    );
    o.set_charter(after);
    assert!(!o.is_active_member(&c, &pk(3), now()));
    assert!(o.is_active_member(&c, &pk(1), now()));
}

#[test]
fn shared_circles_need_both_sides_on_the_roll() {
    let o = oracle();
    assert_eq!(o.shared_circles(&pk(1), &pk(2)), vec![circle()]);
    assert_eq!(o.shared_circles(&pk(1), &pk(3)), vec![circle()]);
    assert!(o.shared_circles(&pk(1), &pk(9)).is_empty());
    assert!(o.shared_circles(&pk(9), &pk(1)).is_empty());
    let mut revoked = oracle();
    revoked.revoke(circle(), pk(2));
    assert!(revoked.shared_circles(&pk(1), &pk(2)).is_empty());
}

#[test]
fn the_read_rules_work_unchanged_on_top_of_the_roll() {
    let o = oracle();
    let ch = charter();
    // A circle-wide proposal and its ballots: every member, and nobody else.
    let wide = adopt(1, &ch, "*", digest(b"wide"));
    let ballot = vote(2, &wide, VoteDecision::Approve);
    for seed in [1, 2, 3] {
        assert!(may_read_event(&o, wide.envelope(), &pk(seed), now()));
        assert!(may_read_event(&o, ballot.envelope(), &pk(seed), now()));
    }
    assert!(!may_read_event(&o, wide.envelope(), &pk(9), now()));
    // A proposal scoped to another team: only members whose scopes cover it.
    let finance = adopt(1, &ch, "team/finance", digest(b"fin"));
    assert!(may_read_event(&o, finance.envelope(), &pk(2), now()));
    assert!(!may_read_event(&o, finance.envelope(), &pk(3), now()));
    let backend = adopt(1, &ch, "team/backend", digest(b"be"));
    assert!(may_read_event(&o, backend.envelope(), &pk(3), now()));
}
