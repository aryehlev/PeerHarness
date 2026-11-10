//! Read authorization: which peers may receive which events (spec 5.3, 6.4; architecture
//! section 7).
//!
//! * QUESTION and ANSWER events, and decision events (PROPOSAL, VOTE, RESULT) with a
//!   scope other than `*`, are readable by a peer iff the oracle grants it `read` on the
//!   event scope in the event's circle at `now`.
//! * Control-plane events (MEMBERSHIP, REVOCATION, CHARTER) are readable by every
//!   **active member** of that circle (`oracle.is_active_member`), regardless of scope,
//!   so that revocations, memberships and the charter reach everyone who must enforce
//!   them.
//! * Decision events with scope `*` are readable by every active member too. A `*`
//!   proposal concerns the whole circle and its electorate is the whole roll
//!   (architecture section 10.3); every `amend` proposal is one. Members could not vote
//!   on what they cannot read.
//!
//! Use [`recipients_for_event`] (or [`recipients`]) to filter outgoing pushes and the
//! outbox, [`filter_readable`] to filter `FetchEvents` responses, and
//! [`may_fetch_bundle`] to gate `FetchBundle`. Authorization is evaluated on every call
//! (never cached), so a peer revoked or expired since the last request receives nothing
//! new. A majority vote can never widen read access: nothing here looks at votes.

use std::collections::HashSet;

use ph_core::{CircleId, DeviceKey, Digest, MembershipOracle, Scope, Timestamp};
use ph_protocol::SignedEnvelope;

use crate::views::ProposalView;

/// Whether `peer` may read objects with `scope` in `circle` at `now`
/// (`oracle.authorize_read(..).is_ok()`).
pub fn may_read(
    oracle: &dyn MembershipOracle,
    circle: &CircleId,
    peer: &DeviceKey,
    scope: &Scope,
    now: Timestamp,
) -> bool {
    oracle.authorize_read(circle, peer, scope, now).is_ok()
}

/// Whether `peer` may read `env` at `now`: control-plane events and circle-wide (`*`)
/// decision events need active membership in the event's circle, all others need
/// [`may_read`] on the event scope.
pub fn may_read_event(
    oracle: &dyn MembershipOracle,
    env: &SignedEnvelope,
    peer: &DeviceKey,
    now: Timestamp,
) -> bool {
    let t = env.event_type();
    if t.is_control_plane() || (t.is_decision() && env.scope.is_wildcard()) {
        oracle.is_active_member(&env.circle_id, peer, now)
    } else {
        may_read(oracle, &env.circle_id, peer, &env.scope, now)
    }
}

/// The candidates allowed to read a knowledge-plane object with `event_scope` in
/// `circle`, deduplicated, in first-seen order. For control-plane events use
/// [`recipients_for_event`].
pub fn recipients(
    event_scope: &Scope,
    circle: &CircleId,
    candidate_peers: &[DeviceKey],
    oracle: &dyn MembershipOracle,
    now: Timestamp,
) -> Vec<DeviceKey> {
    let mut seen = HashSet::new();
    candidate_peers
        .iter()
        .filter(|k| seen.insert(**k))
        .filter(|k| may_read(oracle, circle, k, event_scope, now))
        .copied()
        .collect()
}

/// The candidates allowed to read `env` (see [`may_read_event`]), deduplicated, in
/// first-seen order. The author is not excluded; the caller may skip it.
pub fn recipients_for_event(
    env: &SignedEnvelope,
    candidate_peers: &[DeviceKey],
    oracle: &dyn MembershipOracle,
    now: Timestamp,
) -> Vec<DeviceKey> {
    let mut seen = HashSet::new();
    candidate_peers
        .iter()
        .filter(|k| seen.insert(**k))
        .filter(|k| may_read_event(oracle, env, k, now))
        .copied()
        .collect()
}

/// For a `FetchEvents { circle_id }` request from `peer`: the events that belong to
/// `circle` **and** that `peer` may read, in input order. Events of other circles are
/// always dropped.
pub fn filter_readable<'a, I>(
    events: I,
    circle: &CircleId,
    peer: &DeviceKey,
    oracle: &dyn MembershipOracle,
    now: Timestamp,
) -> Vec<&'a SignedEnvelope>
where
    I: IntoIterator<Item = &'a SignedEnvelope>,
{
    events
        .into_iter()
        .filter(|e| &e.circle_id == circle && may_read_event(oracle, e, peer, now))
        .collect()
}

/// For a `FetchBundle { circle_id, digest }` request from `peer`: `true` iff one of the
/// stored `proposals` is an `adopt` proposal in `circle` with `bundle_digest == digest`
/// that `peer` may read now ([`may_read_event`]). The caller passes the stored proposals
/// with that digest (passing more is harmless).
pub fn may_fetch_bundle(
    circle: &CircleId,
    digest: &Digest,
    proposals: &[ProposalView],
    peer: &DeviceKey,
    oracle: &dyn MembershipOracle,
    now: Timestamp,
) -> bool {
    proposals.iter().any(|p| {
        &p.circle_id() == circle
            && p.bundle_digest().as_ref() == Some(digest)
            && may_read_event(oracle, p.envelope(), peer, now)
    })
}
