//! Local event creation and the membership registry, shared by every command and the
//! daemon.
//!
//! Signed events are always written to the local event log and the outbox first
//! (architecture section 1), so they reach peers later even if no daemon is running.
// The outbox helpers here are for the network daemon, which is not wired into the CLI yet.
#![allow(dead_code)]
use anyhow::{Context, Result};
use ph_core::{CircleId, DeviceKey, EventId, Scope, Timestamp};
use ph_identity::MembershipRegistry;
use ph_protocol::{EnvelopeBuilder, EventBody, SignedEnvelope, SigningKey};
use ph_store::{InsertOutcome, Store};

use crate::node::Node;

/// Rebuilds the membership registry from the store (daemon startup order):
///
/// 1. `add_circle` for each stored circle;
/// 2. `add_stored_proof` for every accepted membership (expired ones included; they
///    never authorize);
/// 3. `add_revocation` for each stored revocation;
/// 4. `note_invite_issuer` for every non-blocked peer linked to the circle in
///    `peer_circles` (for a joined circle this is the invite issuer; for a founded
///    circle these are invited peers) and every invitee of an issued invite. This only
///    affects `is_plausible_member`/`proofs_to_present` (whom we present our own proofs
///    to); it never grants authorization.
///
/// Entries that fail verification are skipped and logged by count only.
pub fn build_registry(store: &Store, now: Timestamp) -> ph_store::Result<MembershipRegistry> {
    let mut reg = MembershipRegistry::new();
    let mut rejected = 0usize;
    let circles = store.circles()?;
    for c in &circles {
        if reg.add_circle(c.circle_id, c.root_key).is_err() {
            rejected += 1;
        }
    }
    for proof in store.all_membership_proofs()? {
        if reg.add_stored_proof(proof, now).is_err() {
            rejected += 1;
        }
    }
    for r in store.all_revocations()? {
        if reg.add_revocation(r.revocation, now).is_err() {
            rejected += 1;
        }
    }
    for c in &circles {
        for p in store.peers_for_circle(&c.circle_id)? {
            if !p.blocked {
                let _ = reg.note_invite_issuer(&c.circle_id, p.device_key);
            }
        }
        for inv in store.issued_invites(Some(&c.circle_id))? {
            let _ = reg.note_invite_issuer(&c.circle_id, inv.invitee_key);
        }
    }
    if rejected > 0 {
        tracing::warn!(
            rejected,
            "skipped stored membership entries that failed verification"
        );
    }
    tracing::debug!(circles = circles.len(), "membership registry rebuilt");
    Ok(reg)
}

/// Options for [`sign_and_store_event_with`].
#[derive(Clone, Debug, Default)]
pub struct EventOptions {
    /// Explicit expiry (default: the type's default lifetime; MEMBERSHIP: the credential
    /// expiry).
    pub expires_at: Option<Timestamp>,
    /// Peer ids to queue to in addition to the authorized recipients (for example the
    /// invite issuer for our own MEMBERSHIP, whose credential we do not know yet).
    pub extra_recipients: Vec<String>,
}

/// The result of storing a local event.
#[derive(Clone, Debug)]
pub struct LocalEvent {
    pub event_id: EventId,
    pub outcome: InsertOutcome,
    /// Peer ids the event was queued to.
    pub recipients: Vec<String>,
}

/// Builds and signs an envelope with `signer` as the author.
pub fn sign_envelope(
    signer: &SigningKey,
    circle: &CircleId,
    scope: &Scope,
    body: EventBody,
    expires_at: Option<Timestamp>,
    now: Timestamp,
) -> Result<SignedEnvelope> {
    let mut b = EnvelopeBuilder::new(*circle, scope.clone(), body);
    if let Some(t) = expires_at {
        b = b.expires_at(t);
    }
    b.sign(signer, now).context("cannot sign the event")
}

/// Peer ids that may currently receive `env`: non-blocked peers linked to the circle
/// whose device key passes `ph_governance::recipients_for_event` against the registry
/// rebuilt from `store` (so revocations and expiry apply), excluding `me` and the
/// author.
pub fn authorized_recipients(
    store: &Store,
    env: &SignedEnvelope,
    me: &DeviceKey,
    now: Timestamp,
) -> ph_store::Result<Vec<String>> {
    let reg = build_registry(store, now)?;
    let peers: Vec<_> = store
        .peers_for_circle(&env.circle_id)?
        .into_iter()
        .filter(|p| !p.blocked && p.device_key != *me && p.device_key != env.author)
        .collect();
    let keys: Vec<DeviceKey> = peers.iter().map(|p| p.device_key).collect();
    let allowed = ph_governance::recipients_for_event(env, &keys, &reg, now);
    Ok(peers
        .into_iter()
        .filter(|p| allowed.contains(&p.device_key))
        .map(|p| p.peer_id)
        .collect())
}

/// Inserts a locally created, signed event into the log and queues it in the outbox for
/// every currently authorized recipient (plus `extra` peers), in one transaction.
pub fn store_local_event(
    store: &Store,
    env: &SignedEnvelope,
    me: &DeviceKey,
    extra: &[String],
    now: Timestamp,
) -> ph_store::Result<LocalEvent> {
    store.transaction(|s| {
        let mut recipients = authorized_recipients(s, env, me, now)?;
        for p in extra {
            if !recipients.contains(p) {
                recipients.push(p.clone());
            }
        }
        let outcome = s.insert_local_event_with_outbox(env, &recipients, now)?;
        Ok(LocalEvent {
            event_id: env.event_id,
            outcome,
            recipients,
        })
    })
}

/// Signs `body` with this node's device key, stores it and queues it to every currently
/// authorized recipient peer. Unlocks the device key if needed.
pub fn sign_and_store_local_event(
    node: &Node,
    circle: &CircleId,
    scope: &Scope,
    body: EventBody,
) -> Result<EventId> {
    let dev = node.device()?;
    Ok(sign_and_store_event_with(
        node,
        dev.signing_key(),
        circle,
        scope,
        body,
        EventOptions::default(),
    )?
    .event_id)
}

/// Like [`sign_and_store_local_event`] with an explicit signer (the circle root key for
/// REVOCATION, ADR-010) and options.
pub fn sign_and_store_event_with(
    node: &Node,
    signer: &SigningKey,
    circle: &CircleId,
    scope: &Scope,
    body: EventBody,
    opts: EventOptions,
) -> Result<LocalEvent> {
    let now = node.now();
    let env = sign_envelope(signer, circle, scope, body, opts.expires_at, now)?;
    let ev = store_local_event(
        &node.store,
        &env,
        &node.device_key(),
        &opts.extra_recipients,
        now,
    )
    .context("cannot store the event")?;
    tracing::info!(
        event_id = %ev.event_id,
        event_type = env.event_type().as_str(),
        recipients = ev.recipients.len(),
        "local event stored"
    );
    Ok(ev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ph_identity::{accept_credential, CircleAuthority, DeviceIdentity};
    use ph_protocol::MembershipBody;
    use ph_store::{CircleRow, InsertOutcome};

    fn circle_row(auth: &CircleAuthority, now: Timestamp) -> CircleRow {
        CircleRow {
            circle_id: auth.circle_id(),
            name: "team".into(),
            root_key: auth.root_key(),
            is_founder: true,
            root_keystore_ref: None,
            adoption_mode: "ask".into(),
            accepted_charter: None,
            created_at: now,
        }
    }

    #[test]
    fn membership_event_queues_only_to_active_members() {
        let now = Timestamp::now();
        let store = Store::open_in_memory().unwrap();
        let root = SigningKey::from_bytes(&[7; 32]);
        let auth = CircleAuthority::from_signing_key(root);
        let me = DeviceIdentity::from_signing_key(SigningKey::from_bytes(&[8; 32]));
        let bob = DeviceIdentity::from_signing_key(SigningKey::from_bytes(&[9; 32]));
        let carol = DeviceIdentity::from_signing_key(SigningKey::from_bytes(&[10; 32]));
        store.insert_circle(&circle_row(&auth, now)).unwrap();
        let circle = auth.circle_id();

        // me (founder) and bob are active; carol is only invited (no acceptance).
        let mine = accept_credential(
            &auth.issue_founder_credential(me.public(), now).unwrap(),
            &me,
            now,
        )
        .unwrap();
        store.upsert_membership_proof(&mine, true, now).unwrap();
        let bob_cred = auth
            .issue_credential(
                bob.public(),
                vec![ph_core::Role::Member],
                vec![Scope::all()],
                3600,
                now,
            )
            .unwrap();
        let bob_proof = accept_credential(&bob_cred, &bob, now).unwrap();
        store
            .upsert_membership_proof(&bob_proof, false, now)
            .unwrap();
        let carol_cred = auth
            .issue_credential(
                carol.public(),
                vec![ph_core::Role::Member],
                vec![Scope::all()],
                3600,
                now,
            )
            .unwrap();
        store
            .upsert_membership(&carol_cred, None, false, now)
            .unwrap();
        for (d, _) in [(&bob, 0), (&carol, 1)] {
            let pid = ph_network::peer_id_from_device_key(&d.public()).to_string();
            store.upsert_peer(&pid, &d.public(), &[], now).unwrap();
            store.add_peer_circle(&pid, &circle).unwrap();
        }

        let body = EventBody::Membership(MembershipBody {
            credential: mine.credential.clone(),
            acceptance: mine.acceptance.clone(),
        });
        let env = sign_envelope(me.signing_key(), &circle, &Scope::all(), body, None, now).unwrap();
        let ev = store_local_event(&store, &env, &me.public(), &[], now).unwrap();
        assert_eq!(ev.outcome, InsertOutcome::Inserted);
        let bob_pid = ph_network::peer_id_from_device_key(&bob.public()).to_string();
        assert_eq!(ev.recipients, vec![bob_pid.clone()]);
        assert_eq!(store.pending_outbox_count().unwrap(), 1);

        // Idempotent: a duplicate insert is reported, no new outbox rows.
        let again = store_local_event(&store, &env, &me.public(), &[], now).unwrap();
        assert_eq!(again.outcome, InsertOutcome::Duplicate);
        assert_eq!(store.pending_outbox_count().unwrap(), 1);

        // After revoking bob, nothing new is queued to him.
        let rev = auth.issue_revocation(bob.public(), "", now).unwrap();
        store.insert_revocation(&rev, now).unwrap();
        let reg = build_registry(&store, now).unwrap();
        assert!(reg.is_revoked(&circle, &bob.public()));
        let body = EventBody::Revocation(ph_protocol::RevocationBody { revocation: rev });
        let env2 =
            sign_envelope(auth.signing_key(), &circle, &Scope::all(), body, None, now).unwrap();
        let ev2 = store_local_event(&store, &env2, &me.public(), &[], now).unwrap();
        assert!(ev2.recipients.is_empty());
    }
}
