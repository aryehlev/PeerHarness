//! `events`: the append-only log of validated signed events, plus sync queries.
//!
//! Events are immutable and keyed by `event_id`, which is the digest of their signed
//! content, so inserting the same event twice is a no-op ([`InsertOutcome::Duplicate`])
//! and never an error. This gives idempotent sync and replay rejection.

use std::collections::HashSet;
use std::fmt;

use ph_core::{CircleId, DeviceKey, Digest, EventId, Scope, Timestamp};
use ph_protocol::jcs::{parse_strict_str, ParseLimits};
use ph_protocol::limits::{MAX_FETCH_LIMIT, MAX_FRAME_BYTES};
use ph_protocol::{EventBody, EventType, ProposalAction, SignedEnvelope, VerifiedEnvelope};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;
use serde_json::Value;

use crate::error::{Result, StoreError};
use crate::peers::check_peer_id;
use crate::sql;
use crate::Store;

/// Default byte budget for one [`Store::missing_for_peer`] batch: the 512 KiB frame
/// limit minus 16 KiB for the response wrapper.
pub const DEFAULT_SYNC_MAX_BYTES: usize = MAX_FRAME_BYTES - 16 * 1024;

/// Result of inserting an event.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsertOutcome {
    /// The event was new and is now stored.
    Inserted,
    /// An event with the same id was already stored; nothing changed.
    Duplicate,
}

/// A stored event: indexed metadata plus the canonical envelope JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// Event id.
    pub event_id: EventId,
    /// Event type.
    pub event_type: EventType,
    /// Circle.
    pub circle_id: CircleId,
    /// Scope.
    pub scope: Scope,
    /// Author device key.
    pub author: DeviceKey,
    /// Author-claimed creation time (informational).
    pub created_at: Timestamp,
    /// Expiry.
    pub expires_at: Timestamp,
    /// When this node stored it.
    pub received_at: Timestamp,
    /// The peer it was received from (`None` for locally created events).
    pub origin_peer: Option<String>,
    /// Referenced event: `question_id` of an ANSWER, `proposal_id` of a VOTE or RESULT,
    /// `target` of a `repeal` PROPOSAL.
    pub ref_event_id: Option<EventId>,
    /// `bundle_digest` of an `adopt` PROPOSAL.
    pub bundle_digest: Option<Digest>,
    /// Canonical (JCS) JSON of the transmitted envelope.
    pub envelope_json: String,
}

impl fmt::Debug for StoredEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredEvent")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("circle_id", &self.circle_id)
            .field("author", &self.author)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("received_at", &self.received_at)
            .field("envelope_len", &self.envelope_json.len())
            .finish_non_exhaustive()
    }
}

impl StoredEvent {
    /// Parses the stored envelope (strict schema; the signature is not re-checked).
    pub fn envelope(&self) -> Result<SignedEnvelope> {
        SignedEnvelope::from_json_bytes(self.envelope_json.as_bytes()).map_err(|_| {
            StoreError::Corrupt {
                what: "event envelope",
            }
        })
    }

    /// The envelope as a JSON value, e.g. for `PushEvents` / `Events` wire messages.
    pub fn to_value(&self) -> Result<Value> {
        parse_strict_str(&self.envelope_json, ParseLimits::EVENT).map_err(|_| StoreError::Corrupt {
            what: "event envelope",
        })
    }
}

impl Serialize for StoredEvent {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let envelope: Value = serde_json::from_str(&self.envelope_json)
            .map_err(|_| serde::ser::Error::custom("stored event envelope is corrupt"))?;
        let mut st = s.serialize_struct("StoredEvent", 8)?;
        st.serialize_field("event_id", &self.event_id)?;
        st.serialize_field("type", &self.event_type.as_str())?;
        st.serialize_field("circle_id", &self.circle_id)?;
        st.serialize_field("scope", &self.scope)?;
        st.serialize_field("received_at", &self.received_at)?;
        st.serialize_field("origin_peer", &self.origin_peer)?;
        st.serialize_field("envelope", &envelope)?;
        st.end()
    }
}

/// Filter for [`Store::list_events`].
#[derive(Clone, Copy, Debug)]
pub struct EventFilter<'a> {
    /// Only these types (all types when empty).
    pub types: &'a [EventType],
    /// Only events whose scope is covered by one of these granted scopes
    /// (`Scope::covers`); `None` for no scope filter.
    pub readable_scopes: Option<&'a [Scope]>,
    /// Only events that have not expired at `t`: `expires_at > t`, or a permanent type
    /// (PROPOSAL, VOTE, RESULT, CHARTER, REVOCATION), which never expires. `None` to
    /// include expired events.
    pub not_expired_at: Option<Timestamp>,
    /// Maximum number of events returned.
    pub limit: usize,
}

impl Default for EventFilter<'_> {
    fn default() -> Self {
        Self {
            types: &[],
            readable_scopes: None,
            not_expired_at: None,
            limit: usize::MAX,
        }
    }
}

/// Parameters of [`Store::missing_for_peer`].
#[derive(Clone, Copy, Debug)]
pub struct MissingQuery<'a> {
    /// Circle being synchronized.
    pub circle_id: &'a CircleId,
    /// Event ids the peer already has (from `FetchEvents.known`).
    pub known: &'a HashSet<EventId>,
    /// Local time; expiring events (QUESTION, ANSWER, MEMBERSHIP) with
    /// `expires_at <= now` are never returned. Permanent events always are.
    pub now: Timestamp,
    /// Maximum number of events (clamped to `MAX_FETCH_LIMIT`).
    pub limit: usize,
    /// Maximum total size of the returned envelopes' JSON, in bytes (plus one byte per
    /// event for the separating comma). At least one event is returned if any is
    /// eligible.
    pub max_bytes: usize,
}

impl<'a> MissingQuery<'a> {
    /// A query with `limit = MAX_FETCH_LIMIT` and `max_bytes = DEFAULT_SYNC_MAX_BYTES`.
    pub fn new(circle_id: &'a CircleId, known: &'a HashSet<EventId>, now: Timestamp) -> Self {
        Self {
            circle_id,
            known,
            now,
            limit: MAX_FETCH_LIMIT as usize,
            max_bytes: DEFAULT_SYNC_MAX_BYTES,
        }
    }

    /// Sets [`Self::limit`] (for example the requester's `FetchEvents.limit`).
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Sets [`Self::max_bytes`].
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

/// Result of [`Store::missing_for_peer`].
#[derive(Clone, Debug, Default)]
pub struct MissingEvents {
    /// Events to send, in `(created_at, event_id)` order.
    pub events: Vec<StoredEvent>,
    /// Whether more eligible events exist beyond this batch.
    pub more: bool,
}

const COLS: &str = "event_id, type, circle_id, scope, author, created_at, expires_at, \
                    received_at, origin_peer, ref_event_id, bundle_digest, envelope_json";

fn row(r: &Row<'_>) -> rusqlite::Result<StoredEvent> {
    Ok(StoredEvent {
        event_id: sql::parse(r, 0, "event id")?,
        event_type: sql::parse(r, 1, "event type")?,
        circle_id: sql::parse(r, 2, "circle id")?,
        scope: sql::parse(r, 3, "scope")?,
        author: sql::parse(r, 4, "author key")?,
        created_at: sql::ts(r, 5)?,
        expires_at: sql::ts(r, 6)?,
        received_at: sql::ts(r, 7)?,
        origin_peer: r.get(8)?,
        ref_event_id: sql::parse_opt(r, 9, "event id")?,
        bundle_digest: sql::parse_opt(r, 10, "digest")?,
        envelope_json: r.get(11)?,
    })
}

fn refs(body: &EventBody) -> (Option<EventId>, Option<Digest>) {
    match body {
        EventBody::Answer(b) => (Some(b.question_id), None),
        EventBody::Proposal(b) => match &b.action {
            ProposalAction::Adopt(a) => (None, Some(a.bundle_digest)),
            ProposalAction::Repeal { target } => (Some(*target), None),
            ProposalAction::Amend { .. } => (None, None),
        },
        EventBody::Vote(b) => (Some(b.proposal_id), None),
        EventBody::Result(b) => (Some(b.proposal_id), None),
        EventBody::Question(_)
        | EventBody::Charter(_)
        | EventBody::Membership(_)
        | EventBody::Revocation(_) => (None, None),
    }
}

/// SQL condition "this event has not expired at the bound time parameter `param`":
/// its `expires_at` is later, or its type is permanent (architecture section 10.11:
/// decision events, CHARTER and REVOCATION never expire). The type list is derived from
/// [`EventType::is_permanent`] so it cannot drift.
fn not_expired_sql(param: &str) -> String {
    let permanent: Vec<String> = EventType::ALL
        .into_iter()
        .filter(|t| t.is_permanent())
        .map(|t| format!("'{}'", t.as_str()))
        .collect();
    format!(
        "(expires_at > {param} OR type IN ({}))",
        permanent.join(", ")
    )
}

impl Store {
    /// Stores an event that passed `ph_protocol::validate_stateless` (and the caller's
    /// stateful authorization). `origin_peer` is the `PeerId` it came from.
    ///
    /// Returns [`InsertOutcome::Duplicate`] (never an error) if the id is already stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReference`] if the circle is not stored,
    /// [`StoreError::Invalid`] for a malformed `origin_peer`.
    pub fn insert_event(
        &self,
        env: &VerifiedEnvelope,
        origin_peer: Option<&str>,
        received_at: Timestamp,
    ) -> Result<InsertOutcome> {
        self.insert_envelope(
            env.envelope(),
            env.canonical_json(),
            origin_peer,
            received_at,
        )
    }

    /// Stores a signed envelope that has not been through `validate_stateless`, typically
    /// one this node just created and signed.
    ///
    /// Before anything is written the envelope gets every time-independent check of
    /// `validate_stateless`: the strict schema and size limits (canonical JSON at most
    /// `MAX_EVENT_BYTES`, typed body bounds, exact round trip), the author/body
    /// bindings, and the signature and `event_id`. So every stored event can be parsed
    /// back and fits a sync frame. Time rules and authorization stay the caller's
    /// business.
    ///
    /// # Errors
    ///
    /// As [`Store::insert_event`], plus [`StoreError::Protocol`] for a bad signature,
    /// an oversized envelope or a schema violation.
    pub fn insert_signed_event(
        &self,
        env: &SignedEnvelope,
        origin_peer: Option<&str>,
        received_at: Timestamp,
    ) -> Result<InsertOutcome> {
        let json = env.to_canonical_json()?;
        // Re-parse the exact bytes we are about to store with the wire parser: this
        // applies the size/depth limits and the strict schema that a peer (and
        // `StoredEvent::envelope`) will apply to them later.
        let parsed = SignedEnvelope::from_json_bytes(json.as_bytes())?;
        parsed.check_bindings()?;
        parsed.verify_signature()?;
        self.insert_envelope(&parsed, &json, origin_peer, received_at)
    }

    /// Stores a locally created event and queues it for each of `peer_ids`, atomically
    /// (architecture section 1: events go to the log and the outbox first). Returns the
    /// insert outcome; outbox rows are added even on [`InsertOutcome::Duplicate`].
    pub fn insert_local_event_with_outbox<I, S>(
        &self,
        env: &SignedEnvelope,
        peer_ids: I,
        now: Timestamp,
    ) -> Result<InsertOutcome>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let tx = self.tx()?;
        let outcome = self.insert_signed_event(env, None, now)?;
        for p in peer_ids {
            self.enqueue_outbox(&env.event_id, p.as_ref(), now)?;
        }
        tx.commit()?;
        Ok(outcome)
    }

    fn insert_envelope(
        &self,
        env: &SignedEnvelope,
        canonical_json: &str,
        origin_peer: Option<&str>,
        received_at: Timestamp,
    ) -> Result<InsertOutcome> {
        if let Some(p) = origin_peer {
            check_peer_id(p)?;
        }
        let (ref_id, bundle) = refs(&env.body);
        let n = self.conn.execute(
            &format!(
                "INSERT INTO events ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(event_id) DO NOTHING"
            ),
            params![
                env.event_id.to_string(),
                env.event_type().as_str(),
                env.circle_id.to_string(),
                env.scope.as_str(),
                env.author.to_string(),
                env.created_at.unix_seconds(),
                env.expires_at.unix_seconds(),
                received_at.unix_seconds(),
                origin_peer,
                ref_id.as_ref().map(ToString::to_string),
                bundle.as_ref().map(ToString::to_string),
                canonical_json
            ],
        )?;
        let outcome = if n == 1 {
            InsertOutcome::Inserted
        } else {
            InsertOutcome::Duplicate
        };
        tracing::debug!(event = %env.event_id, ty = env.event_type().as_str(), ?outcome, "event insert");
        Ok(outcome)
    }

    /// The event with this id.
    pub fn event(&self, id: &EventId) -> Result<Option<StoredEvent>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM events WHERE event_id = ?1"),
                [id.to_string()],
                row,
            )
            .optional()?)
    }

    /// Whether an event with this id is stored.
    pub fn has_event(&self, id: &EventId) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1)",
            [id.to_string()],
            |r| r.get(0),
        )?)
    }

    /// Events of a circle matching `filter`, newest first by `(created_at, event_id)`.
    pub fn list_events(
        &self,
        circle: &CircleId,
        filter: &EventFilter<'_>,
    ) -> Result<Vec<StoredEvent>> {
        let mut where_sql = String::from("circle_id = ?");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(circle.to_string())];
        if !filter.types.is_empty() {
            where_sql.push_str(&format!(
                " AND type IN ({})",
                sql::placeholders(filter.types.len())
            ));
            for t in filter.types {
                args.push(Box::new(t.as_str()));
            }
        }
        if let Some(t) = filter.not_expired_at {
            where_sql.push_str(&format!(" AND {}", not_expired_sql("?")));
            args.push(Box::new(t.unix_seconds()));
        }
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM events WHERE {where_sql} ORDER BY created_at DESC, event_id DESC"
        ))?;
        let mut rows = st.query(rusqlite::params_from_iter(args.iter().map(|b| b.as_ref())))?;
        let mut out = Vec::new();
        while out.len() < filter.limit {
            let Some(r) = rows.next()? else { break };
            let ev = row(r)?;
            if let Some(granted) = filter.readable_scopes {
                if !Scope::any_covers(granted, &ev.scope) {
                    continue;
                }
            }
            out.push(ev);
        }
        Ok(out)
    }

    fn events_where(&self, cond: &str, args: impl rusqlite::Params) -> Result<Vec<StoredEvent>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM events WHERE {cond} ORDER BY created_at, event_id"
        ))?;
        let rows = st
            .query_map(args, row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Ids of a circle's events that have not expired at `now` (permanent events never
    /// do), oldest first: the `known` set this node sends in `FetchEvents`.
    pub fn event_ids_for_circle(&self, circle: &CircleId, now: Timestamp) -> Result<Vec<EventId>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT event_id FROM events WHERE circle_id = ?1 AND {}
             ORDER BY created_at, event_id",
            not_expired_sql("?2")
        ))?;
        let ids = st
            .query_map(params![circle.to_string(), now.unix_seconds()], |r| {
                sql::parse(r, 0, "event id")
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    /// The events a peer is missing, for answering `FetchEvents` (architecture 7).
    ///
    /// Returns unexpired events of `q.circle_id` (never of another circle) that are not
    /// in `q.known` and are readable by the requester. Permanent events (PROPOSAL, VOTE,
    /// RESULT, CHARTER, REVOCATION) never count as expired, so a node that joins later
    /// can still fetch the circle's decisions. An event is readable when
    ///
    /// * it is a control-plane event (MEMBERSHIP, REVOCATION, CHARTER), or
    /// * it is a decision event with scope `*`, which concerns every member
    ///   (architecture section 10.3; every `amend` proposal and its ballots), or
    /// * `readable` returns `true` for its scope. `readable` is where the caller applies
    ///   the requester's credential (for example
    ///   `|s| oracle.authorize_read(&circle, &requester, s, now).is_ok()`).
    ///
    /// Ordered by `(created_at, event_id)`; bounded by `q.limit` and `q.max_bytes`;
    /// `more` reports whether further eligible events remain.
    ///
    /// # Security precondition
    ///
    /// Control-plane events carry the circle's member list (subject keys, roles,
    /// scopes, and the charter's roll), and they and circle-wide decision events are
    /// returned **regardless of `readable`**. The caller must therefore
    /// first establish that the requester is an active member of `q.circle_id` (for
    /// example `oracle.is_active_member(&circle, &requester, now)`) and answer
    /// `Error{unauthorized}` otherwise, without calling this method. A deny-all
    /// `readable` is **not** a substitute for that check.
    pub fn missing_for_peer(
        &self,
        q: &MissingQuery<'_>,
        readable: impl Fn(&Scope) -> bool,
    ) -> Result<MissingEvents> {
        let limit = q.limit.min(MAX_FETCH_LIMIT as usize);
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM events WHERE circle_id = ?1 AND {}
             ORDER BY created_at, event_id",
            not_expired_sql("?2")
        ))?;
        let mut rows = st.query(params![q.circle_id.to_string(), q.now.unix_seconds()])?;
        let mut out = MissingEvents::default();
        let mut bytes = 0usize;
        while let Some(r) = rows.next()? {
            // Cheap pre-check on the id before decoding the whole row.
            let id: EventId = sql::parse(r, 0, "event id")?;
            if q.known.contains(&id) {
                continue;
            }
            let ev = row(r)?;
            let for_every_member = ev.event_type.is_control_plane()
                || (ev.event_type.is_decision() && ev.scope.is_wildcard());
            if !(for_every_member || readable(&ev.scope)) {
                continue;
            }
            let size = ev.envelope_json.len() + 1;
            if out.events.len() >= limit
                || (!out.events.is_empty() && bytes.saturating_add(size) > q.max_bytes)
            {
                out.more = true;
                break;
            }
            bytes = bytes.saturating_add(size);
            out.events.push(ev);
        }
        tracing::debug!(
            count = out.events.len(),
            more = out.more,
            "missing_for_peer"
        );
        Ok(out)
    }

    /// VOTE events referencing `proposal_id` **in the proposal's own circle**, oldest
    /// first. Empty while the PROPOSAL itself is not stored. A VOTE published in another
    /// circle that names this proposal is never returned. Callers must still count them
    /// against the roll of the charter the proposal names (ph-governance `tally`).
    pub fn votes_for_proposal(&self, proposal_id: &EventId) -> Result<Vec<StoredEvent>> {
        self.referencing(proposal_id, EventType::Vote, EventType::Proposal)
    }

    /// ANSWER events referencing `question_id` in the question's own circle, oldest
    /// first. Empty while the QUESTION event is not stored.
    pub fn answers_for_question(&self, question_id: &EventId) -> Result<Vec<StoredEvent>> {
        self.referencing(question_id, EventType::Answer, EventType::Question)
    }

    /// RESULT events referencing `proposal_id` in the proposal's own circle, oldest
    /// first. Empty while the PROPOSAL is not stored. A RESULT carries no authority; it
    /// must be verified against the ballots it lists (ph-governance `verify_result`).
    pub fn results_for_proposal(&self, proposal_id: &EventId) -> Result<Vec<StoredEvent>> {
        self.referencing(proposal_id, EventType::Result, EventType::Proposal)
    }

    /// `repeal` PROPOSAL events targeting the `adopt` proposal `target`, in the target's
    /// own circle, oldest first. Empty while the target is not stored.
    pub fn repeals_of(&self, target: &EventId) -> Result<Vec<StoredEvent>> {
        self.referencing(target, EventType::Proposal, EventType::Proposal)
    }

    /// Events of type `ty` whose `ref_event_id` is `target`, restricted to the circle of
    /// the stored `target` event, which must have type `target_ty`.
    fn referencing(
        &self,
        target: &EventId,
        ty: EventType,
        target_ty: EventType,
    ) -> Result<Vec<StoredEvent>> {
        self.events_where(
            "ref_event_id = ?1 AND type = ?2 AND circle_id =
                 (SELECT t.circle_id FROM events t WHERE t.event_id = ?1 AND t.type = ?3)",
            params![target.to_string(), ty.as_str(), target_ty.as_str()],
        )
    }

    /// PROPOSAL events of a circle, oldest first.
    pub fn proposals(&self, circle: &CircleId) -> Result<Vec<StoredEvent>> {
        self.events_where("circle_id = ?1 AND type = 'PROPOSAL'", [circle.to_string()])
    }

    /// `adopt` PROPOSAL events of a circle with this bundle digest (for `FetchBundle`
    /// authorization), oldest first.
    pub fn proposals_with_bundle(
        &self,
        circle: &CircleId,
        digest: &Digest,
    ) -> Result<Vec<StoredEvent>> {
        self.events_where(
            "circle_id = ?1 AND bundle_digest = ?2 AND type = 'PROPOSAL'",
            params![circle.to_string(), digest.to_string()],
        )
    }

    /// Number of events stored for a circle.
    pub fn event_count(&self, circle: &CircleId) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE circle_id = ?1",
            [circle.to_string()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Every stored event, oldest first (for export).
    pub fn all_events(&self) -> Result<Vec<StoredEvent>> {
        self.events_where("1 = 1", [])
    }
}
