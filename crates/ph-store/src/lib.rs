//! # ph-store
//!
//! The PeerHarness local database (architecture section 8, spec section 10): one SQLite
//! file per node (`$PEERHARNESS_HOME/peerharness.db`), opened through [`Store`], with
//! forward-only migrations and typed repository methods for every table.
//!
//! * Engine: `rusqlite` with bundled SQLite (ADR-009). No other database engine.
//! * Pragmas: `journal_mode=WAL`, `foreign_keys=ON`, `synchronous=NORMAL`,
//!   `busy_timeout` ([`DEFAULT_BUSY_TIMEOUT_MS`] unless opened with
//!   [`Store::open_with_busy_timeout`]).
//! * Concurrency: a [`Store`] owns one connection and is `Send` but not `Sync`. Open one
//!   per thread/task/process. Every multi-step write runs in a `BEGIN IMMEDIATE`
//!   transaction; [`Store::transaction`] groups several calls atomically (nested calls
//!   become savepoints).
//! * Encoding: timestamps are stored as Unix seconds, keys/digests/ids/scopes as their
//!   canonical strings, signed protocol objects as canonical (JCS) JSON text.
//! * Integrity: the store verifies cheap, time-independent invariants (credential and
//!   revocation signatures, acceptance binding, bundle digest vs. manifest, circle id
//!   vs. root key, charter signatures and chain links, envelope signatures for
//!   [`Store::insert_signed_event`]). It does
//!   **not** authorize anything: time rules, membership, scope, capability and
//!   revocation checks belong to ph-protocol / ph-identity / ph-governance and must run
//!   before data is stored or served.
//!
//! ## Privacy
//!
//! * The database never stores private key bytes; keystore rows hold references only.
//! * Observations are local-only; nothing in this crate sends anything anywhere.
//! * [`StoreError`] `Display` never contains stored or supplied content, and `Debug` of
//!   rows carrying free text (observations, candidates, questions, events, circle names)
//!   prints lengths instead. `tracing` events carry ids and counts only.
//!
//! ## Table map
//!
//! | table | methods |
//! |---|---|
//! | `identity_metadata` | [`Store::identity`], [`Store::set_identity`] |
//! | `circles` | [`Store::insert_circle`], [`Store::circle`], [`Store::circle_by_name`], [`Store::circles`], [`Store::set_circle_adoption`] |
//! | `charters` | [`Store::insert_charter`], [`Store::insert_charter_history`], [`Store::current_charter`], [`Store::oldest_charter`], [`Store::charter_by_digest`], [`Store::charters`] |
//! | `rule_optouts` | [`Store::set_rule_opt_out`], [`Store::clear_rule_opt_out`], [`Store::is_rule_opted_out`], [`Store::rule_opt_outs`] |
//! | `rule_installs` | [`Store::record_rule_install`], [`Store::clear_rule_install`], [`Store::rule_installs`] |
//! | `memberships` | [`Store::upsert_membership_proof`], [`Store::upsert_membership`], [`Store::membership`], [`Store::memberships_for_circle`], [`Store::memberships_for_subject`], [`Store::self_membership`], [`Store::self_membership_proofs`], [`Store::all_membership_proofs`] |
//! | `issued_invites` | [`Store::insert_issued_invite`], [`Store::issued_invites`] |
//! | `revocations` | [`Store::insert_revocation`], [`Store::revocations_for_circle`], [`Store::all_revocations`], [`Store::revocation`], [`Store::is_revoked`], [`Store::revocation_epoch`] |
//! | `peers`, `peer_circles` | [`Store::upsert_peer`], [`Store::add_peer_circle`], [`Store::remove_peer_circle`], [`Store::peer`], [`Store::peer_by_device_key`], [`Store::peers`], [`Store::peers_for_circle`], [`Store::set_peer_blocked`], [`Store::set_peer_muted`], [`Store::touch_peer_last_seen`] |
//! | `observations` | [`Store::insert_observation`], [`Store::observation`], [`Store::recent_observations`], [`Store::purge_expired_observations`], [`Store::observation_count`] |
//! | `candidates` | [`Store::insert_or_merge_candidate`], [`Store::candidate`], [`Store::candidate_by_concept`], [`Store::candidates`], [`Store::update_candidate_status`], `set_candidate_*` |
//! | `questions` | [`Store::insert_question`], [`Store::question`], [`Store::inbox`], [`Store::local_questions`], [`Store::set_question_status`], [`Store::count_questions_by_author_since`], [`Store::count_questions_by_circle_since`], [`Store::question_text_exists`] |
//! | `events` | [`Store::insert_event`], [`Store::insert_signed_event`], [`Store::insert_local_event_with_outbox`], [`Store::event`], [`Store::list_events`], [`Store::event_ids_for_circle`], [`Store::missing_for_peer`], [`Store::votes_for_proposal`], [`Store::proposals`], [`Store::proposals_with_bundle`], [`Store::answers_for_question`], [`Store::results_for_proposal`], [`Store::repeals_of`] |
//! | `outbox` | [`Store::enqueue_outbox`], [`Store::pending_for_peer`], [`Store::mark_delivered`], [`Store::bump_outbox_attempts`], [`Store::pending_outbox_count`], [`Store::peers_with_pending`], [`Store::drop_expired_outbox`] |
//! | `bundles` | [`Store::insert_bundle`], [`Store::bundle`], [`Store::bundles`] |
//! | `skills` | [`Store::insert_skill`], [`Store::skill`], [`Store::skill_by_name`], [`Store::skills_by_name`], [`Store::skills`], [`Store::set_skill_status`] |
//! | `installations` | [`Store::record_install`], [`Store::active_installation`], [`Store::active_installation_at`], [`Store::active_installations`], [`Store::mark_installation_removed`], [`Store::installation_history`] |
//! | `sync_cursors` | [`Store::sync_cursor`], [`Store::set_sync_cursor`], [`Store::sync_cursors`] |
//! | `notifications` | [`Store::record_notification`], [`Store::count_notifications_since`], [`Store::last_notification_for_topic`], [`Store::purge_notifications_before`] |
//! | all | [`Store::export_owned_json`] |
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod candidates;
pub mod charters;
pub mod circles;
pub mod error;
pub mod events;
pub mod identity;
pub mod membership;
pub mod misc;
pub mod observations;
pub mod outbox;
pub mod peers;
pub mod questions;
mod schema;
pub mod skills;
mod sql;
mod store;
mod tx;

pub use candidates::{
    CandidateId, CandidateRow, MAX_CANDIDATE_EVIDENCE, MAX_CANDIDATE_TEXT_BYTES,
    MAX_SKILL_DRAFT_BYTES,
};
pub use circles::{check_circle_name, CircleRow, ADOPTION_MODES};
pub use error::{Result, StoreError};
pub use events::{
    EventFilter, InsertOutcome, MissingEvents, MissingQuery, StoredEvent, DEFAULT_SYNC_MAX_BYTES,
};
pub use identity::{check_keystore_ref, IdentityMetadata, MAX_KEYSTORE_REF_BYTES};
pub use membership::{
    IssuedInviteRow, MembershipRow, RevocationInsert, RevocationRow, UpsertOutcome,
};
pub use misc::{NotificationRow, SyncCursor, EXPORT_SCHEMA};
pub use observations::{
    default_observation_expiry, StoredObservation, DEFAULT_OBSERVATION_RETENTION_DAYS,
    MAX_REPO_KEY_BYTES,
};
pub use outbox::{OutboxEntry, PendingDelivery};
pub use peers::{check_peer_id, PeerRow, UpsertPeer, MAX_PEER_ID_LEN};
pub use questions::{
    NewQuestion, QuestionInsert, QuestionRow, QuestionStatus, MAX_NORMALIZED_TEXT_BYTES,
};
pub use schema::SCHEMA_VERSION;
pub use skills::{
    BundleRow, InstallationRow, NewInstallation, NewSkill, SkillOrigin, SkillRow, SkillStatus,
    MAX_PATH_BYTES,
};
pub use store::{Store, DEFAULT_BUSY_TIMEOUT_MS, MAX_BUSY_TIMEOUT_MS};
