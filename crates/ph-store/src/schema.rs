//! Forward-only migrations keyed by `PRAGMA user_version`.
//!
//! `MIGRATIONS[i]` upgrades the schema from version `i` to `i + 1`. Each one runs in its
//! own `BEGIN IMMEDIATE` transaction that re-reads `user_version` first, so several
//! processes opening a fresh database at the same time migrate it exactly once.
//! Never edit a released migration; append a new one.

use rusqlite::Connection;

use crate::error::{Result, StoreError};
use crate::tx::Tx;

/// Schema version written by this build.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

const V1: &str = r#"
CREATE TABLE identity_metadata (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    device_key       TEXT    NOT NULL,
    keystore_backend TEXT    NOT NULL,
    keystore_ref     TEXT    NOT NULL,
    created_at       INTEGER NOT NULL
) STRICT;

CREATE TABLE circles (
    circle_id         TEXT    PRIMARY KEY NOT NULL,
    name              TEXT    NOT NULL UNIQUE,
    root_key          TEXT    NOT NULL,
    is_founder        INTEGER NOT NULL CHECK (is_founder IN (0, 1)),
    root_keystore_ref TEXT,
    policy_json       TEXT    NOT NULL,
    policy_hash       TEXT    NOT NULL,
    created_at        INTEGER NOT NULL
) STRICT;

CREATE TABLE memberships (
    credential_digest TEXT    PRIMARY KEY NOT NULL,
    circle_id         TEXT    NOT NULL REFERENCES circles(circle_id),
    subject_key       TEXT    NOT NULL,
    roles_json        TEXT    NOT NULL,
    scopes_json       TEXT    NOT NULL,
    issued_at         INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    credential_json   TEXT    NOT NULL,
    acceptance_json   TEXT,
    is_self           INTEGER NOT NULL CHECK (is_self IN (0, 1)),
    received_at       INTEGER NOT NULL
) STRICT;
CREATE INDEX memberships_by_circle  ON memberships(circle_id, subject_key);
CREATE INDEX memberships_by_subject ON memberships(subject_key);

CREATE TABLE issued_invites (
    credential_digest TEXT    PRIMARY KEY NOT NULL,
    circle_id         TEXT    NOT NULL REFERENCES circles(circle_id),
    invitee_key       TEXT    NOT NULL,
    created_at        INTEGER NOT NULL,
    invite_expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX issued_invites_by_circle ON issued_invites(circle_id, created_at);

CREATE TABLE revocations (
    id              INTEGER PRIMARY KEY,
    circle_id       TEXT    NOT NULL REFERENCES circles(circle_id),
    subject_key     TEXT    NOT NULL,
    revoked_at      INTEGER NOT NULL,
    revocation_json TEXT    NOT NULL,
    received_at     INTEGER NOT NULL,
    epoch           INTEGER NOT NULL,
    UNIQUE (circle_id, subject_key),
    UNIQUE (circle_id, epoch)
) STRICT;

CREATE TABLE peers (
    peer_id    TEXT    PRIMARY KEY NOT NULL,
    device_key TEXT    NOT NULL UNIQUE,
    addrs_json TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER,
    blocked    INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    muted      INTEGER NOT NULL DEFAULT 0 CHECK (muted IN (0, 1))
) STRICT;

CREATE TABLE peer_circles (
    peer_id   TEXT NOT NULL REFERENCES peers(peer_id) ON DELETE CASCADE,
    circle_id TEXT NOT NULL REFERENCES circles(circle_id),
    PRIMARY KEY (peer_id, circle_id)
) STRICT;
CREATE INDEX peer_circles_by_circle ON peer_circles(circle_id);

CREATE TABLE observations (
    id           TEXT    PRIMARY KEY NOT NULL,
    created_at   INTEGER NOT NULL,
    source       TEXT    NOT NULL,
    session_hash TEXT,
    repo_key     TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    text         TEXT    NOT NULL,
    expires_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX observations_by_created ON observations(created_at);
CREATE INDEX observations_by_repo    ON observations(repo_key, created_at);
CREATE INDEX observations_by_expiry  ON observations(expires_at);

CREATE TABLE candidates (
    id                TEXT    PRIMARY KEY NOT NULL,
    concept_key       TEXT    NOT NULL,
    repo_key          TEXT    NOT NULL,
    status            TEXT    NOT NULL,
    statement         TEXT    NOT NULL,
    preferred         TEXT,
    avoided           TEXT,
    confidence        TEXT    NOT NULL,
    evidence_json     TEXT    NOT NULL,
    skill_name        TEXT    NOT NULL,
    topic             TEXT    NOT NULL,
    skill_draft       TEXT,
    circle_id         TEXT    REFERENCES circles(circle_id),
    scope             TEXT,
    question_event_id TEXT,
    proposal_event_id TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE (concept_key, repo_key)
) STRICT;
CREATE INDEX candidates_by_status   ON candidates(status, updated_at);
CREATE INDEX candidates_by_question ON candidates(question_event_id);
CREATE INDEX candidates_by_proposal ON candidates(proposal_event_id);

CREATE TABLE questions (
    event_id          TEXT    PRIMARY KEY NOT NULL,
    circle_id         TEXT    NOT NULL REFERENCES circles(circle_id),
    scope             TEXT    NOT NULL,
    author            TEXT    NOT NULL,
    question          TEXT    NOT NULL,
    topic             TEXT    NOT NULL,
    normalized_text   TEXT    NOT NULL,
    related_candidate TEXT,
    is_local          INTEGER NOT NULL CHECK (is_local IN (0, 1)),
    status            TEXT    NOT NULL CHECK (status IN ('new', 'answered', 'muted', 'dismissed')),
    created_at        INTEGER NOT NULL,
    received_at       INTEGER NOT NULL,
    UNIQUE (circle_id, normalized_text)
) STRICT;
CREATE INDEX questions_by_author ON questions(author, received_at);
CREATE INDEX questions_by_circle ON questions(circle_id, received_at);
CREATE INDEX questions_by_status ON questions(is_local, status, received_at);

CREATE TABLE events (
    event_id      TEXT    PRIMARY KEY NOT NULL,
    type          TEXT    NOT NULL,
    circle_id     TEXT    NOT NULL REFERENCES circles(circle_id),
    scope         TEXT    NOT NULL,
    author        TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    received_at   INTEGER NOT NULL,
    origin_peer   TEXT,
    ref_event_id  TEXT,
    bundle_digest TEXT,
    envelope_json TEXT    NOT NULL
) STRICT;
CREATE INDEX events_by_circle_type ON events(circle_id, type, created_at);
CREATE INDEX events_by_circle_time ON events(circle_id, created_at, event_id);
CREATE INDEX events_by_ref         ON events(ref_event_id, type);
CREATE INDEX events_by_bundle      ON events(circle_id, bundle_digest);

CREATE TABLE outbox (
    event_id        TEXT    NOT NULL REFERENCES events(event_id),
    peer_id         TEXT    NOT NULL REFERENCES peers(peer_id),
    enqueued_at     INTEGER NOT NULL,
    delivered_at    INTEGER,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at INTEGER,
    PRIMARY KEY (event_id, peer_id)
) STRICT;
CREATE INDEX outbox_pending ON outbox(peer_id, delivered_at, enqueued_at);

CREATE TABLE bundles (
    digest        TEXT    PRIMARY KEY NOT NULL,
    skill_name    TEXT    NOT NULL,
    manifest_json TEXT    NOT NULL,
    rel_path      TEXT    NOT NULL,
    size          INTEGER NOT NULL,
    created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE skills (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL,
    bundle_digest TEXT    NOT NULL REFERENCES bundles(digest),
    origin_kind   TEXT    NOT NULL CHECK (origin_kind IN ('local', 'proposal')),
    origin_ref    TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    UNIQUE (name, bundle_digest)
) STRICT;

CREATE TABLE installations (
    id              INTEGER PRIMARY KEY,
    skill_name      TEXT    NOT NULL,
    agent           TEXT    NOT NULL,
    install_scope   TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    bundle_digest   TEXT    NOT NULL,
    previous_digest TEXT,
    installed_at    INTEGER NOT NULL,
    removed_at      INTEGER
) STRICT;
CREATE UNIQUE INDEX installations_active
    ON installations(skill_name, agent, install_scope, path) WHERE removed_at IS NULL;
CREATE INDEX installations_by_skill ON installations(skill_name, installed_at);

CREATE TABLE sync_cursors (
    peer_id      TEXT    NOT NULL REFERENCES peers(peer_id) ON DELETE CASCADE,
    circle_id    TEXT    NOT NULL REFERENCES circles(circle_id),
    last_sync_at INTEGER NOT NULL,
    PRIMARY KEY (peer_id, circle_id)
) STRICT;

CREATE TABLE notifications (
    id      INTEGER PRIMARY KEY,
    topic   TEXT    NOT NULL,
    shown_at INTEGER NOT NULL
) STRICT;
CREATE INDEX notifications_by_time  ON notifications(shown_at);
CREATE INDEX notifications_by_topic ON notifications(topic, shown_at);
"#;

/// Version 2: governance by charter (architecture section 10).
///
/// * `charters` holds the chain of charters this node has accepted for each circle; the
///   row with the greatest `seq` is the current one. A node that joined late starts at
///   whatever `seq` its invitation carried.
/// * `rule_optouts` records rules the owner opted out of on this machine.
/// * `circles` loses the per-node quorum policy (the rules of the vote now live in the
///   charter and are the same for every member) and gains the owner's adoption mode and
///   the digest of the charter the owner last accepted.
const V2: &str = r#"
ALTER TABLE circles DROP COLUMN policy_json;
ALTER TABLE circles DROP COLUMN policy_hash;
ALTER TABLE circles ADD COLUMN adoption_mode TEXT NOT NULL DEFAULT 'ask'
    CHECK (adoption_mode IN ('follow', 'ask'));
ALTER TABLE circles ADD COLUMN accepted_charter TEXT;

CREATE TABLE charters (
    circle_id    TEXT    NOT NULL REFERENCES circles(circle_id),
    seq          INTEGER NOT NULL CHECK (seq >= 1),
    digest       TEXT    NOT NULL UNIQUE,
    charter_json TEXT    NOT NULL,
    accepted_at  INTEGER NOT NULL,
    PRIMARY KEY (circle_id, seq)
) STRICT;

CREATE TABLE rule_optouts (
    circle_id    TEXT    NOT NULL REFERENCES circles(circle_id),
    skill_name   TEXT    NOT NULL,
    opted_out_at INTEGER NOT NULL,
    PRIMARY KEY (circle_id, skill_name)
) STRICT;
"#;

/// Version 3: which installed skills a circle's vote put on this machine.
///
/// `rule_installs` records each skill that was installed because a rule passed in a
/// circle, so that a repeal removes exactly what the vote installed and never a skill
/// the owner installed for themselves.
const V3: &str = r#"
CREATE TABLE rule_installs (
    circle_id     TEXT    NOT NULL REFERENCES circles(circle_id),
    skill_name    TEXT    NOT NULL,
    bundle_digest TEXT    NOT NULL,
    installed_at  INTEGER NOT NULL,
    PRIMARY KEY (circle_id, skill_name)
) STRICT;
"#;

/// All migrations, in order. `MIGRATIONS[i]` moves from version `i` to `i + 1`.
const MIGRATIONS: &[&str] = &[V1, V2, V3];

/// Reads `PRAGMA user_version`.
pub(crate) fn user_version(conn: &Connection) -> Result<u32> {
    let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    u32::try_from(v).map_err(|_| StoreError::Corrupt {
        what: "schema version",
    })
}

/// Applies every pending migration. Idempotent and safe to run concurrently from
/// several connections.
pub(crate) fn migrate(conn: &Connection) -> Result<()> {
    let found = user_version(conn)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let target = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if target <= found {
            continue;
        }
        let tx = Tx::begin(conn)?;
        // Another process may have migrated between our read and BEGIN IMMEDIATE.
        let current = user_version(conn)?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }
        if current >= target {
            continue;
        }
        conn.execute_batch(sql)?;
        conn.pragma_update(None, "user_version", i64::from(target))?;
        tx.commit()?;
        tracing::debug!(version = target, "applied store migration");
    }
    Ok(())
}
