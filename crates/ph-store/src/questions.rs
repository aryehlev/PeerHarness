//! `questions`: local and received QUESTION state (the inbox).

use std::fmt;
use std::str::FromStr;

use ph_core::{CircleId, DeviceKey, Digest, EventId, ParseError, Scope, Timestamp};
use ph_protocol::{EventBody, SignedEnvelope};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::error::{Result, StoreError};
use crate::sql;
use crate::Store;

/// Maximum length of a caller-supplied normalized dedup text/key.
pub const MAX_NORMALIZED_TEXT_BYTES: usize = 8 * 1024;

/// Inbox state of a question.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStatus {
    /// Not yet handled.
    New,
    /// The local human answered it.
    Answered,
    /// Muted by the local human.
    Muted,
    /// Dismissed by the local human.
    Dismissed,
}

impl QuestionStatus {
    /// Every status.
    pub const ALL: [QuestionStatus; 4] = [
        QuestionStatus::New,
        QuestionStatus::Answered,
        QuestionStatus::Muted,
        QuestionStatus::Dismissed,
    ];

    /// The stored string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            QuestionStatus::New => "new",
            QuestionStatus::Answered => "answered",
            QuestionStatus::Muted => "muted",
            QuestionStatus::Dismissed => "dismissed",
        }
    }
}

impl fmt::Display for QuestionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QuestionStatus {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "new" => Ok(Self::New),
            "answered" => Ok(Self::Answered),
            "muted" => Ok(Self::Muted),
            "dismissed" => Ok(Self::Dismissed),
            _ => Err(ParseError::new("question status", "unknown status")),
        }
    }
}

/// A question to store. Build it with [`NewQuestion::from_envelope`].
#[derive(Clone, PartialEq, Eq)]
pub struct NewQuestion {
    /// QUESTION event id.
    pub event_id: EventId,
    /// Circle.
    pub circle_id: CircleId,
    /// Scope.
    pub scope: Scope,
    /// Author device key.
    pub author: DeviceKey,
    /// Question text (already validated by ph-protocol).
    pub question: String,
    /// Topic.
    pub topic: String,
    /// Dedup text: the output of `ph_governance::normalize_question_text` (or any
    /// deterministic key the caller uses consistently). Unique per circle.
    pub normalized_text: String,
    /// Optional related candidate digest from the body.
    pub related_candidate: Option<Digest>,
    /// Whether this node asked it.
    pub is_local: bool,
    /// `created_at` of the event (informational).
    pub created_at: Timestamp,
    /// When this node stored it (quotas count by this).
    pub received_at: Timestamp,
}

impl fmt::Debug for NewQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewQuestion")
            .field("event_id", &self.event_id)
            .field("circle_id", &self.circle_id)
            .field("is_local", &self.is_local)
            .field("question_len", &self.question.len())
            .finish_non_exhaustive()
    }
}

impl NewQuestion {
    /// Builds a question from a QUESTION envelope; `None` for any other event type.
    pub fn from_envelope(
        env: &SignedEnvelope,
        normalized_text: String,
        is_local: bool,
        received_at: Timestamp,
    ) -> Option<Self> {
        let EventBody::Question(b) = &env.body else {
            return None;
        };
        Some(Self {
            event_id: env.event_id,
            circle_id: env.circle_id,
            scope: env.scope.clone(),
            author: env.author,
            question: b.question.clone(),
            topic: b.topic.clone(),
            normalized_text,
            related_candidate: b.related_candidate,
            is_local,
            created_at: env.created_at,
            received_at,
        })
    }
}

/// A stored question.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct QuestionRow {
    /// QUESTION event id.
    pub event_id: EventId,
    /// Circle.
    pub circle_id: CircleId,
    /// Scope.
    pub scope: Scope,
    /// Author device key.
    pub author: DeviceKey,
    /// Question text.
    pub question: String,
    /// Topic.
    pub topic: String,
    /// Dedup text.
    pub normalized_text: String,
    /// Related candidate digest.
    pub related_candidate: Option<Digest>,
    /// Whether this node asked it.
    pub is_local: bool,
    /// Inbox state.
    pub status: QuestionStatus,
    /// Event `created_at`.
    pub created_at: Timestamp,
    /// Local receive time.
    pub received_at: Timestamp,
}

impl fmt::Debug for QuestionRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuestionRow")
            .field("event_id", &self.event_id)
            .field("circle_id", &self.circle_id)
            .field("author", &self.author)
            .field("question_len", &self.question.len())
            .field("is_local", &self.is_local)
            .field("status", &self.status)
            .field("received_at", &self.received_at)
            .finish_non_exhaustive()
    }
}

/// Outcome of [`Store::insert_question`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionInsert {
    /// Stored with status `New`.
    Inserted,
    /// A question with the same event id is already stored.
    DuplicateEvent,
    /// Another question with the same normalized text exists in the circle.
    DuplicateText,
}

const COLS: &str = "event_id, circle_id, scope, author, question, topic, normalized_text, \
                    related_candidate, is_local, status, created_at, received_at";

fn row(r: &Row<'_>) -> rusqlite::Result<QuestionRow> {
    Ok(QuestionRow {
        event_id: sql::parse(r, 0, "event id")?,
        circle_id: sql::parse(r, 1, "circle id")?,
        scope: sql::parse(r, 2, "scope")?,
        author: sql::parse(r, 3, "author key")?,
        question: r.get(4)?,
        topic: r.get(5)?,
        normalized_text: r.get(6)?,
        related_candidate: sql::parse_opt(r, 7, "digest")?,
        is_local: sql::flag(r, 8)?,
        status: sql::parse(r, 9, "question status")?,
        created_at: sql::ts(r, 10)?,
        received_at: sql::ts(r, 11)?,
    })
}

impl Store {
    /// Stores a question with status `New`, deduplicated by event id and by
    /// `(circle_id, normalized_text)`. Never errors on a duplicate.
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] for an empty or oversized `normalized_text`,
    /// [`StoreError::MissingReference`] if the circle is not stored.
    pub fn insert_question(&self, q: &NewQuestion) -> Result<QuestionInsert> {
        if q.normalized_text.is_empty() || q.normalized_text.len() > MAX_NORMALIZED_TEXT_BYTES {
            return Err(StoreError::invalid(
                "normalized question text",
                "empty or too long",
            ));
        }
        let tx = self.tx()?;
        let by_id: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM questions WHERE event_id = ?1)",
            [q.event_id.to_string()],
            |r| r.get(0),
        )?;
        if by_id {
            return Ok(QuestionInsert::DuplicateEvent);
        }
        if self.question_text_exists(&q.circle_id, &q.normalized_text)? {
            return Ok(QuestionInsert::DuplicateText);
        }
        self.conn.execute(
            &format!(
                "INSERT INTO questions ({COLS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            ),
            params![
                q.event_id.to_string(),
                q.circle_id.to_string(),
                q.scope.as_str(),
                q.author.to_string(),
                q.question,
                q.topic,
                q.normalized_text,
                q.related_candidate.as_ref().map(ToString::to_string),
                sql::b(q.is_local),
                QuestionStatus::New.as_str(),
                q.created_at.unix_seconds(),
                q.received_at.unix_seconds()
            ],
        )?;
        tx.commit()?;
        Ok(QuestionInsert::Inserted)
    }

    /// The question with this event id.
    pub fn question(&self, event_id: &EventId) -> Result<Option<QuestionRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM questions WHERE event_id = ?1"),
                [event_id.to_string()],
                row,
            )
            .optional()?)
    }

    fn questions_filtered(
        &self,
        is_local: bool,
        statuses: &[QuestionStatus],
    ) -> Result<Vec<QuestionRow>> {
        let filter = if statuses.is_empty() {
            String::new()
        } else {
            format!("AND status IN ({})", sql::placeholders(statuses.len()))
        };
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM questions WHERE is_local = {} {filter}
             ORDER BY received_at DESC, event_id",
            sql::b(is_local)
        ))?;
        let args: Vec<&str> = statuses.iter().map(|s| s.as_str()).collect();
        let rows = st
            .query_map(rusqlite::params_from_iter(args), row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Received (non-local) questions whose status is in `statuses` (all when empty),
    /// newest first.
    pub fn inbox(&self, statuses: &[QuestionStatus]) -> Result<Vec<QuestionRow>> {
        self.questions_filtered(false, statuses)
    }

    /// Questions this node asked, newest first.
    pub fn local_questions(&self) -> Result<Vec<QuestionRow>> {
        self.questions_filtered(true, &[])
    }

    /// Sets a question's inbox status.
    pub fn set_question_status(&self, event_id: &EventId, status: QuestionStatus) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE questions SET status = ?2 WHERE event_id = ?1",
            params![event_id.to_string(), status.as_str()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound { what: "question" });
        }
        Ok(())
    }

    /// Questions by `author` (in any circle) received at or after `since`.
    pub fn count_questions_by_author_since(
        &self,
        author: &DeviceKey,
        since: Timestamp,
    ) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM questions WHERE author = ?1 AND received_at >= ?2",
            params![author.to_string(), since.unix_seconds()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Questions in `circle` received at or after `since`.
    pub fn count_questions_by_circle_since(
        &self,
        circle: &CircleId,
        since: Timestamp,
    ) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM questions WHERE circle_id = ?1 AND received_at >= ?2",
            params![circle.to_string(), since.unix_seconds()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Whether a question with this normalized text exists in `circle`. The text is
    /// compared exactly; normalize it with the same function used for
    /// [`NewQuestion::normalized_text`].
    pub fn question_text_exists(&self, circle: &CircleId, normalized_text: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM questions WHERE circle_id = ?1 AND normalized_text = ?2)",
            params![circle.to_string(), normalized_text],
            |r| r.get(0),
        )?)
    }

    /// Every stored question, oldest first (for export).
    pub fn all_questions(&self) -> Result<Vec<QuestionRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM questions ORDER BY received_at, event_id"
        ))?;
        let rows = st
            .query_map([], row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
