//! Column encoding helpers shared by the repositories.
//!
//! Conventions:
//! * timestamps are `INTEGER` Unix seconds;
//! * keys, digests, ids and scopes are `TEXT` in their canonical string form;
//! * booleans are `INTEGER` 0/1;
//! * lists are JSON arrays in `TEXT`;
//! * signed protocol objects are canonical (JCS) JSON text.

use std::str::FromStr;

use ph_core::Timestamp;
use rusqlite::types::Type;
use rusqlite::Row;
use serde::de::DeserializeOwned;

use crate::error::CorruptColumn;

/// A decoding failure in column `idx`, surfacing as `StoreError::Corrupt { what }`.
pub(crate) fn corrupt(idx: usize, what: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(idx, Type::Text, Box::new(CorruptColumn(what)))
}

/// Reads a `TEXT` column and parses it with `FromStr`.
pub(crate) fn parse<T: FromStr>(
    row: &Row<'_>,
    idx: usize,
    what: &'static str,
) -> rusqlite::Result<T> {
    let s: String = row.get(idx)?;
    s.parse().map_err(|_| corrupt(idx, what))
}

/// Reads a nullable `TEXT` column and parses it with `FromStr`.
pub(crate) fn parse_opt<T: FromStr>(
    row: &Row<'_>,
    idx: usize,
    what: &'static str,
) -> rusqlite::Result<Option<T>> {
    let s: Option<String> = row.get(idx)?;
    s.map(|s| s.parse().map_err(|_| corrupt(idx, what)))
        .transpose()
}

/// Reads an `INTEGER` Unix-seconds column as a [`Timestamp`].
pub(crate) fn ts(row: &Row<'_>, idx: usize) -> rusqlite::Result<Timestamp> {
    let secs: i64 = row.get(idx)?;
    Timestamp::from_unix_seconds(secs).map_err(|_| corrupt(idx, "timestamp"))
}

/// Reads a nullable `INTEGER` Unix-seconds column.
pub(crate) fn ts_opt(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<Timestamp>> {
    let secs: Option<i64> = row.get(idx)?;
    secs.map(|s| Timestamp::from_unix_seconds(s).map_err(|_| corrupt(idx, "timestamp")))
        .transpose()
}

/// Reads an `INTEGER` 0/1 column as `bool`.
pub(crate) fn flag(row: &Row<'_>, idx: usize) -> rusqlite::Result<bool> {
    let v: i64 = row.get(idx)?;
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt(idx, "flag")),
    }
}

/// Reads a non-negative `INTEGER` column as `u64`.
pub(crate) fn uint(row: &Row<'_>, idx: usize, what: &'static str) -> rusqlite::Result<u64> {
    let v: i64 = row.get(idx)?;
    u64::try_from(v).map_err(|_| corrupt(idx, what))
}

/// Reads a `TEXT` column holding JSON and deserializes it.
pub(crate) fn json<T: DeserializeOwned>(
    row: &Row<'_>,
    idx: usize,
    what: &'static str,
) -> rusqlite::Result<T> {
    let s: String = row.get(idx)?;
    serde_json::from_str(&s).map_err(|_| corrupt(idx, what))
}

/// Converts a `u64` to an SQLite integer, rejecting values above `i64::MAX`.
pub(crate) fn int(v: u64, what: &'static str) -> crate::Result<i64> {
    i64::try_from(v).map_err(|_| crate::StoreError::invalid(what, "value too large"))
}

/// Converts a caller-supplied limit to an SQLite `LIMIT` value.
pub(crate) fn limit(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// `true` -> 1, `false` -> 0.
pub(crate) const fn b(v: bool) -> i64 {
    if v {
        1
    } else {
        0
    }
}

/// Serializes a value to JSON text for a `TEXT` column.
pub(crate) fn to_json<T: serde::Serialize + ?Sized>(
    v: &T,
    what: &'static str,
) -> crate::Result<String> {
    serde_json::to_string(v).map_err(|_| crate::StoreError::invalid(what, "not serializable"))
}

/// Builds `?, ?, ?` with `n` placeholders.
pub(crate) fn placeholders(n: usize) -> String {
    let mut s = String::with_capacity(n * 3);
    for i in 0..n {
        if i > 0 {
            s.push_str(", ");
        }
        s.push('?');
    }
    s
}

/// Validates a short single-line identifier-like string (agent names, install
/// scopes, keystore backends, topics...).
pub(crate) fn check_short(what: &'static str, s: &str, max: usize) -> crate::Result<()> {
    if s.is_empty() {
        return Err(crate::StoreError::invalid(what, "empty"));
    }
    if s.len() > max {
        return Err(crate::StoreError::invalid(what, "too long"));
    }
    if s.chars().any(char::is_control) {
        return Err(crate::StoreError::invalid(what, "control character"));
    }
    Ok(())
}
