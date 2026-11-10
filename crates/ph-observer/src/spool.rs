//! The hook fallback spool: `$PEERHARNESS_HOME/spool/observations.jsonl` (architecture
//! section 1).
//!
//! When the hook cannot write to SQLite quickly, it appends one JSON line per
//! [`NormalizedObservation`] here. The next CLI or daemon run calls [`drain`] and stores
//! the result. The file is 0600, opened with `O_APPEND`, capped at [`MAX_SPOOL_BYTES`],
//! and never followed through a symlink: on Unix every open uses `O_NOFOLLOW` (refused
//! atomically, no check-then-open race) and `O_NONBLOCK` (a FIFO planted at the spool
//! path cannot make the hook block), and anything that is not a regular file is refused.
//! Only the final path component is protected; the spool directory itself lives inside
//! the private (0700) PeerHarness home.
//!
//! Concurrency:
//!
//! * Each append is a single `write` of one complete line, so concurrent hooks do not
//!   interleave lines on local filesystems.
//! * [`drain`] claims the spool by atomically renaming it to a unique claim file
//!   (`observations.jsonl.processing-<unix-secs>-<pid>-<n>`), so two concurrent drains
//!   (CLI and daemon) never read or delete each other's data. Claim files left behind by
//!   a crashed drain (older than [`STALE_CLAIM_SECS`]) and the legacy
//!   `observations.jsonl.processing` file are re-claimed and drained by the next run.
//! * A hook that opened the spool just before [`drain`] renamed it may still append to
//!   the claimed file after it was read; that one observation is lost. Observations are
//!   low-value hints, so this is accepted.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ph_core::{bound_text, NormalizedObservation, Timestamp};

use crate::fsutil::{
    ensure_private_dir, is_symlink, open_regular, parent_dir, private_open_options, OpenFailure,
};

/// Appends are dropped once the spool is this large (5 MiB).
pub const MAX_SPOOL_BYTES: u64 = 5 * 1024 * 1024;

/// Lines longer than this are never written and are skipped when draining.
pub const MAX_SPOOL_LINE_BYTES: usize = 64 * 1024;

/// [`drain`] reads at most this much of one spool or claim file.
pub const MAX_DRAIN_BYTES: u64 = 2 * MAX_SPOOL_BYTES;

/// Maximum `repo_key` length kept when draining.
pub const MAX_REPO_KEY_BYTES: usize = 128;

/// The spool path relative to the PeerHarness home.
pub const SPOOL_RELATIVE_PATH: &str = "spool/observations.jsonl";

/// Suffix of the legacy processing file and prefix of claim-file suffixes.
pub const PROCESSING_SUFFIX: &str = ".processing";

/// A claim file older than this (by the time in its name) is treated as left behind by
/// a crashed drain and is drained again.
pub const STALE_CLAIM_SECS: i64 = 60;

/// `home/spool/observations.jsonl`.
pub fn spool_path(home: &Path) -> PathBuf {
    home.join(SPOOL_RELATIVE_PATH)
}

/// The legacy processing path: the spool path plus `.processing`. [`drain`] no longer
/// renames to it (it uses unique claim files) but still drains it when present.
pub fn processing_path(spool: &Path) -> PathBuf {
    let mut s = spool.as_os_str().to_owned();
    s.push(PROCESSING_SUFFIX);
    PathBuf::from(s)
}

/// Spool errors. `Display` never includes observation content.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// A filesystem operation failed.
    #[error("spool {op} failed: {kind}")]
    Io {
        /// What we were doing.
        op: &'static str,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
    /// The spool path is a symlink; refused.
    #[error("spool file is a symlink; refusing to use it")]
    Symlink,
    /// The spool path exists but is not a regular file (FIFO, directory, device...).
    #[error("spool path is not a regular file; refusing to use it")]
    NotRegularFile,
    /// The observation could not be serialized.
    #[error("observation could not be serialized")]
    Serialize,
}

fn io_err(op: &'static str) -> impl FnOnce(io::Error) -> SpoolError {
    move |e| SpoolError::Io { op, kind: e.kind() }
}

/// What [`append_observation`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The line was appended.
    Appended,
    /// The spool is at or over [`MAX_SPOOL_BYTES`]; the observation was dropped.
    DroppedFull,
    /// The serialized line exceeded [`MAX_SPOOL_LINE_BYTES`]; it was dropped.
    DroppedTooLarge,
}

/// Appends `obs` as one JSON line to `spool`, creating the file (0600) and its parent
/// directory (0700) if needed.
///
/// The write is dropped (not an error) when the file is already at least
/// [`MAX_SPOOL_BYTES`] long. A symlinked spool path gives [`SpoolError::Symlink`] and a
/// non-regular file (for example a FIFO) gives [`SpoolError::NotRegularFile`]; neither
/// ever blocks.
pub fn append_observation(
    spool: &Path,
    obs: &NormalizedObservation,
) -> Result<AppendOutcome, SpoolError> {
    let mut line = serde_json::to_vec(obs).map_err(|_| SpoolError::Serialize)?;
    line.push(b'\n');
    if line.len() > MAX_SPOOL_LINE_BYTES {
        tracing::debug!(bytes = line.len(), "spool line too large; dropped");
        return Ok(AppendOutcome::DroppedTooLarge);
    }
    ensure_private_dir(&parent_dir(spool)).map_err(io_err("create directory"))?;
    let mut f = match open_regular(
        private_open_options().append(true).create(true),
        spool,
        false,
    ) {
        Ok(f) => f,
        Err(OpenFailure::Symlink) => return Err(SpoolError::Symlink),
        Err(OpenFailure::NotRegularFile) => return Err(SpoolError::NotRegularFile),
        Err(OpenFailure::NotFound) => {
            return Err(SpoolError::Io {
                op: "open",
                kind: io::ErrorKind::NotFound,
            })
        }
        Err(OpenFailure::Io(e)) => return Err(io_err("open")(e)),
    };
    let len = f.metadata().map_err(io_err("stat"))?.len();
    if len >= MAX_SPOOL_BYTES {
        tracing::debug!(bytes = len, "spool full; observation dropped");
        return Ok(AppendOutcome::DroppedFull);
    }
    f.write_all(&line).map_err(io_err("write"))?;
    Ok(AppendOutcome::Appended)
}

/// Result of [`drain`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Drained {
    /// Observations in file order (left-over claim files first, then the spool).
    pub observations: Vec<NormalizedObservation>,
    /// Lines that were malformed or too long and were skipped.
    pub skipped_lines: usize,
}

/// Takes everything out of the spool.
///
/// 1. Left-over files from interrupted earlier drains (the legacy `.processing` file and
///    claim files older than [`STALE_CLAIM_SECS`]) are claimed, read and deleted.
/// 2. The spool is atomically renamed to a fresh, unique claim file, read, and deleted.
///
/// Every claim is a `rename`, so of two concurrent drains exactly one gets each file.
/// Malformed lines are skipped and counted. Every observation is re-normalized on the
/// way out (text redacted and bounded again, `repo_key` bounded), so a tampered spool
/// cannot inject unredacted text. A missing spool gives an empty result. A symlinked
/// spool gives [`SpoolError::Symlink`]; a non-regular file found at a claimed path is
/// deleted (it is only a directory entry in our spool namespace) and skipped. Data is
/// deleted once read: the caller should store the result promptly, idempotently by
/// observation id.
pub fn drain(spool: &Path) -> Result<Drained, SpoolError> {
    if is_symlink(spool) {
        return Err(SpoolError::Symlink);
    }
    let mut out = Drained::default();
    let dir = parent_dir(spool);
    let Some(spool_name) = spool.file_name().and_then(|n| n.to_str()) else {
        return Err(SpoolError::Io {
            op: "resolve spool name",
            kind: io::ErrorKind::InvalidInput,
        });
    };
    let now = Timestamp::now().unix_seconds();
    let mut leftovers: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| is_recoverable_leftover(spool_name, n, now))
            })
            .map(|e| e.path())
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(io_err("list directory")(e)),
    };
    leftovers.sort();
    for path in leftovers {
        if is_symlink(&path) {
            tracing::debug!("spool leftover is a symlink; skipped");
            continue;
        }
        if let Some(claimed) = claim(&path, spool)? {
            read_and_delete(&claimed, &mut out)?;
        }
    }
    if let Some(claimed) = claim(spool, spool)? {
        read_and_delete(&claimed, &mut out)?;
    }
    tracing::debug!(
        drained = out.observations.len(),
        skipped = out.skipped_lines,
        "spool drained"
    );
    Ok(out)
}

/// `true` for the legacy `<spool>.processing` file and for claim files
/// `<spool>.processing-<secs>-...` whose claim time is at least [`STALE_CLAIM_SECS`]
/// away from `now` (or unparseable).
fn is_recoverable_leftover(spool_name: &str, name: &str, now: i64) -> bool {
    let Some(rest) = name
        .strip_prefix(spool_name)
        .and_then(|r| r.strip_prefix(PROCESSING_SUFFIX))
    else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some(claim) = rest.strip_prefix('-') else {
        return false;
    };
    match claim.split('-').next().and_then(|t| t.parse::<i64>().ok()) {
        Some(secs) => now.saturating_sub(secs).saturating_abs() >= STALE_CLAIM_SECS,
        None => true,
    }
}

/// A fresh claim path next to `spool`, unique across processes (pid) and within this
/// process (counter).
fn claim_path(spool: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut s = processing_path(spool).into_os_string();
    s.push(format!(
        "-{}-{}-{n}",
        Timestamp::now().unix_seconds(),
        std::process::id()
    ));
    PathBuf::from(s)
}

/// Atomically renames `path` to a fresh claim file. `None` when `path` no longer exists
/// (nothing to drain, or another drain claimed it first).
fn claim(path: &Path, spool: &Path) -> Result<Option<PathBuf>, SpoolError> {
    let to = claim_path(spool);
    match fs::rename(path, &to) {
        Ok(()) => Ok(Some(to)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err("rename")(e)),
    }
}

fn read_and_delete(path: &Path, out: &mut Drained) -> Result<(), SpoolError> {
    let f = match open_regular(fs::OpenOptions::new().read(true), path, false) {
        Ok(f) => f,
        // Re-claimed by a concurrent drain: it owns the data now.
        Err(OpenFailure::NotFound) => return Ok(()),
        Err(OpenFailure::Symlink) | Err(OpenFailure::NotRegularFile) => {
            tracing::debug!("spool claim is not a regular file; removed");
            return remove_claim(path);
        }
        Err(OpenFailure::Io(e)) => return Err(io_err("open")(e)),
    };
    let mut reader = BufReader::new(f.take(MAX_DRAIN_BYTES));
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_SPOOL_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(io_err("read"))?;
        if n == 0 {
            break;
        }
        if line.last() != Some(&b'\n') && line.len() > MAX_SPOOL_LINE_BYTES {
            // Over-long line: skip the rest of it.
            out.skipped_lines += 1;
            skip_to_newline(&mut reader)?;
            continue;
        }
        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        if body.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<NormalizedObservation>(body) {
            Ok(o) => out.observations.push(renormalize(o)),
            Err(_) => out.skipped_lines += 1,
        }
    }
    remove_claim(path)
}

/// Deletes a claim file; already gone is fine.
fn remove_claim(path: &Path) -> Result<(), SpoolError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("delete")(e)),
    }
}

fn skip_to_newline<R: BufRead>(reader: &mut R) -> Result<(), SpoolError> {
    loop {
        let buf = reader.fill_buf().map_err(io_err("read"))?;
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            reader.consume(pos + 1);
            return Ok(());
        }
        let len = buf.len();
        reader.consume(len);
    }
}

fn renormalize(o: NormalizedObservation) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        o.id,
        o.created_at,
        o.source,
        o.session_hash,
        bound_text(&o.repo_key, MAX_REPO_KEY_BYTES),
        o.kind,
        &o.text,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leftover_recognition() {
        let now = 1_800_000_000;
        let n = "observations.jsonl";
        assert!(is_recoverable_leftover(
            n,
            "observations.jsonl.processing",
            now
        ));
        assert!(is_recoverable_leftover(
            n,
            &format!("observations.jsonl.processing-{}-12-0", now - 61),
            now
        ));
        assert!(!is_recoverable_leftover(
            n,
            &format!("observations.jsonl.processing-{}-12-0", now - 5),
            now
        ));
        assert!(is_recoverable_leftover(
            n,
            &format!("observations.jsonl.processing-{}-12-0", now + 3600),
            now
        ));
        assert!(is_recoverable_leftover(
            n,
            "observations.jsonl.processing-x",
            now
        ));
        assert!(!is_recoverable_leftover(n, "observations.jsonl", now));
        assert!(!is_recoverable_leftover(
            n,
            "observations.jsonl.processingx",
            now
        ));
        assert!(!is_recoverable_leftover(n, "other.jsonl.processing", now));
    }

    #[test]
    fn claim_paths_are_unique() {
        let p = Path::new("/x/observations.jsonl");
        let a = claim_path(p);
        let b = claim_path(p);
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(name.starts_with("observations.jsonl.processing-"));
        // A fresh claim is not treated as a leftover.
        assert!(!is_recoverable_leftover(
            "observations.jsonl",
            &name,
            Timestamp::now().unix_seconds()
        ));
    }
}
