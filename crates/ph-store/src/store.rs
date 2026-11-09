//! [`Store`]: opening, pragmas, migrations and transactions.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::error::{Result, StoreError};
use crate::schema;
use crate::tx::Tx;

/// Default `busy_timeout` for CLI and daemon connections, in milliseconds.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Largest busy timeout SQLite accepts (`i32::MAX` milliseconds, about 24.8 days).
/// Larger values passed to [`Store::open_with_busy_timeout`] are clamped to it.
pub const MAX_BUSY_TIMEOUT_MS: u64 = i32::MAX as u64;

/// The PeerHarness SQLite database (`$PEERHARNESS_HOME/peerharness.db`).
///
/// A `Store` wraps exactly one [`rusqlite::Connection`]. It is `Send` but not `Sync`:
/// move it into a thread or task, or open one `Store` per thread/task. Several
/// processes and connections may use the same file at once (WAL mode with file
/// locking); every multi-statement write runs in a `BEGIN IMMEDIATE` transaction.
///
/// The database never contains private key bytes (architecture section 8).
pub struct Store {
    pub(crate) conn: Connection,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("in_memory", &self.path.is_none())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens (creating if needed) the database at `path` with the default busy timeout
    /// of [`DEFAULT_BUSY_TIMEOUT_MS`].
    ///
    /// On Unix a new file is created with mode `0600`, and an existing file readable by
    /// group or others is tightened to `0600`. The parent directory must exist. The
    /// connection is configured with `journal_mode=WAL`, `foreign_keys=ON`,
    /// `synchronous=NORMAL` and the busy timeout, and pending migrations are applied.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] if the file cannot be created or secured,
    /// [`StoreError::SchemaTooNew`] if a newer build wrote the database,
    /// [`StoreError::Busy`] if the database stays locked past the timeout, and
    /// [`StoreError::Sqlite`] for other SQLite failures.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_busy_timeout(path, DEFAULT_BUSY_TIMEOUT_MS)
    }

    /// [`Store::open`] with an explicit busy timeout in milliseconds. Hook writers use a
    /// short timeout and fall back to the spool file on [`StoreError::Busy`].
    ///
    /// The timeout is clamped to [`MAX_BUSY_TIMEOUT_MS`] (so a value read from config
    /// can never panic). `0` disables waiting: a locked database fails at once.
    pub fn open_with_busy_timeout(path: impl AsRef<Path>, busy_timeout_ms: u64) -> Result<Self> {
        let path = path.as_ref();
        prepare_file(path)?;
        let conn = Connection::open(path)?;
        let busy_timeout_ms = busy_timeout_ms.min(MAX_BUSY_TIMEOUT_MS);
        let timeout = Duration::from_millis(busy_timeout_ms);
        conn.busy_timeout(timeout)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Switching a brand-new file to WAL and the first migration can report
        // SQLITE_BUSY without consulting the busy handler when several processes open
        // the file at the same moment, so retry those steps until the timeout.
        let start = Instant::now();
        let deadline = start.checked_add(timeout).unwrap_or(start);
        retry_busy(deadline, || {
            let mode: String =
                conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::Invalid {
                    what: "journal mode",
                    reason: "WAL mode could not be enabled",
                });
            }
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            schema::migrate(&conn)
        })?;
        tracing::debug!(
            schema_version = schema::SCHEMA_VERSION,
            busy_timeout_ms,
            "opened store"
        );
        Ok(Self {
            conn,
            path: Some(path.to_owned()),
        })
    }

    /// Opens a fresh, private in-memory database (for tests). WAL does not apply.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate(&conn)?;
        Ok(Self { conn, path: None })
    }

    /// The database file path, or `None` for an in-memory store.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The current `PRAGMA user_version` (equals [`crate::SCHEMA_VERSION`] after open).
    pub fn schema_version(&self) -> Result<u32> {
        schema::user_version(&self.conn)
    }

    /// Runs `f` inside one `BEGIN IMMEDIATE` transaction (or a savepoint when already
    /// inside one). Every repository method called from `f` joins the transaction. `f`
    /// returning `Err` (or panicking) rolls everything back.
    ///
    /// ```
    /// # use ph_store::Store;
    /// let store = Store::open_in_memory().unwrap();
    /// let n = store.transaction(|s| s.pending_outbox_count()).unwrap();
    /// assert_eq!(n, 0);
    /// ```
    pub fn transaction<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        let tx = Tx::begin(&self.conn)?;
        let out = f(self)?;
        tx.commit()?;
        Ok(out)
    }

    /// Runs `PRAGMA quick_check` and reports whether the database is consistent
    /// (for `peerharness doctor`).
    pub fn quick_check(&self) -> Result<bool> {
        let r: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        Ok(r == "ok")
    }

    /// Checkpoints the WAL into the main file and truncates it. Useful before copying
    /// the file or scanning it; a no-op for in-memory stores.
    pub fn checkpoint(&self) -> Result<()> {
        if self.path.is_some() {
            self.conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        }
        Ok(())
    }

    pub(crate) fn tx(&self) -> Result<Tx<'_>> {
        Tx::begin(&self.conn)
    }
}

/// Runs `f`, retrying with a short sleep while it fails with [`StoreError::Busy`] and
/// `deadline` has not passed.
fn retry_busy<T>(deadline: Instant, mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let mut pause = Duration::from_millis(2);
    loop {
        match f() {
            Err(StoreError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            other => return other,
        }
    }
}

#[cfg(unix)]
fn prepare_file(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let io = |op: &'static str| move |e: std::io::Error| StoreError::Io { op, kind: e.kind() };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(io("creating the database file"))?;
    let meta = file
        .metadata()
        .map_err(io("reading database file metadata"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(io("restricting database file permissions"))?;
    }
    // SQLite creates `-wal`/`-shm` with the main file's mode, but files left behind by
    // an earlier, looser setup keep theirs: tighten them too. They hold row data.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut side = path.as_os_str().to_owned();
        side.push(suffix);
        let side = Path::new(&side);
        match std::fs::symlink_metadata(side) {
            Ok(m) if m.file_type().is_file() && m.permissions().mode() & 0o077 != 0 => {
                std::fs::set_permissions(side, std::fs::Permissions::from_mode(0o600))
                    .map_err(io("restricting database side-file permissions"))?;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("reading database side-file metadata")(e)),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_file(path: &Path) -> Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map(|_| ())
        .map_err(|e| StoreError::Io {
            op: "creating the database file",
            kind: e.kind(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Store>();
    }

    #[test]
    fn retry_busy_gives_up_at_deadline() {
        let mut calls = 0;
        let r: Result<()> = retry_busy(Instant::now() + Duration::from_millis(20), || {
            calls += 1;
            Err(StoreError::Busy)
        });
        assert!(matches!(r, Err(StoreError::Busy)));
        assert!(calls >= 2);
        let r = retry_busy(Instant::now(), || Ok(5));
        assert_eq!(r.unwrap(), 5);
    }
}
