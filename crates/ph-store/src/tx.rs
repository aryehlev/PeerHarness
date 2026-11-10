//! A nestable write-transaction guard.
//!
//! The outermost guard runs `BEGIN IMMEDIATE`, which takes SQLite's write lock up front
//! (waiting up to the busy timeout). That avoids the `SQLITE_BUSY` a deferred
//! read-then-write transaction gets in WAL mode when another connection commits in
//! between, and it makes read-check-write sequences (candidate status compare-and-set)
//! atomic across processes. A guard opened while a transaction is already active uses a
//! `SAVEPOINT` instead, so repository methods compose inside [`crate::Store::transaction`].
//!
//! Dropping a guard without [`Tx::commit`] rolls back its work.

use rusqlite::Connection;

use crate::error::Result;

const SAVEPOINT: &str = "ph_store_sp";

/// Write-transaction guard; see the module docs.
pub(crate) struct Tx<'c> {
    conn: &'c Connection,
    nested: bool,
    done: bool,
}

impl<'c> Tx<'c> {
    /// Starts an immediate transaction, or a savepoint if one is already active.
    pub(crate) fn begin(conn: &'c Connection) -> Result<Self> {
        let nested = !conn.is_autocommit();
        if nested {
            conn.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))?;
        } else {
            conn.execute_batch("BEGIN IMMEDIATE")?;
        }
        Ok(Self {
            conn,
            nested,
            done: false,
        })
    }

    /// Commits (or releases the savepoint). On failure the guard rolls back on drop.
    pub(crate) fn commit(mut self) -> Result<()> {
        if self.nested {
            self.conn
                .execute_batch(&format!("RELEASE SAVEPOINT {SAVEPOINT}"))?;
        } else {
            self.conn.execute_batch("COMMIT")?;
        }
        self.done = true;
        Ok(())
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let sql = if self.nested {
            format!("ROLLBACK TO SAVEPOINT {SAVEPOINT}; RELEASE SAVEPOINT {SAVEPOINT}")
        } else {
            "ROLLBACK".to_owned()
        };
        // A failing rollback leaves nothing better to do; SQLite rolls back an open
        // transaction when the connection closes anyway.
        if self.conn.execute_batch(&sql).is_err() {
            tracing::warn!("store transaction rollback failed");
        }
    }
}
