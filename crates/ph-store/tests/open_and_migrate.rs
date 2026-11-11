//! Opening, pragmas, migrations and file permissions.

mod common;

use common::*;
use ph_store::{Store, StoreError, SCHEMA_VERSION};

#[test]
fn migration_is_idempotent_across_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peerharness.db");
    {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        s.insert_circle(&circle_row()).unwrap();
    }
    for _ in 0..3 {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(s.circles().unwrap().len(), 1, "data survives reopen");
        assert!(s.quick_check().unwrap());
    }
}

#[test]
fn pragmas_are_set() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let _s = Store::open(&path).unwrap();
    // Inspect via a raw connection: WAL is persistent in the file.
    let c = rusqlite::Connection::open(&path).unwrap();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn foreign_keys_are_enforced() {
    let s = Store::open_in_memory().unwrap();
    // No circle stored: an event for it must be refused.
    let q = question(ALICE, "team/backend", "Use pnpm?", 1);
    let err = s.insert_event(&verified(&q), None, now()).unwrap_err();
    assert!(matches!(err, StoreError::MissingReference), "{err:?}");
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    drop(Store::open(&path).unwrap());
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.pragma_update(None, "user_version", i64::from(SCHEMA_VERSION) + 1)
            .unwrap();
    }
    let err = Store::open(&path).unwrap_err();
    assert!(matches!(err, StoreError::SchemaTooNew { .. }), "{err:?}");
    // The Display is static and content-free.
    assert!(err.to_string().contains("newer"));
}

#[test]
fn missing_parent_directory_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = Store::open(dir.path().join("nope").join("p.db")).unwrap_err();
    assert!(matches!(err, StoreError::Io { .. }), "{err:?}");
}

#[test]
fn garbage_file_is_rejected_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    std::fs::write(
        &path,
        b"this is definitely not an sqlite database file .......",
    )
    .unwrap();
    assert!(Store::open(&path).is_err());
}

#[cfg(unix)]
#[test]
fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    let s = Store::open(&path).unwrap();
    s.insert_circle(&circle_row()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    for suffix in ["-wal", "-shm"] {
        let p = dir.path().join(format!("p.db{suffix}"));
        if p.exists() {
            let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m & 0o077, 0, "{suffix} must not be group/other accessible");
        }
    }
    drop(s);

    // An existing over-permissive file is tightened.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(Store::open(&path).unwrap());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn transaction_rolls_back_everything_on_error() {
    let s = Store::open_in_memory().unwrap();
    let res: ph_store::Result<()> = s.transaction(|s| {
        s.insert_circle(&circle_row())?;
        s.record_notification("t", now())?;
        Err(StoreError::NotFound { what: "test" })
    });
    assert!(res.is_err());
    assert!(s.circles().unwrap().is_empty());
    assert_eq!(
        s.count_notifications_since(now().minus_secs(10)).unwrap(),
        0
    );

    // Nested method transactions (savepoints) commit with the outer one.
    s.transaction(|s| {
        s.insert_circle(&circle_row())?;
        s.upsert_membership_proof(&proof(ALICE, &["team"]), true, now())?;
        Ok(())
    })
    .unwrap();
    assert_eq!(s.memberships_for_circle(&circle()).unwrap().len(), 1);
}

/// What a caller of `transaction_with` returns from its closure: this crate's error,
/// or one of its own.
#[derive(Debug)]
enum CallerError {
    Store(StoreError),
    Refused(&'static str),
}

impl From<StoreError> for CallerError {
    fn from(e: StoreError) -> Self {
        CallerError::Store(e)
    }
}

/// `transaction_with` is `transaction` for a closure whose error is the caller's. An
/// error that is not this crate's rolls back what the closure wrote, like one that is,
/// and comes back as it was returned.
#[test]
fn transaction_with_rolls_back_on_the_callers_own_error() {
    let s = Store::open_in_memory().unwrap();
    let res: Result<(), CallerError> = s.transaction_with(|s| {
        s.insert_circle(&circle_row())?;
        s.record_notification("t", now())?;
        assert_eq!(s.circles()?.len(), 1, "written inside the transaction");
        Err(CallerError::Refused("the caller's own check failed"))
    });
    assert!(
        matches!(
            res,
            Err(CallerError::Refused("the caller's own check failed"))
        ),
        "{res:?}"
    );
    assert!(s.circles().unwrap().is_empty());
    assert_eq!(
        s.count_notifications_since(now().minus_secs(10)).unwrap(),
        0
    );

    // An error of this crate inside it is carried in the caller's type, and rolls back.
    let res: Result<(), CallerError> = s.transaction_with(|s| {
        s.insert_circle(&circle_row())?;
        s.insert_circle(&circle_row())?;
        Ok(())
    });
    assert!(
        matches!(
            res,
            Err(CallerError::Store(StoreError::AlreadyExists { .. }))
        ),
        "{res:?}"
    );
    assert!(s.circles().unwrap().is_empty());

    // Without an error it commits, and its value comes back.
    let n: Result<usize, CallerError> = s.transaction_with(|s| {
        s.insert_circle(&circle_row())?;
        Ok(s.circles()?.len())
    });
    assert!(matches!(n, Ok(1)), "{n:?}");
    assert_eq!(s.circles().unwrap().len(), 1);

    // Nested in a transaction it is a savepoint: its own failure takes back its own
    // writes, and the outer transaction goes on and commits.
    s.transaction(|s| {
        s.record_notification("outer", now())?;
        let inner: Result<(), CallerError> = s.transaction_with(|s| {
            s.record_notification("inner", now())?;
            Err(CallerError::Refused("inner"))
        });
        assert!(matches!(inner, Err(CallerError::Refused("inner"))));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        s.count_notifications_since(now().minus_secs(10)).unwrap(),
        1
    );
}

#[test]
fn inner_failure_rolls_back_only_its_savepoint_when_caught() {
    let s = store_with_circle();
    s.transaction(|s| {
        s.record_notification("a", now())?;
        // Fails inside its own savepoint (revocation for an unknown circle hits the
        // foreign key at INSERT time); the outer work survives.
        let foreign = ph_protocol::UnsignedRevocation::new(
            pk(9),
            pk(ALICE),
            now(),
            "x".into(),
            ph_core::Nonce::from_bytes([9; 16]),
        )
        .sign(&sk(9))
        .unwrap();
        let err = s.insert_revocation(&foreign, now()).unwrap_err();
        assert!(matches!(err, StoreError::MissingReference), "{err:?}");
        s.record_notification("b", now())?;
        Ok(())
    })
    .unwrap();
    assert_eq!(s.count_notifications_since(now().minus_secs(1)).unwrap(), 2);
    assert!(s.all_revocations().unwrap().is_empty());
}

// ------------------------------------------------------------------ review additions

/// A busy timeout read from config can be anything; it must never panic (rusqlite
/// panics above i32::MAX ms, and `Instant + Duration` panics on overflow).
#[test]
fn huge_busy_timeout_is_clamped_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    for ms in [u64::MAX, ph_store::MAX_BUSY_TIMEOUT_MS + 1, 0] {
        let s = Store::open_with_busy_timeout(&path, ms).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }
}

/// Leftover `-wal` / `-shm` files that are group/other readable are tightened on open.
#[cfg(unix)]
#[test]
fn loose_wal_side_files_are_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    // Keep a connection open so the WAL and SHM files exist.
    let holder = Store::open(&path).unwrap();
    holder.insert_circle(&circle_row()).unwrap();
    for suffix in ["-wal", "-shm"] {
        let p = dir.path().join(format!("p.db{suffix}"));
        assert!(p.exists(), "{suffix} exists while a connection is open");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _s = Store::open(&path).unwrap();
    for suffix in ["-wal", "-shm"] {
        let p = dir.path().join(format!("p.db{suffix}"));
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "{suffix}");
    }
}

/// An empty pre-existing file is a valid version-0 database: it is migrated, and
/// reopening never re-runs or duplicates a migration.
#[test]
fn empty_existing_file_is_migrated_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.db");
    std::fs::write(&path, b"").unwrap();
    let count_tables = || -> i64 {
        rusqlite::Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    drop(Store::open(&path).unwrap());
    let first = count_tables();
    assert!(first >= 16, "all tables created ({first})");
    for _ in 0..2 {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(s.quick_check().unwrap());
    }
    assert_eq!(count_tables(), first);
}
