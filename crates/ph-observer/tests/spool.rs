//! Spool append/drain.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use ph_core::{
    NormalizedObservation, ObservationId, ObservationKind, ObservationSource, Timestamp,
};
use ph_observer::spool::{processing_path, spool_path, MAX_SPOOL_BYTES, MAX_SPOOL_LINE_BYTES};
use ph_observer::{append_observation, claim_spool, drain, AppendOutcome, SpoolError};

fn obs(i: usize, text: &str) -> NormalizedObservation {
    NormalizedObservation::from_raw(
        ObservationId::new(&format!("obs_{i}")).unwrap(),
        Timestamp::from_unix_seconds(1_800_000_000 + i as i64).unwrap(),
        ObservationSource::Hook,
        Some(ph_core::Digest::domain("peerharness-session-v0", b"s")),
        "repo:0123456789abcdef".to_owned(),
        ObservationKind::UserPrompt,
        text,
    )
}

fn setup() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = spool_path(&dir.path().join("home"));
    (dir, p)
}

#[test]
fn round_trip() {
    let (_d, p) = setup();
    let items: Vec<_> = (0..3)
        .map(|i| obs(i, &format!("line {i}\nwith newline \"quotes\"")))
        .collect();
    for o in &items {
        assert_eq!(append_observation(&p, o).unwrap(), AppendOutcome::Appended);
    }
    let content = fs::read_to_string(&p).unwrap();
    assert_eq!(content.lines().count(), 3);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(p.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let d = drain(&p).unwrap();
    assert_eq!(d.observations, items);
    assert_eq!(d.skipped_lines, 0);
    assert!(!p.exists());
    assert!(!processing_path(&p).exists());
    // Draining again is empty, as is draining a spool that never existed.
    assert!(drain(&p).unwrap().observations.is_empty());
    let (_d2, p2) = setup();
    assert!(drain(&p2).unwrap().observations.is_empty());
}

#[test]
fn cap_drops_writes() {
    let (_d, p) = setup();
    append_observation(&p, &obs(0, "first")).unwrap();
    let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(MAX_SPOOL_BYTES).unwrap();
    drop(f);
    assert_eq!(
        append_observation(&p, &obs(1, "dropped")).unwrap(),
        AppendOutcome::DroppedFull
    );
    assert_eq!(fs::metadata(&p).unwrap().len(), MAX_SPOOL_BYTES);
    // Just under the cap still appends.
    let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(MAX_SPOOL_BYTES - 1).unwrap();
    drop(f);
    assert_eq!(
        append_observation(&p, &obs(2, "ok")).unwrap(),
        AppendOutcome::Appended
    );
}

#[test]
fn oversized_line_is_not_written() {
    let (_d, p) = setup();
    let mut o = obs(0, "x");
    o.repo_key = "r".repeat(MAX_SPOOL_LINE_BYTES);
    assert_eq!(
        append_observation(&p, &o).unwrap(),
        AppendOutcome::DroppedTooLarge
    );
}

#[test]
fn malformed_lines_are_skipped() {
    let (_d, p) = setup();
    append_observation(&p, &obs(0, "good one")).unwrap();
    {
        let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"not json\n\n   \n{\"id\":\"obs_x\"}\n")
            .unwrap();
        f.write_all(&vec![b'z'; MAX_SPOOL_LINE_BYTES * 2]).unwrap();
        f.write_all(b"\n\xff\xfe\n").unwrap();
    }
    append_observation(&p, &obs(1, "good two")).unwrap();
    // A final line without a newline (torn write) is still parsed if complete.
    {
        let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(serde_json::to_string(&obs(2, "tail")).unwrap().as_bytes())
            .unwrap();
    }
    let d = drain(&p).unwrap();
    let texts: Vec<&str> = d.observations.iter().map(|o| o.text.as_str()).collect();
    assert_eq!(texts, ["good one", "good two", "tail"]);
    assert_eq!(d.skipped_lines, 4);
}

#[test]
fn tampered_spool_is_redacted_on_drain() {
    let (_d, p) = setup();
    let mut o = obs(0, "clean");
    o.text = "my key sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE".to_owned();
    o.repo_key = "k".repeat(1000);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, format!("{}\n", serde_json::to_string(&o).unwrap())).unwrap();
    let d = drain(&p).unwrap();
    assert_eq!(d.observations.len(), 1);
    assert!(!d.observations[0].text.contains("FAKE"));
    assert!(d.observations[0].repo_key.len() <= 128);
}

#[test]
fn leftover_processing_file_is_recovered() {
    let (_d, p) = setup();
    append_observation(&p, &obs(0, "old")).unwrap();
    fs::rename(&p, processing_path(&p)).unwrap();
    append_observation(&p, &obs(1, "new")).unwrap();
    let d = drain(&p).unwrap();
    let texts: Vec<&str> = d.observations.iter().map(|o| o.text.as_str()).collect();
    assert_eq!(texts, ["old", "new"]);
    assert!(!processing_path(&p).exists());
}

#[cfg(unix)]
#[test]
fn symlinked_spool_is_refused() {
    let (d, p) = setup();
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let target = d.path().join("elsewhere");
    fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, &p).unwrap();
    assert!(matches!(
        append_observation(&p, &obs(0, "x")),
        Err(SpoolError::Symlink)
    ));
    assert!(matches!(drain(&p), Err(SpoolError::Symlink)));
    assert_eq!(fs::read(&target).unwrap(), b"");
}

#[test]
fn concurrent_appends_do_not_interleave() {
    let (_d, p) = setup();
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let p = p.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    let text = format!("thread {t} item {i} {}", "pad ".repeat(200));
                    append_observation(&p, &obs(t * 1000 + i, &text)).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let d = drain(&p).unwrap();
    assert_eq!(d.observations.len(), 400);
    assert_eq!(d.skipped_lines, 0);
}

#[test]
fn error_display_has_no_content() {
    let e = SpoolError::Io {
        op: "write",
        kind: std::io::ErrorKind::PermissionDenied,
    };
    assert_eq!(e.to_string(), "spool write failed: permission denied");
}

/// A dangling symlink is refused too, and its target is never created.
#[cfg(unix)]
#[test]
fn dangling_symlink_spool_is_refused() {
    let (d, p) = setup();
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let target = d.path().join("created-through-link");
    std::os::unix::fs::symlink(&target, &p).unwrap();
    assert!(matches!(
        append_observation(&p, &obs(0, "x")),
        Err(SpoolError::Symlink)
    ));
    assert!(!target.exists());
}

/// A FIFO planted at the spool path must never block the hook (or a drain).
#[cfg(unix)]
#[test]
fn fifo_spool_never_blocks() {
    use std::sync::mpsc;
    use std::time::Duration;
    let (_d, p) = setup();
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&p)
        .status()
        .unwrap()
        .success());
    let (tx, rx) = mpsc::channel();
    let p2 = p.clone();
    std::thread::spawn(move || {
        let a = append_observation(&p2, &obs(0, "x"));
        let d = drain(&p2);
        let _ = tx.send((a, d));
    });
    let (a, d) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("spool blocked on a FIFO");
    assert!(matches!(a, Err(SpoolError::NotRegularFile)));
    // Drain claims and discards the FIFO entry, so the next append works again.
    assert!(d.unwrap().observations.is_empty());
    assert!(!p.exists());
    assert_eq!(
        append_observation(&p, &obs(1, "y")).unwrap(),
        AppendOutcome::Appended
    );
}

/// Concurrent drains (CLI and daemon) split the data: every observation comes out
/// exactly once and nothing is left behind.
#[test]
fn concurrent_drains_never_lose_or_duplicate() {
    for _round in 0..5 {
        let (_d, p) = setup();
        for i in 0..300 {
            append_observation(&p, &obs(i, &format!("item {i}"))).unwrap();
        }
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || drain(&p).unwrap().observations)
            })
            .collect();
        let mut ids: Vec<String> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .map(|o| o.id.as_str().to_owned())
            .collect();
        assert_eq!(ids.len(), 300, "lost or duplicated observations");
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 300);
        assert_eq!(fs::read_dir(p.parent().unwrap()).unwrap().count(), 0);
    }
}

/// A claim file left by a crashed drain is recovered once it is stale; a fresh claim
/// (another drain in progress) is left alone.
#[test]
fn stale_claims_are_recovered_and_fresh_ones_left_alone() {
    let (_d, p) = setup();
    append_observation(&p, &obs(0, "stale")).unwrap();
    let now = Timestamp::now().unix_seconds();
    let stale = PathBuf::from(format!(
        "{}-{}-1-0",
        processing_path(&p).display(),
        now - 3600
    ));
    fs::rename(&p, &stale).unwrap();
    append_observation(&p, &obs(1, "busy")).unwrap();
    let fresh = PathBuf::from(format!("{}-{}-1-1", processing_path(&p).display(), now));
    fs::rename(&p, &fresh).unwrap();
    append_observation(&p, &obs(2, "new")).unwrap();
    let d = drain(&p).unwrap();
    let texts: Vec<&str> = d.observations.iter().map(|o| o.text.as_str()).collect();
    assert_eq!(texts, ["stale", "new"]);
    assert!(!stale.exists());
    assert!(fresh.exists());
}

/// What was claimed is deleted when its caller says it is stored, and not before
/// (ADR-051). A caller that could not store it drops the claim: the lines stay on
/// disk and a later drain reads them again. The spool used to be deleted as soon as
/// it was read.
#[test]
fn a_claim_keeps_its_lines_until_it_is_released() {
    let (_d, p) = setup();
    let dir = p.parent().unwrap().to_path_buf();
    let files = || -> Vec<PathBuf> {
        let mut all: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        all.sort();
        all
    };
    let items: Vec<_> = (0..3).map(|i| obs(i, &format!("line {i}"))).collect();
    for o in &items {
        append_observation(&p, o).unwrap();
    }

    // Claimed and read: the spool is a claim file now, and the lines are in it.
    let claimed = claim_spool(&p).unwrap();
    assert_eq!(claimed.observations, items);
    assert!(!p.exists());
    let kept = files();
    assert_eq!(kept.len(), 1);
    assert_eq!(fs::read_to_string(&kept[0]).unwrap().lines().count(), 3);

    // The caller could not store them. Nothing is deleted.
    drop(claimed);
    assert_eq!(files(), kept);
    // A drain that runs at once leaves another drain's fresh claim alone...
    assert!(claim_spool(&p).unwrap().observations.is_empty());
    assert_eq!(files(), kept);
    // ...and one that runs later reads the same lines again.
    let stale = PathBuf::from(format!(
        "{}-{}-1-0",
        processing_path(&p).display(),
        Timestamp::now().unix_seconds() - 3600
    ));
    fs::rename(&kept[0], &stale).unwrap();
    append_observation(&p, &obs(3, "line 3")).unwrap();
    let again = claim_spool(&p).unwrap();
    let texts: Vec<&str> = again.observations.iter().map(|o| o.text.as_str()).collect();
    assert_eq!(texts, ["line 0", "line 1", "line 2", "line 3"]);
    assert_eq!(
        files().len(),
        2,
        "the old claim and the spool, both claimed"
    );

    // Stored this time: released, and nothing is left.
    again.release().unwrap();
    assert!(files().is_empty());
    assert!(drain(&p).unwrap().observations.is_empty());
}
