//! BundleStore: atomic immutable puts and verified gets.

use std::fs;

use ph_skills::*;

const PNPM: &str = include_str!("fixtures/pnpm-repository-convention/SKILL.md");

fn bundle() -> Bundle {
    build_bundle(PNPM, None).unwrap()
}

#[test]
fn put_get_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path().join("bundles"));
    let b = bundle();
    assert!(store.list().unwrap().is_empty());
    assert!(matches!(store.get(&b.digest()), Err(StoreError::NotFound)));

    let o = store.put(&b).unwrap();
    assert!(o.newly_stored);
    assert_eq!(o.path, store.path_for(&b.digest()));
    assert_eq!(
        store.path_for(&b.digest()),
        tmp.path()
            .join("bundles")
            .join(b.digest().to_hex())
            .join("SKILL.md")
    );
    assert_eq!(
        BundleStore::relative_path(&b.digest()),
        format!("{}/SKILL.md", b.digest().to_hex())
    );
    assert_eq!(fs::read_to_string(&o.path).unwrap(), PNPM);
    assert!(fs::metadata(&o.path).unwrap().permissions().readonly());
    assert!(store.contains(&b.digest()));

    let again = store.put(&b).unwrap();
    assert!(!again.newly_stored);
    assert_eq!(store.get(&b.digest()).unwrap(), b);
    assert_eq!(store.list().unwrap(), vec![b.digest()]);
    // no staging leftovers
    let names: Vec<_> = fs::read_dir(store.root())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1);
    assert_eq!(store.cleanup_staging().unwrap(), 0);
}

#[test]
fn tampered_content_is_detected_and_never_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path());
    let b = bundle();
    let o = store.put(&b).unwrap();
    let mut perms = fs::metadata(&o.path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&o.path, perms).unwrap();
    fs::write(&o.path, PNPM.replace("pnpm instead", "yarn instead")).unwrap();
    assert!(matches!(
        store.get(&b.digest()),
        Err(StoreError::Corrupt(BundleError::DigestMismatch))
    ));
    // put refuses to "repair" by overwriting
    assert!(matches!(store.put(&b), Err(StoreError::Corrupt(_))));
    assert!(fs::read_to_string(&o.path)
        .unwrap()
        .contains("yarn instead"));
}

#[test]
fn extra_files_in_store_dir_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path());
    let b = bundle();
    store.put(&b).unwrap();
    fs::write(store.dir_for(&b.digest()).join("payload.sh"), "#!/bin/sh\n").unwrap();
    assert!(matches!(
        store.get(&b.digest()),
        Err(StoreError::UnexpectedEntry)
    ));
    assert!(matches!(store.put(&b), Err(StoreError::UnexpectedEntry)));
}

#[test]
fn missing_skill_file_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path());
    let b = bundle();
    fs::create_dir_all(store.dir_for(&b.digest())).unwrap();
    assert!(matches!(
        store.get(&b.digest()),
        Err(StoreError::Corrupt(BundleError::Empty))
    ));
}

#[test]
fn leftover_staging_is_cleaned() {
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path());
    fs::create_dir_all(tmp.path().join(".staging-deadbeef")).unwrap();
    fs::write(tmp.path().join(".staging-deadbeef/SKILL.md"), "x").unwrap();
    assert_eq!(store.cleanup_staging().unwrap(), 1);
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn case_variant_file_name_rejected() {
    // `skill.md` must not be accepted as `SKILL.md`, even on case-insensitive
    // filesystems where opening `SKILL.md` would find it.
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path());
    let b = bundle();
    let dir = store.dir_for(&b.digest());
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("skill.md"), PNPM).unwrap();
    assert!(matches!(
        store.get(&b.digest()),
        Err(StoreError::UnexpectedEntry)
    ));
    assert!(store.put(&b).is_err());
}

#[test]
fn bundle_under_wrong_digest_dir_rejected() {
    // Content stored (or planted) under another digest's directory never verifies.
    let tmp = tempfile::tempdir().unwrap();
    let store = BundleStore::new(tmp.path());
    let b = bundle();
    let other = ph_core::Digest::sha256(b"other");
    let dir = store.dir_for(&other);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), PNPM).unwrap();
    assert!(matches!(
        store.get(&other),
        Err(StoreError::Corrupt(BundleError::DigestMismatch))
    ));
    assert!(store.get(&b.digest()).is_err());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlinked_bundle_dir_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BundleStore::new(tmp.path().join("bundles"));
        let b = bundle();
        // Attacker prepares a directory elsewhere with matching content and links it in.
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("SKILL.md"), PNPM).unwrap();
        fs::create_dir_all(store.root()).unwrap();
        symlink(&elsewhere, store.dir_for(&b.digest())).unwrap();
        assert!(matches!(store.get(&b.digest()), Err(StoreError::Symlink)));
        assert!(matches!(store.put(&b), Err(StoreError::Symlink)));
    }

    #[test]
    fn symlinked_skill_file_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BundleStore::new(tmp.path().join("bundles"));
        let b = bundle();
        let target = tmp.path().join("target.md");
        fs::write(&target, PNPM).unwrap();
        let dir = store.dir_for(&b.digest());
        fs::create_dir_all(&dir).unwrap();
        symlink(&target, dir.join("SKILL.md")).unwrap();
        assert!(matches!(store.get(&b.digest()), Err(StoreError::Symlink)));
    }

    #[test]
    fn symlink_next_to_skill_file_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BundleStore::new(tmp.path());
        let b = bundle();
        store.put(&b).unwrap();
        symlink("/etc/passwd", store.dir_for(&b.digest()).join("link")).unwrap();
        assert!(matches!(
            store.get(&b.digest()),
            Err(StoreError::UnexpectedEntry)
        ));
    }

    #[test]
    fn fifo_skill_file_rejected_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BundleStore::new(tmp.path());
        let b = bundle();
        let dir = store.dir_for(&b.digest());
        fs::create_dir_all(&dir).unwrap();
        let ok = std::process::Command::new("mkfifo")
            .arg(dir.join("SKILL.md"))
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("mkfifo unavailable; skipping");
            return;
        }
        assert!(matches!(
            store.get(&b.digest()),
            Err(StoreError::NotRegular)
        ));
        assert!(matches!(store.put(&b), Err(StoreError::NotRegular)));
    }

    #[test]
    fn hard_link_content_still_verified() {
        // A hard link is a regular file; it is accepted only if its content verifies.
        let tmp = tempfile::tempdir().unwrap();
        let store = BundleStore::new(tmp.path().join("bundles"));
        let b = bundle();
        let outside = tmp.path().join("outside.md");
        fs::write(&outside, PNPM.replace("pnpm instead", "yarn instead")).unwrap();
        let dir = store.dir_for(&b.digest());
        fs::create_dir_all(&dir).unwrap();
        fs::hard_link(&outside, dir.join("SKILL.md")).unwrap();
        assert!(matches!(
            store.get(&b.digest()),
            Err(StoreError::Corrupt(BundleError::DigestMismatch))
        ));
    }
}
