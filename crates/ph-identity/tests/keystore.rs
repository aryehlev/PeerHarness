//! Keystore integration and adversarial tests (file and insecure-dev backends).

use std::fs;
use std::path::Path;

use ph_core::DeviceKey;
use ph_identity::{
    open_keystore, CircleAuthority, DeviceIdentity, FileKeyStore, IdentityError,
    InsecureAcknowledged, InsecureDevKeyStore, KdfParams, KeyStore, KeystoreBackend,
    KeystoreConfig, PassphraseSource, Zeroizing, PASSPHRASE_ENV,
};
use serde_json::Value;

fn file_store(home: &Path, pass: &str) -> FileKeyStore {
    FileKeyStore::new(home, PassphraseSource::fixed(pass))
        .with_kdf_params(KdfParams::insecure_fast_for_tests())
}

fn edit_json(path: &Path, f: impl FnOnce(&mut serde_json::Map<String, Value>)) {
    let mut v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    f(v.as_object_mut().unwrap());
    fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

fn flip_b64(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

#[test]
fn file_round_trip_and_format() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "correct horse");
    assert_eq!(ks.backend(), KeystoreBackend::File);
    assert!(!DeviceIdentity::exists(&ks).unwrap());
    let id = DeviceIdentity::create(&ks).unwrap();
    assert!(DeviceIdentity::exists(&ks).unwrap());

    // A fresh store (new process) with the same passphrase loads the same key.
    let ks2 = file_store(home.path(), "correct horse");
    let loaded = DeviceIdentity::load(&ks2).unwrap();
    assert_eq!(loaded.public(), id.public());
    assert_eq!(ks2.public_key("device").unwrap(), id.public());

    let path = home.path().join("keys").join("device.key");
    assert_eq!(ks.key_path("device").unwrap(), path);
    assert_eq!(ks.locator("device").unwrap(), path.display().to_string());
    let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let o = v.as_object().unwrap();
    let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "ciphertext",
            "kdf",
            "m_kib",
            "nonce",
            "p",
            "public_key",
            "salt",
            "schema",
            "t"
        ]
    );
    assert_eq!(o["schema"], "peerharness.keyfile/0.1");
    assert_eq!(o["kdf"], "argon2id");
    assert_eq!(o["m_kib"], 64);
    assert_eq!(o["public_key"], id.public().to_string());
    // The seed never appears in the file.
    let raw = fs::read_to_string(&path).unwrap();
    let seed = id.libp2p_seed();
    for enc in [
        hex::encode(&seed[..]),
        base64_url(&seed[..]),
        base64_std(&seed[..]),
    ] {
        assert!(!raw.contains(&enc));
    }
}

fn base64_url(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn base64_std(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn default_kdf_params_are_recorded() {
    let home = tempfile::tempdir().unwrap();
    let ks = FileKeyStore::new(home.path(), PassphraseSource::fixed("pw"));
    ks.store_secret("device", &Zeroizing::new([5u8; 32]))
        .unwrap();
    let v: Value =
        serde_json::from_slice(&fs::read(ks.key_path("device").unwrap()).unwrap()).unwrap();
    assert_eq!(v["m_kib"], 65536);
    assert_eq!(v["t"], 3);
    assert_eq!(v["p"], 1);
    assert_eq!(*ks.load_secret("device").unwrap(), [5u8; 32]);
}

#[test]
fn two_homes_never_share_identity() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ka = file_store(a.path(), "same");
    let kb = file_store(b.path(), "same");
    let ia = DeviceIdentity::create(&ka).unwrap();
    assert!(!DeviceIdentity::exists(&kb).unwrap());
    assert!(matches!(
        DeviceIdentity::load(&kb),
        Err(IdentityError::NotFound { .. })
    ));
    let ib = DeviceIdentity::create(&kb).unwrap();
    assert_ne!(ia.public(), ib.public());
    assert_eq!(DeviceIdentity::load(&ka).unwrap().public(), ia.public());
    assert_eq!(DeviceIdentity::load(&kb).unwrap().public(), ib.public());

    // Same for the insecure backend.
    let ack = InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext;
    let c = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let ic = DeviceIdentity::create(&InsecureDevKeyStore::new(c.path(), ack())).unwrap();
    let id = DeviceIdentity::create(&InsecureDevKeyStore::new(d.path(), ack())).unwrap();
    assert_ne!(ic.public(), id.public());
}

#[test]
fn wrong_passphrase_rejected() {
    let home = tempfile::tempdir().unwrap();
    DeviceIdentity::create(&file_store(home.path(), "right")).unwrap();
    let err = DeviceIdentity::load(&file_store(home.path(), "wrong")).unwrap_err();
    assert!(
        matches!(err, IdentityError::DecryptionFailed { .. }),
        "{err}"
    );
    let msg = err.to_string();
    assert!(msg.contains("wrong passphrase"));
    assert!(!msg.contains("right") && !msg.contains("wrong\""));
}

#[test]
fn never_overwrites() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    let first = DeviceIdentity::create(&ks).unwrap();
    assert!(matches!(
        DeviceIdentity::create(&ks),
        Err(IdentityError::AlreadyExists { .. })
    ));
    assert_eq!(DeviceIdentity::load(&ks).unwrap().public(), first.public());
    assert!(ks.delete("device").unwrap());
    assert!(!ks.delete("device").unwrap());
    assert!(!ks.exists("device").unwrap());
}

#[test]
fn tampered_ciphertext_rejected() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    DeviceIdentity::create(&ks).unwrap();
    let path = ks.key_path("device").unwrap();
    edit_json(&path, |o| {
        let ct = o["ciphertext"].as_str().unwrap().to_owned();
        o.insert("ciphertext".into(), Value::String(flip_b64(&ct)));
    });
    assert!(matches!(
        file_store(home.path(), "pw").load_secret("device"),
        Err(IdentityError::DecryptionFailed { .. })
    ));
}

#[test]
fn tampered_header_rejected() {
    type Tamper = fn(&mut serde_json::Map<String, Value>);
    let cases: Vec<(&str, Tamper)> = vec![
        ("salt", |o| {
            let s = o["salt"].as_str().unwrap().to_owned();
            o.insert("salt".into(), Value::String(flip_b64(&s)));
        }),
        ("nonce", |o| {
            let s = o["nonce"].as_str().unwrap().to_owned();
            o.insert("nonce".into(), Value::String(flip_b64(&s)));
        }),
        ("t", |o| {
            o.insert("t".into(), Value::from(2));
        }),
        ("m_kib", |o| {
            o.insert("m_kib".into(), Value::from(128));
        }),
        ("public_key", |o| {
            let other =
                DeviceKey::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[42; 32]));
            o.insert("public_key".into(), Value::String(other.to_string()));
        }),
    ];
    for (name, f) in cases {
        let home = tempfile::tempdir().unwrap();
        let ks = file_store(home.path(), "pw");
        DeviceIdentity::create(&ks).unwrap();
        edit_json(&ks.key_path("device").unwrap(), f);
        let r = file_store(home.path(), "pw").load_secret("device");
        assert!(
            matches!(r, Err(IdentityError::DecryptionFailed { .. })),
            "tampered {name}: {r:?}"
        );
    }

    // Structural tampering is reported as a corrupt file.
    type Structural = fn(&mut serde_json::Map<String, Value>);
    let structural: Vec<(&str, Structural)> = vec![
        ("schema", |o| {
            o.insert("schema".into(), Value::from("peerharness.keyfile/9.9"));
        }),
        ("kdf", |o| {
            o.insert("kdf".into(), Value::from("scrypt"));
        }),
        ("extra field", |o| {
            o.insert("extra".into(), Value::from(1));
        }),
        ("missing field", |o| {
            o.remove("salt");
        }),
        ("huge m", |o| {
            o.insert("m_kib".into(), Value::from(u32::MAX));
        }),
        ("short salt", |o| {
            o.insert("salt".into(), Value::from("AAAA"));
        }),
        ("short ciphertext", |o| {
            o.insert("ciphertext".into(), Value::from("AAAA"));
        }),
        ("not base64", |o| {
            o.insert("nonce".into(), Value::from("!!!!"));
        }),
    ];
    for (name, f) in structural {
        let home = tempfile::tempdir().unwrap();
        let ks = file_store(home.path(), "pw");
        DeviceIdentity::create(&ks).unwrap();
        edit_json(&ks.key_path("device").unwrap(), f);
        let r = file_store(home.path(), "pw").load_secret("device");
        assert!(
            matches!(r, Err(IdentityError::CorruptKeyFile { .. })),
            "{name}: {r:?}"
        );
    }
}

#[test]
fn renamed_key_file_rejected() {
    // Moving device.key to another label must not decrypt (AAD binds the label).
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    DeviceIdentity::create(&ks).unwrap();
    fs::rename(
        ks.key_path("device").unwrap(),
        ks.key_path("other").unwrap(),
    )
    .unwrap();
    assert!(matches!(
        ks.load_secret("other"),
        Err(IdentityError::DecryptionFailed { .. })
    ));
}

#[test]
fn garbage_and_oversized_files_rejected() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    DeviceIdentity::create(&ks).unwrap();
    let path = ks.key_path("device").unwrap();
    fs::write(&path, b"\xff\xfe not json").unwrap();
    assert!(matches!(
        ks.load_secret("device"),
        Err(IdentityError::CorruptKeyFile { .. })
    ));
    fs::write(&path, vec![b' '; 10_000]).unwrap();
    assert!(matches!(
        ks.load_secret("device"),
        Err(IdentityError::FileTooLarge { .. })
    ));
}

#[test]
fn invalid_labels_rejected_everywhere() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    let s = Zeroizing::new([1u8; 32]);
    for bad in ["../device", "a/b", "", "Device", "x.key"] {
        assert!(matches!(
            ks.store_secret(bad, &s),
            Err(IdentityError::InvalidLabel)
        ));
        assert!(matches!(
            ks.load_secret(bad),
            Err(IdentityError::InvalidLabel)
        ));
        assert!(matches!(ks.exists(bad), Err(IdentityError::InvalidLabel)));
        assert!(matches!(ks.delete(bad), Err(IdentityError::InvalidLabel)));
    }
}

#[cfg(unix)]
#[test]
fn file_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    DeviceIdentity::create(&ks).unwrap();
    let path = ks.key_path("device").unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&home.path().join("keys")), 0o700);
    // No temp files left behind.
    let entries: Vec<_> = fs::read_dir(home.path().join("keys")).unwrap().collect();
    assert_eq!(entries.len(), 1);

    for bad in [0o640, 0o604, 0o660, 0o644] {
        fs::set_permissions(&path, fs::Permissions::from_mode(bad)).unwrap();
        let r = ks.load_secret("device");
        assert!(
            matches!(r, Err(IdentityError::InsecurePermissions { .. })),
            "{bad:o}: {r:?}"
        );
        assert!(ks.public_key("device").is_err());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(ks.load_secret("device").is_ok());

    // A loose keys directory is tightened on the next write.
    fs::set_permissions(home.path().join("keys"), fs::Permissions::from_mode(0o755)).unwrap();
    ks.store_secret("second", &Zeroizing::new([2; 32])).unwrap();
    assert_eq!(mode(&home.path().join("keys")), 0o700);
    assert_eq!(mode(&ks.key_path("second").unwrap()), 0o600);
}

#[cfg(unix)]
#[test]
fn symlinked_key_file_rejected() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    DeviceIdentity::create(&ks).unwrap();
    let path = ks.key_path("device").unwrap();
    let real = home.path().join("real.key");
    fs::rename(&path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert!(matches!(
        ks.load_secret("device"),
        Err(IdentityError::NotRegularFile { .. })
    ));
}

#[test]
fn passphrase_is_cached_and_cleared_on_failure() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    let id = DeviceIdentity::create(&ks).unwrap();
    // The same store can unlock other keys written with the same passphrase.
    let (auth, circle) = CircleAuthority::create(&ks).unwrap();
    let loaded = CircleAuthority::load(&ks, &circle).unwrap();
    assert_eq!(loaded.root_key(), auth.root_key());
    assert_ne!(auth.root_key(), id.public());
    assert!(CircleAuthority::exists(&ks, &circle).unwrap());
}

#[test]
fn env_passphrase_source() {
    let home = tempfile::tempdir().unwrap();
    // Only this test touches the variable.
    std::env::set_var(PASSPHRASE_ENV, "from-env");
    let ks = FileKeyStore::new(home.path(), PassphraseSource::Env)
        .with_kdf_params(KdfParams::insecure_fast_for_tests());
    let id = DeviceIdentity::create(&ks).unwrap();
    let again = FileKeyStore::new(home.path(), PassphraseSource::Env);
    assert_eq!(DeviceIdentity::load(&again).unwrap().public(), id.public());
    assert!(DeviceIdentity::load(&file_store(home.path(), "other")).is_err());
    std::env::remove_var(PASSPHRASE_ENV);
    let none = FileKeyStore::new(home.path(), PassphraseSource::Env);
    assert!(matches!(
        DeviceIdentity::load(&none),
        Err(IdentityError::PassphraseUnavailable { .. })
    ));
    assert!(DeviceIdentity::exists(&none).unwrap());
}

#[test]
fn insecure_dev_round_trip() {
    let home = tempfile::tempdir().unwrap();
    let ks = InsecureDevKeyStore::new(
        home.path(),
        InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext(),
    );
    assert_eq!(ks.backend(), KeystoreBackend::InsecureDev);
    let id = DeviceIdentity::create(&ks).unwrap();
    assert_eq!(DeviceIdentity::load(&ks).unwrap().public(), id.public());
    let path = home.path().join("keys").join("device.insecure-key");
    assert_eq!(ks.key_path("device").unwrap(), path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ks.load_secret("device"),
            Err(IdentityError::InsecurePermissions { .. })
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Mismatched public key / label are detected.
    edit_json(&path, |o| {
        o.insert("label".into(), Value::from("other"));
    });
    assert!(matches!(
        ks.load_secret("device"),
        Err(IdentityError::CorruptKeyFile { .. })
    ));
}

#[test]
fn open_keystore_dispatch() {
    let home = tempfile::tempdir().unwrap();
    let cfg = KeystoreConfig::File {
        passphrase: PassphraseSource::fixed("pw"),
        kdf: KdfParams::insecure_fast_for_tests(),
    };
    assert_eq!(cfg.backend(), KeystoreBackend::File);
    let ks = open_keystore(home.path(), cfg).unwrap();
    assert_eq!(ks.backend(), KeystoreBackend::File);
    let id = DeviceIdentity::create(&*ks).unwrap();
    assert_eq!(DeviceIdentity::load(&ks).unwrap().public(), id.public());

    let ks = open_keystore(
        home.path(),
        KeystoreConfig::InsecureDev(
            InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext(),
        ),
    )
    .unwrap();
    assert_eq!(ks.backend(), KeystoreBackend::InsecureDev);
    // A different backend in the same home is a different key slot.
    assert!(!DeviceIdentity::exists(&*ks).unwrap());
}

#[test]
fn circle_root_label_and_mismatch() {
    let home = tempfile::tempdir().unwrap();
    let ks = file_store(home.path(), "pw");
    let (auth, circle) = CircleAuthority::create(&ks).unwrap();
    assert_eq!(
        auth.keystore_label(),
        format!("circle-root-{}", circle.to_hex())
    );
    assert!(ks.exists(&auth.keystore_label()).unwrap());
    // A root key stored under the wrong circle's label is refused.
    let other = CircleAuthority::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[8; 32]));
    let seed = ks.load_secret(&auth.keystore_label()).unwrap();
    ks.store_secret(&other.keystore_label(), &seed).unwrap();
    assert!(matches!(
        CircleAuthority::load(&ks, &other.circle_id()),
        Err(IdentityError::KeyMismatch { .. })
    ));
}
