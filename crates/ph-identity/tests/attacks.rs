//! Adversarial tests added during review: capability mixing across credentials, stolen
//! (bearer) invites, forged acceptances and revocations, stored-proof loading,
//! credential presentation policy, keystore passphrase consistency and no-clobber
//! creation, and secret-free error messages.

use ed25519_dalek::SigningKey;
use ph_core::{Capability, DenyReason, DeviceKey, MembershipOracle, Role, Scope, Timestamp};
use ph_identity::{
    accept_credential, accept_invite, invite_to_bytes, validate_invite, AddOutcome,
    CircleAuthority, DeviceIdentity, FileKeyStore, IdentityError, InsecureAcknowledged,
    InsecureDevKeyStore, InviteRejection, KdfParams, KeyStore, MembershipRegistry,
    MembershipRejection, PassphraseSource, Zeroizing,
};
use ph_protocol::signing::sign_input;
use ph_protocol::{
    Acceptance, MembershipProof, Revocation, UnsignedAcceptance, UnsignedMembershipCredential,
    UnsignedRevocation,
};

fn t0() -> Timestamp {
    "2026-11-09T18:00:00Z".parse().unwrap()
}
fn scope(s: &str) -> Scope {
    Scope::new(s).unwrap()
}
fn dev(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_signing_key(SigningKey::from_bytes(&[seed; 32]))
}
fn authority(seed: u8) -> CircleAuthority {
    CircleAuthority::from_signing_key(SigningKey::from_bytes(&[seed; 32]))
}

/// A registry with circle `auth` registered.
fn registry(auth: &CircleAuthority) -> MembershipRegistry {
    let mut reg = MembershipRegistry::new();
    reg.add_circle(auth.circle_id(), auth.root_key()).unwrap();
    reg
}

fn enroll(
    reg: &mut MembershipRegistry,
    auth: &CircleAuthority,
    who: &DeviceIdentity,
    roles: Vec<Role>,
    scopes: &[&str],
    ttl: i64,
    now: Timestamp,
) -> MembershipProof {
    let cred = auth
        .issue_credential(
            who.public(),
            roles,
            scopes.iter().map(|s| scope(s)).collect(),
            ttl,
            now,
        )
        .unwrap();
    let proof = accept_credential(&cred, who, now).unwrap();
    assert_eq!(
        reg.add_proof(proof.clone(), now).unwrap(),
        AddOutcome::Added
    );
    proof
}

#[test]
fn capabilities_and_scopes_never_mix_across_credentials() {
    let auth = authority(100);
    let mut reg = registry(&auth);
    let c = auth.circle_id();
    let alice = dev(1);
    // Member everywhere under `team`, owner only under `team/x`.
    enroll(
        &mut reg,
        &auth,
        &alice,
        vec![Role::Member],
        &["team"],
        86_400,
        t0(),
    );
    enroll(
        &mut reg,
        &auth,
        &alice,
        vec![Role::Owner],
        &["team/x"],
        86_400,
        t0(),
    );
    let now = t0().plus_secs(10);
    let k = alice.public();
    // Owner capability in the owner credential's scope: allowed.
    assert_eq!(
        reg.authorize(&c, &k, &scope("team/x/sub"), Capability::Revoke, now),
        Ok(())
    );
    // `team/y` is covered by the member credential, `revoke` by the owner credential,
    // but no single credential grants both.
    assert_eq!(
        reg.authorize(&c, &k, &scope("team/y"), Capability::Revoke, now),
        Err(DenyReason::CapabilityDenied)
    );
    assert_eq!(
        reg.authorize(&c, &k, &scope("team/y"), Capability::Invite, now),
        Err(DenyReason::CapabilityDenied)
    );
    assert_eq!(
        reg.authorize(&c, &k, &scope("team/y"), Capability::Vote, now),
        Ok(())
    );
    // Outside every scope.
    assert_eq!(
        reg.authorize(&c, &k, &scope("other"), Capability::Read, now),
        Err(DenyReason::ScopeDenied)
    );
    // A parent of a granted scope is not covered, and `*` as an object is not covered
    // by a non-wildcard grant.
    assert_eq!(
        reg.authorize(&c, &k, &Scope::all(), Capability::Read, now),
        Err(DenyReason::ScopeDenied)
    );
}

#[test]
fn expired_strong_credential_does_not_lend_power_to_active_weak_one() {
    let auth = authority(100);
    let mut reg = registry(&auth);
    let c = auth.circle_id();
    let bob = dev(2);
    enroll(&mut reg, &auth, &bob, vec![Role::Owner], &["*"], 60, t0());
    enroll(
        &mut reg,
        &auth,
        &bob,
        vec![Role::Member],
        &["team"],
        86_400,
        t0(),
    );
    let later = t0().plus_secs(120);
    assert_eq!(
        reg.authorize(&c, &bob.public(), &scope("team"), Capability::Revoke, later),
        Err(DenyReason::CapabilityDenied)
    );
    assert_eq!(
        reg.authorize(&c, &bob.public(), &scope("ops"), Capability::Read, later),
        Err(DenyReason::ScopeDenied)
    );
    assert_eq!(
        reg.authorize(&c, &bob.public(), &scope("team"), Capability::Ask, later),
        Ok(())
    );
}

#[test]
fn revoked_owner_loses_everything_even_with_fresh_owner_credentials() {
    let auth = authority(100);
    let mut reg = registry(&auth);
    let c = auth.circle_id();
    let owner = dev(3);
    enroll(
        &mut reg,
        &auth,
        &owner,
        vec![Role::Owner, Role::Member],
        &["*"],
        86_400,
        t0(),
    );
    let now = t0().plus_secs(5);
    reg.add_revocation(auth.issue_revocation(owner.public(), "", now).unwrap(), now)
        .unwrap();
    let later = now.plus_secs(5);
    enroll(
        &mut reg,
        &auth,
        &owner,
        vec![Role::Owner],
        &["*"],
        86_400,
        later,
    );
    for cap in Capability::ALL {
        assert_eq!(
            reg.authorize(&c, &owner.public(), &scope("a"), cap, later),
            Err(DenyReason::Revoked)
        );
    }
    assert!(!reg.is_active_member(&c, &owner.public(), later));
    assert!(reg
        .proofs_to_present(&owner.public(), &dev(9).public(), later)
        .is_empty());
    let view = reg.members(&c, later);
    assert!(view[0].revoked && !view[0].active);
}

#[test]
fn stolen_invite_is_useless_without_the_subject_key() {
    let auth = authority(100);
    let founder = dev(1);
    let bob = dev(2);
    let mallory = dev(66);
    let invite = auth
        .invite_member(
            "Backend",
            bob.public(),
            vec![Role::Member],
            vec![scope("team")],
            founder.public(),
            vec![],
            t0(),
        )
        .unwrap();
    let bytes = invite_to_bytes(&invite).unwrap();
    let now = t0().plus_secs(30);

    // Mallory cannot validate it for herself...
    assert!(matches!(
        validate_invite(&bytes, &mallory.public(), now),
        Err(IdentityError::Invite(InviteRejection::NotForThisDevice))
    ));
    // ...and validating it "as Bob" (Bob's public key is public) does not let her accept.
    let as_bob = validate_invite(&bytes, &bob.public(), now).unwrap();
    assert!(matches!(
        accept_invite(&as_bob, &mallory, now),
        Err(IdentityError::KeyMismatch { .. })
    ));
    // The protocol refuses to sign an acceptance for someone else's key.
    assert!(UnsignedAcceptance::for_credential(&invite.credential, now)
        .unwrap()
        .sign(mallory.signing_key())
        .is_err());

    let mut reg = registry(&auth);
    let c = auth.circle_id();
    // Hand-forged acceptance: Bob's acceptance body, Mallory's signature.
    let unsigned = UnsignedAcceptance::for_credential(&invite.credential, now).unwrap();
    let forged = Acceptance {
        signature: sign_input(mallory.signing_key(), &unsigned.signing_input().unwrap()),
        unsigned,
    };
    let proof = MembershipProof {
        credential: invite.credential.clone(),
        acceptance: forged,
    };
    assert!(matches!(
        reg.add_proof(proof.clone(), now),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidProof(_)
        ))
    ));
    assert!(matches!(
        reg.add_stored_proof(proof, now),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidProof(_)
        ))
    ));
    // Acceptance that names Mallory as the subject of Bob's credential.
    let mut unsigned = UnsignedAcceptance::for_credential(&invite.credential, now).unwrap();
    unsigned.subject_device_key = mallory.public();
    let acc = unsigned.sign(mallory.signing_key()).unwrap();
    let proof = MembershipProof {
        credential: invite.credential.clone(),
        acceptance: acc,
    };
    assert!(reg.add_proof(proof, now).is_err());
    assert_eq!(
        reg.authorize(&c, &mallory.public(), &scope("team"), Capability::Read, now),
        Err(DenyReason::NotMember)
    );

    // Bob's genuine proof, replayed by Mallory over her own transport identity.
    let genuine = accept_invite(&as_bob, &bob, now).unwrap();
    let out = reg.accept_presented_proofs(&mallory.public(), &[genuine], now);
    assert_eq!(out.rejected, 1);
    assert!(out.active_circles.is_empty());
    assert!(!reg.is_active_member(&c, &mallory.public(), now));
    assert!(!reg.is_active_member(&c, &bob.public(), now));
}

#[test]
fn forged_and_foreign_revocations_rejected() {
    let auth = authority(100);
    let other = authority(101);
    let mut reg = registry(&auth);
    reg.add_circle(other.circle_id(), other.root_key()).unwrap();
    let c = auth.circle_id();
    let bob = dev(2);
    enroll(
        &mut reg,
        &auth,
        &bob,
        vec![Role::Member],
        &["team"],
        86_400,
        t0(),
    );
    let now = t0().plus_secs(10);

    // Another circle's root revoking Bob in its own circle does not touch ours.
    reg.add_revocation(other.issue_revocation(bob.public(), "", now).unwrap(), now)
        .unwrap();
    assert!(!reg.is_revoked(&c, &bob.public()));
    assert!(reg.is_active_member(&c, &bob.public(), now));

    // A revocation claiming our circle id but signed by another key.
    let mut unsigned = UnsignedRevocation::new(
        auth.root_key(),
        bob.public(),
        now,
        String::new(),
        ph_core::Nonce::from_bytes([7; 16]),
    );
    let forged = Revocation {
        signature: sign_input(other.signing_key(), &unsigned.signing_input().unwrap()),
        unsigned: unsigned.clone(),
    };
    assert!(matches!(
        reg.add_revocation(forged, now),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidRevocation(_)
        ))
    ));
    // Claiming our circle id with the other root as issuer.
    unsigned.issuer_key = other.root_key();
    let mixed = Revocation {
        signature: sign_input(other.signing_key(), &unsigned.signing_input().unwrap()),
        unsigned,
    };
    assert!(matches!(
        reg.add_revocation(mixed, now),
        Err(IdentityError::Membership(
            MembershipRejection::IssuerNotRoot
        ))
    ));
    // A member (even an owner) cannot author a valid revocation in v0.
    let member_signed = UnsignedRevocation::new(
        bob.public(),
        bob.public(),
        now,
        String::new(),
        ph_core::Nonce::from_bytes([8; 16]),
    )
    .sign(bob.signing_key())
    .unwrap();
    assert!(reg.add_revocation(member_signed, now).is_err());
    assert!(!reg.is_revoked(&c, &bob.public()));

    // Far-future-dated revocations are refused now (beyond the clock-skew allowance).
    let future = auth
        .issue_revocation(bob.public(), "", now.plus_secs(3600))
        .unwrap();
    assert!(reg.add_revocation(future.clone(), now).is_err());
    assert_eq!(
        reg.add_revocation(future, now.plus_secs(3600)).unwrap(),
        AddOutcome::Added
    );
    assert!(reg.is_revoked(&c, &bob.public()));
}

#[test]
fn stored_proofs_keep_expired_members_without_authorizing() {
    let auth = authority(100);
    let c = auth.circle_id();
    let carol = dev(4);
    let cred = auth
        .issue_credential(
            carol.public(),
            vec![Role::Member],
            vec![scope("team")],
            60,
            t0(),
        )
        .unwrap();
    let proof = accept_credential(&cred, &carol, t0()).unwrap();
    let restart = t0().plus_secs(86_400);

    let mut reg = registry(&auth);
    // The network path refuses expired proofs...
    assert!(matches!(
        reg.add_proof(proof.clone(), restart),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidProof(_)
        ))
    ));
    // ...the storage path keeps them, but they never authorize.
    assert_eq!(
        reg.add_stored_proof(proof.clone(), restart).unwrap(),
        AddOutcome::Added
    );
    assert_eq!(
        reg.add_stored_proof(proof, restart).unwrap(),
        AddOutcome::Duplicate
    );
    assert_eq!(
        reg.authorize(
            &c,
            &carol.public(),
            &scope("team"),
            Capability::Read,
            restart
        ),
        Err(DenyReason::Expired)
    );
    assert!(!reg.is_active_member(&c, &carol.public(), restart));
    assert!(reg.is_plausible_member(&c, &carol.public()));
    let m = reg.members(&c, restart);
    assert_eq!(m.len(), 1);
    assert!(!m[0].active && !m[0].revoked);
    assert!(reg
        .active_proofs_for(&c, &carol.public(), restart)
        .is_empty());

    // A stored proof still needs a genuine root signature and a sane lifetime.
    let mut tampered = accept_credential(&cred, &carol, t0()).unwrap();
    tampered.credential.unsigned.scopes = vec![Scope::all()];
    assert!(reg.add_stored_proof(tampered, restart).is_err());
    let too_long = UnsignedMembershipCredential::new(
        auth.root_key(),
        carol.public(),
        vec![Role::Member],
        vec![scope("team")],
        t0(),
        t0().plus_days(500),
    )
    .sign(auth.signing_key())
    .unwrap();
    let p = accept_credential(&too_long, &carol, t0());
    // accept_credential itself refuses (it verifies the proof), so build it by hand.
    assert!(p.is_err());
    let acc = UnsignedAcceptance::for_credential(&too_long, t0())
        .unwrap()
        .sign(carol.signing_key())
        .unwrap();
    let p = MembershipProof {
        credential: too_long,
        acceptance: acc,
    };
    assert!(reg.add_stored_proof(p.clone(), restart).is_err());
    assert!(reg.add_proof(p, t0()).is_err());
    // Unknown circle.
    let mut empty = MembershipRegistry::new();
    assert!(matches!(
        empty.add_stored_proof(accept_credential(&cred, &carol, t0()).unwrap(), restart),
        Err(IdentityError::Membership(
            MembershipRejection::UnknownCircle
        ))
    ));
}

#[test]
fn credentials_are_never_presented_to_unknown_or_revoked_peers() {
    let auth = authority(100);
    let mut reg = registry(&auth);
    let c = auth.circle_id();
    let me = dev(1);
    let peer = dev(2);
    let stranger = dev(3);
    let inviter = dev(4);
    let now = t0().plus_secs(1);
    enroll(
        &mut reg,
        &auth,
        &me,
        vec![Role::Member],
        &["*"],
        86_400,
        t0(),
    );
    assert!(reg
        .proofs_to_present(&stranger.public(), &me.public(), now)
        .is_empty());
    assert!(reg
        .proofs_to_present(&peer.public(), &me.public(), now)
        .is_empty());
    // Our inviter is plausible before we have seen its credential.
    reg.note_invite_issuer(&c, inviter.public()).unwrap();
    assert_eq!(
        reg.proofs_to_present(&inviter.public(), &me.public(), now)
            .len(),
        1
    );
    enroll(
        &mut reg,
        &auth,
        &peer,
        vec![Role::Member],
        &["team"],
        86_400,
        t0(),
    );
    assert_eq!(
        reg.proofs_to_present(&peer.public(), &me.public(), now)
            .len(),
        1
    );
    reg.add_revocation(auth.issue_revocation(peer.public(), "", now).unwrap(), now)
        .unwrap();
    assert!(reg
        .proofs_to_present(&peer.public(), &me.public(), now)
        .is_empty());
    assert!(reg.plausible_circles_for(&stranger.public()).is_empty());
    // An unknown circle for the inviter note.
    let other = authority(101);
    assert!(reg
        .note_invite_issuer(&other.circle_id(), inviter.public())
        .is_err());
}

#[test]
fn root_key_cannot_be_a_member() {
    let auth = authority(100);
    assert!(matches!(
        auth.issue_credential(
            auth.root_key(),
            vec![Role::Member],
            vec![Scope::all()],
            60,
            t0()
        ),
        Err(IdentityError::KeyMismatch { .. })
    ));
    assert!(auth
        .issue_founder_credential(auth.root_key(), t0())
        .is_err());
}

#[test]
fn invite_errors_never_echo_payload_text() {
    let auth = authority(100);
    let bob = dev(2);
    let secret_name = "Project Nightingale";
    let invite = auth
        .invite_member(
            secret_name,
            bob.public(),
            vec![Role::Member],
            vec![scope("team")],
            dev(1).public(),
            vec![],
            t0(),
        )
        .unwrap();
    let bytes = invite_to_bytes(&invite).unwrap();
    for (key, now) in [(dev(3).public(), t0()), (bob.public(), t0().plus_days(30))] {
        let e = validate_invite(&bytes, &key, now).unwrap_err();
        let msg = format!("{e} {e:?}");
        assert!(!msg.contains("Nightingale"), "{msg}");
    }
    let v = validate_invite(&bytes, &bob.public(), t0()).unwrap();
    assert!(!format!("{v:?}").contains("Nightingale"));
    // Bad JSON echoing.
    let mut garbage = bytes.clone();
    garbage.truncate(bytes.len() - 3);
    let e = validate_invite(&garbage, &bob.public(), t0()).unwrap_err();
    assert!(!e.to_string().contains("Nightingale"));
}

fn fstore(home: &std::path::Path, pass: &str) -> FileKeyStore {
    FileKeyStore::new(home, PassphraseSource::fixed(pass))
        .with_kdf_params(KdfParams::insecure_fast_for_tests())
}

#[test]
fn all_key_files_in_a_home_share_one_passphrase() {
    let home = tempfile::tempdir().unwrap();
    let id = DeviceIdentity::create(&fstore(home.path(), "first-pass")).unwrap();

    // A later process with a wrong passphrase cannot create a root key that the next
    // run could not unlock together with the device key.
    let wrong = fstore(home.path(), "second-pass-xyz");
    let e = CircleAuthority::create(&wrong).unwrap_err();
    assert!(matches!(e, IdentityError::DecryptionFailed { .. }), "{e}");
    assert!(!format!("{e} {e:?}").contains("second-pass-xyz"));
    let keys: Vec<_> = std::fs::read_dir(home.path().join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(keys, vec!["device.key".to_owned()]);

    // The right passphrase in a fresh process works, and both keys open together.
    let right = fstore(home.path(), "first-pass");
    let (auth, circle) = CircleAuthority::create(&right).unwrap();
    let fresh = fstore(home.path(), "first-pass");
    assert_eq!(DeviceIdentity::load(&fresh).unwrap().public(), id.public());
    assert_eq!(
        CircleAuthority::load(&fresh, &circle).unwrap().root_key(),
        auth.root_key()
    );

    // With the device key gone, another existing key file is used as the reference.
    assert!(fresh.delete(DeviceIdentity::LABEL).unwrap());
    assert!(matches!(
        DeviceIdentity::create(&fstore(home.path(), "nope")),
        Err(IdentityError::DecryptionFailed { .. })
    ));
    assert!(DeviceIdentity::create(&fstore(home.path(), "first-pass")).is_ok());
}

#[test]
fn key_files_are_never_replaced() {
    let home = tempfile::tempdir().unwrap();
    let ks = fstore(home.path(), "pw");
    let a = Zeroizing::new([1u8; 32]);
    let b = Zeroizing::new([2u8; 32]);
    ks.store_secret("k", &a).unwrap();
    assert!(matches!(
        ks.store_secret("k", &b),
        Err(IdentityError::AlreadyExists { .. })
    ));
    assert_eq!(*ks.load_secret("k").unwrap(), [1u8; 32]);

    let dev_ks = InsecureDevKeyStore::new(
        home.path(),
        InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext(),
    );
    dev_ks.store_secret("k", &a).unwrap();
    assert!(matches!(
        dev_ks.store_secret("k", &b),
        Err(IdentityError::AlreadyExists { .. })
    ));
    assert_eq!(*dev_ks.load_secret("k").unwrap(), [1u8; 32]);
    // No temp files left in the key directory.
    let mut names: Vec<_> = std::fs::read_dir(home.path().join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["k.insecure-key".to_owned(), "k.key".to_owned()]);
}

#[test]
fn file_keystore_never_stores_the_seed_in_plaintext() {
    let home = tempfile::tempdir().unwrap();
    let ks = fstore(home.path(), "pw");
    let id = DeviceIdentity::create(&ks).unwrap();
    let raw = std::fs::read(home.path().join("keys/device.key")).unwrap();
    let seed = id.libp2p_seed();
    let text = String::from_utf8(raw.clone()).unwrap();
    use base64::Engine as _;
    for enc in [
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&seed[..]),
        base64::engine::general_purpose::STANDARD.encode(&seed[..]),
        hex::encode(&seed[..]),
    ] {
        assert!(!text.contains(&enc));
    }
    assert!(!raw.windows(32).any(|w| w == &seed[..]));
    // The public key, however, is readable without the passphrase.
    let locked = FileKeyStore::new(home.path(), PassphraseSource::Env);
    assert_eq!(locked.public_key("device").unwrap(), id.public());
    let _: DeviceKey = id.public();
}
