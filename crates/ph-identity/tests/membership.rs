//! Circle authority, invite and registry integration and adversarial tests.

use ed25519_dalek::SigningKey;
use ph_core::{
    Capability, CircleId, DenyReason, DeviceKey, MembershipOracle, Role, Scope, Timestamp,
};
use ph_identity::{
    accept_credential, accept_invite, invite_from_bytes, invite_to_bytes, read_invite_file,
    validate_invite, write_invite_file, AddOutcome, CircleAuthority, DeviceIdentity, IdentityError,
    InviteRejection, MembershipRegistry, MembershipRejection, SharedMembershipRegistry,
    DEFAULT_INVITE_TTL_SECS, MAX_INVITE_TTL_SECS,
};
use ph_protocol::{
    Acceptance, Invite, MembershipProof, UnsignedAcceptance, UnsignedInvite,
    UnsignedMembershipCredential, UnsignedRevocation,
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

const ADDRS: &str = "/ip4/127.0.0.1/udp/4001/quic-v1";

struct World {
    auth: CircleAuthority,
    founder: DeviceIdentity,
    reg: MembershipRegistry,
}

fn world() -> World {
    let auth = authority(100);
    let founder = dev(1);
    let mut reg = MembershipRegistry::new();
    assert_eq!(
        reg.add_circle(auth.circle_id(), auth.root_key()).unwrap(),
        AddOutcome::Added
    );
    let cred = auth
        .issue_founder_credential(founder.public(), t0())
        .unwrap();
    assert_eq!(cred.roles, vec![Role::Owner, Role::Member]);
    assert_eq!(cred.scopes, vec![Scope::all()]);
    let proof = accept_credential(&cred, &founder, t0()).unwrap();
    assert_eq!(reg.add_proof(proof, t0()).unwrap(), AddOutcome::Added);
    World { auth, founder, reg }
}

/// Founder invites `member` with the given scopes; member validates and accepts.
fn join(w: &mut World, member: &DeviceIdentity, scopes: &[&str]) -> MembershipProof {
    let invite = w
        .auth
        .invite_member(
            "Backend team",
            member.public(),
            vec![Role::Member],
            scopes.iter().map(|s| scope(s)).collect(),
            w.founder.public(),
            vec![ADDRS.to_owned()],
            t0(),
        )
        .unwrap();
    let bytes = invite_to_bytes(&invite).unwrap();
    let now = t0().plus_secs(60);
    let v = validate_invite(&bytes, &member.public(), now).unwrap();
    let proof = accept_invite(&v, member, now).unwrap();
    w.reg.add_proof(proof.clone(), now).unwrap();
    proof
}

#[test]
fn invite_accept_authorize_round_trip() {
    let mut w = world();
    let bob = dev(2);
    let invite = w
        .auth
        .invite_member(
            "Backend team",
            bob.public(),
            vec![Role::Member],
            vec![scope("team/backend")],
            w.founder.public(),
            vec![ADDRS.to_owned()],
            t0(),
        )
        .unwrap();
    assert_eq!(
        invite.invite_expires_at,
        t0().plus_secs(DEFAULT_INVITE_TTL_SECS)
    );

    // Through a file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bob.invite.json");
    write_invite_file(&path, &invite).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = read_invite_file(&path).unwrap();
    assert_eq!(invite_from_bytes(&bytes).unwrap(), invite);

    let now = t0().plus_secs(3600);
    let v = validate_invite(&bytes, &bob.public(), now).unwrap();
    assert_eq!(v.circle_id, w.auth.circle_id());
    assert_eq!(v.circle_name, "Backend team");
    assert_eq!(v.root_key, w.auth.root_key());
    assert_eq!(v.root_fingerprint, w.auth.root_fingerprint());
    assert!(v.fingerprint_matches(&format!(" {} ", w.auth.root_fingerprint().to_uppercase())));
    assert!(!v.fingerprint_matches(&authority(5).root_fingerprint()));
    assert!(!v.fingerprint_matches(""));
    assert_eq!(v.issuer_device_key, w.founder.public());
    assert_eq!(v.issuer_addrs, vec![ADDRS.to_owned()]);
    assert_eq!(v.credential.subject_device_key, bob.public());
    assert!(!format!("{v:?}").contains("Backend team"));

    let proof = accept_invite(&v, &bob, now).unwrap();
    assert_eq!(proof.acceptance.subject_device_key, bob.public());

    // Bob's own registry, built from the invite.
    let mut bob_reg = MembershipRegistry::new();
    bob_reg.add_circle(v.circle_id, v.root_key).unwrap();
    bob_reg.add_proof(proof.clone(), now).unwrap();
    bob_reg
        .note_invite_issuer(&v.circle_id, v.issuer_device_key)
        .unwrap();
    assert!(bob_reg.is_plausible_member(&v.circle_id, &w.founder.public()));
    let to_founder = bob_reg.proofs_to_present(&w.founder.public(), &bob.public(), now);
    assert_eq!(to_founder, vec![proof.clone()]);
    // Bob never presents to an unknown peer.
    assert!(bob_reg
        .proofs_to_present(&dev(77).public(), &bob.public(), now)
        .is_empty());

    // Founder side: Bob authenticates.
    let out = w
        .reg
        .accept_presented_proofs(&bob.public(), &to_founder, now);
    assert_eq!(out.active_circles, vec![w.auth.circle_id()]);
    assert_eq!(out.rejected, 0);
    let reply = w
        .reg
        .best_proofs(&w.founder.public(), &out.active_circles, now);
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].credential.subject_device_key, w.founder.public());
    // Bob processes the founder's reply.
    let back = bob_reg.accept_presented_proofs(&w.founder.public(), &reply, now);
    assert_eq!(back.active_circles, vec![w.auth.circle_id()]);

    let c = w.auth.circle_id();
    for reg in [&w.reg, &bob_reg] {
        assert_eq!(
            reg.authorize(
                &c,
                &bob.public(),
                &scope("team/backend"),
                Capability::Ask,
                now
            ),
            Ok(())
        );
        assert!(reg.is_active_member(&c, &bob.public(), now));
        assert_eq!(
            reg.authorize(
                &c,
                &w.founder.public(),
                &scope("anything/here"),
                Capability::Revoke,
                now
            ),
            Ok(())
        );
    }
    // The registry as a shared oracle.
    let shared = SharedMembershipRegistry::new(w.reg.clone());
    let oracle: &dyn MembershipOracle = &shared;
    assert_eq!(
        oracle.authorize_read(&c, &bob.public(), &scope("team/backend/api"), now),
        Ok(())
    );
    shared
        .write()
        .add_revocation(w.auth.issue_revocation(bob.public(), "", now).unwrap(), now)
        .unwrap();
    assert_eq!(
        oracle.authorize_read(&c, &bob.public(), &scope("team/backend"), now),
        Err(DenyReason::Revoked)
    );
}

#[test]
fn scope_rules() {
    let mut w = world();
    let carol = dev(3);
    join(&mut w, &carol, &["team/frontend"]);
    let c = w.auth.circle_id();
    let now = t0().plus_secs(120);
    let k = carol.public();
    assert_eq!(
        w.reg
            .authorize(&c, &k, &scope("team/finance"), Capability::Ask, now),
        Err(DenyReason::ScopeDenied)
    );
    assert_eq!(
        w.reg.authorize(
            &c,
            &k,
            &scope("team/frontend/web"),
            Capability::Propose,
            now
        ),
        Ok(())
    );
    assert_eq!(
        w.reg
            .authorize(&c, &k, &scope("team/frontend"), Capability::Vote, now),
        Ok(())
    );
    assert_eq!(
        w.reg
            .authorize(&c, &k, &scope("team/frontendx"), Capability::Ask, now),
        Err(DenyReason::ScopeDenied)
    );
    assert_eq!(
        w.reg
            .authorize(&c, &k, &scope("team"), Capability::Read, now),
        Err(DenyReason::ScopeDenied)
    );
}

#[test]
fn non_owner_cannot_revoke_or_invite() {
    let mut w = world();
    let dave = dev(4);
    join(&mut w, &dave, &["team/backend"]);
    let c = w.auth.circle_id();
    let now = t0().plus_secs(120);
    for cap in [Capability::Revoke, Capability::Invite] {
        assert_eq!(
            w.reg
                .authorize(&c, &dave.public(), &scope("team/backend"), cap, now),
            Err(DenyReason::CapabilityDenied)
        );
    }
    // A revocation signed by a member's own key (not the root) is refused.
    let forged = UnsignedRevocation::new(
        dave.public(),
        w.founder.public(),
        now,
        String::new(),
        ph_core::Nonce::random().unwrap(),
    );
    // Its circle id is derived from dave's key, an unknown circle.
    let forged = forged.sign(dave.signing_key()).unwrap();
    assert!(matches!(
        w.reg.add_revocation(forged.clone(), now),
        Err(IdentityError::Membership(
            MembershipRejection::UnknownCircle
        ))
    ));
    // Even if relabelled with the real circle id, the issuer is not the root.
    let mut relabelled = forged;
    relabelled.unsigned.circle_id = c;
    assert!(matches!(
        w.reg.add_revocation(relabelled, now),
        Err(IdentityError::Membership(
            MembershipRejection::IssuerNotRoot
        ))
    ));
    assert!(w.reg.is_active_member(&c, &w.founder.public(), now));
}

#[test]
fn revoked_member_denied_regardless_of_issue_time() {
    let mut w = world();
    let eve = dev(5);
    join(&mut w, &eve, &["team/backend"]);
    let c = w.auth.circle_id();
    let now = t0().plus_secs(600);
    let rev = w
        .auth
        .issue_revocation(eve.public(), "left the team", now)
        .unwrap();
    assert_eq!(
        w.reg.add_revocation(rev.clone(), now).unwrap(),
        AddOutcome::Added
    );
    assert_eq!(
        w.reg.add_revocation(rev, now).unwrap(),
        AddOutcome::Duplicate
    );
    assert!(w.reg.is_revoked(&c, &eve.public()));
    assert!(w.reg.revocation(&c, &eve.public()).is_some());
    assert_eq!(w.reg.revocations(&c).len(), 1);
    assert_eq!(
        w.reg.authorize(
            &c,
            &eve.public(),
            &scope("team/backend"),
            Capability::Read,
            now
        ),
        Err(DenyReason::Revoked)
    );
    assert!(!w.reg.is_active_member(&c, &eve.public(), now));
    assert!(!w.reg.is_plausible_member(&c, &eve.public()));
    assert!(w.reg.active_proofs_for(&c, &eve.public(), now).is_empty());
    assert_eq!(w.reg.proofs_for(&c, &eve.public()).len(), 1);

    // A credential issued after the revocation still does not help (v0: new device key
    // required to re-enroll).
    let later = now.plus_secs(3600);
    let cred = w
        .auth
        .issue_credential(
            eve.public(),
            vec![Role::Member],
            vec![scope("team/backend")],
            86_400,
            later,
        )
        .unwrap();
    let proof = accept_credential(&cred, &eve, later).unwrap();
    assert_eq!(w.reg.add_proof(proof, later).unwrap(), AddOutcome::Added);
    assert_eq!(
        w.reg.authorize(
            &c,
            &eve.public(),
            &scope("team/backend"),
            Capability::Read,
            later
        ),
        Err(DenyReason::Revoked)
    );
    // Eve sees herself marked as revoked in members().
    let members = w.reg.members(&c, later);
    let eve_view = members.iter().find(|m| m.key == eve.public()).unwrap();
    assert!(eve_view.revoked);
    assert!(!eve_view.active);
    assert_eq!(eve_view.credential_count, 2);
    // Revoking someone with no known credential is still recorded.
    let stranger = dev(55).public();
    w.reg
        .add_revocation(w.auth.issue_revocation(stranger, "", later).unwrap(), later)
        .unwrap();
    assert!(w.reg.is_revoked(&c, &stranger));
}

#[test]
fn expired_credential_denied() {
    let mut w = world();
    let frank = dev(6);
    let cred = w
        .auth
        .issue_credential(
            frank.public(),
            vec![Role::Member],
            vec![scope("team/backend")],
            3600,
            t0(),
        )
        .unwrap();
    let proof = accept_credential(&cred, &frank, t0()).unwrap();
    w.reg.add_proof(proof.clone(), t0()).unwrap();
    let c = w.auth.circle_id();
    let s = scope("team/backend");
    assert_eq!(
        w.reg.authorize(
            &c,
            &frank.public(),
            &s,
            Capability::Ask,
            t0().plus_secs(3599)
        ),
        Ok(())
    );
    let after = t0().plus_secs(3600);
    assert_eq!(
        w.reg
            .authorize(&c, &frank.public(), &s, Capability::Ask, after),
        Err(DenyReason::Expired)
    );
    assert!(!w.reg.is_active_member(&c, &frank.public(), after));
    // Expired proofs are refused at add time.
    let mut fresh = MembershipRegistry::new();
    fresh.add_circle(c, w.auth.root_key()).unwrap();
    assert!(matches!(
        fresh.add_proof(proof, after),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidProof(_)
        ))
    ));
    // Still plausible (it may hold a renewal), so we would present our credentials.
    assert!(w.reg.is_plausible_member(&c, &frank.public()));

    // A renewal restores access; ANY active credential suffices.
    let renewed = w.auth.renew_credential(&cred, 7200, after).unwrap();
    let p2 = accept_credential(&renewed, &frank, after).unwrap();
    w.reg.add_proof(p2, after).unwrap();
    assert_eq!(
        w.reg.authorize(
            &c,
            &frank.public(),
            &s,
            Capability::Ask,
            after.plus_secs(10)
        ),
        Ok(())
    );
    let m = w
        .reg
        .members(&c, after.plus_secs(10))
        .into_iter()
        .find(|m| m.key == frank.public())
        .unwrap();
    assert!(m.active);
    assert_eq!(m.credential_count, 2);
    assert_eq!(m.expires_at, after.plus_secs(7200));
}

#[test]
fn any_active_credential_grants() {
    let mut w = world();
    let gina = dev(7);
    join(&mut w, &gina, &["team/frontend"]);
    let c = w.auth.circle_id();
    let now = t0().plus_secs(120);
    assert_eq!(
        w.reg.authorize(
            &c,
            &gina.public(),
            &scope("team/finance"),
            Capability::Ask,
            now
        ),
        Err(DenyReason::ScopeDenied)
    );
    let extra = w
        .auth
        .issue_credential(
            gina.public(),
            vec![Role::Member],
            vec![scope("team/finance")],
            86_400,
            now,
        )
        .unwrap();
    w.reg
        .add_proof(accept_credential(&extra, &gina, now).unwrap(), now)
        .unwrap();
    for s in ["team/finance", "team/frontend/web"] {
        assert_eq!(
            w.reg
                .authorize(&c, &gina.public(), &scope(s), Capability::Ask, now),
            Ok(())
        );
    }
    let m = w
        .reg
        .members(&c, now)
        .into_iter()
        .find(|m| m.key == gina.public())
        .unwrap();
    assert_eq!(
        m.scopes,
        vec![scope("team/finance"), scope("team/frontend")]
    );
    assert_eq!(m.roles, vec![Role::Member]);
    assert_eq!(m.fingerprint, gina.fingerprint());
    // Our proofs across circles.
    assert_eq!(w.reg.credentials_for_subject(&gina.public()).len(), 2);
    // Present only the best (latest-expiring) active one per circle.
    let best = w.reg.best_proofs(&gina.public(), &[c], now);
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].credential.scopes, vec![scope("team/frontend")]);
}

#[test]
fn invite_bound_to_other_key_rejected() {
    let w = world();
    let bob = dev(2);
    let mallory = dev(66);
    let inv = w
        .auth
        .invite_member(
            "c",
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            w.founder.public(),
            vec![],
            t0(),
        )
        .unwrap();
    let bytes = invite_to_bytes(&inv).unwrap();
    let r = validate_invite(&bytes, &mallory.public(), t0());
    assert!(
        matches!(
            r,
            Err(IdentityError::Invite(InviteRejection::NotForThisDevice))
        ),
        "{r:?}"
    );
    // Even with the validated invite in hand, mallory cannot accept for bob.
    let v = validate_invite(&bytes, &bob.public(), t0()).unwrap();
    assert!(matches!(
        accept_invite(&v, &mallory, t0()),
        Err(IdentityError::KeyMismatch { .. })
    ));
}

#[test]
fn expired_invite_rejected() {
    let w = world();
    let bob = dev(2);
    let cred = w
        .auth
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            30 * 86_400,
            t0(),
        )
        .unwrap();
    let inv = w
        .auth
        .create_invite("c", cred, w.founder.public(), vec![], 3600, t0())
        .unwrap();
    let bytes = invite_to_bytes(&inv).unwrap();
    assert!(validate_invite(&bytes, &bob.public(), t0().plus_secs(3599)).is_ok());
    let r = validate_invite(&bytes, &bob.public(), t0().plus_secs(3600));
    assert!(
        matches!(r, Err(IdentityError::Invite(InviteRejection::Expired))),
        "{r:?}"
    );
    // Validated before expiry, accepted after: refused.
    let v = validate_invite(&bytes, &bob.public(), t0()).unwrap();
    assert!(matches!(
        accept_invite(&v, &bob, t0().plus_secs(3601)),
        Err(IdentityError::Invite(InviteRejection::Expired))
    ));
}

#[test]
fn invite_ttl_limits() {
    let w = world();
    let bob = dev(2);
    let cred = w
        .auth
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            3600,
            t0(),
        )
        .unwrap();
    for ttl in [0, -5, MAX_INVITE_TTL_SECS + 1, 3601] {
        assert!(matches!(
            w.auth
                .create_invite("c", cred.clone(), w.founder.public(), vec![], ttl, t0()),
            Err(IdentityError::InvalidTtl { .. })
        ));
    }
    for ttl in [0, -1, 401 * 86_400] {
        assert!(matches!(
            w.auth.issue_credential(
                bob.public(),
                vec![Role::Member],
                vec![scope("a")],
                ttl,
                t0()
            ),
            Err(IdentityError::InvalidTtl { .. })
        ));
    }
    // A credential from another circle cannot be wrapped.
    let other = authority(101);
    let foreign = other
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            3600,
            t0(),
        )
        .unwrap();
    assert!(matches!(
        w.auth
            .create_invite("c", foreign, w.founder.public(), vec![], 600, t0()),
        Err(IdentityError::KeyMismatch { .. })
    ));
    // Bad circle names and addresses are rejected by the protocol layer.
    for name in ["", "line\nbreak", &"x".repeat(65)] {
        assert!(w
            .auth
            .create_invite(name, cred.clone(), w.founder.public(), vec![], 600, t0())
            .is_err());
    }
    let too_many: Vec<String> = (0..9)
        .map(|i| format!("/ip4/127.0.0.1/udp/{i}/quic-v1"))
        .collect();
    assert!(w
        .auth
        .create_invite("c", cred, w.founder.public(), too_many, 600, t0())
        .is_err());
}

#[test]
fn credential_signed_by_non_root_rejected() {
    let w = world();
    let bob = dev(2);
    let impostor = authority(150);
    // An invite claiming the real root, but whose credential is signed by another key
    // that claims to be the root (issuer_key = real root, signature by impostor).
    let real = w
        .auth
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            3600,
            t0(),
        )
        .unwrap();
    let mut forged_cred = real.clone();
    let sig_input = forged_cred.unsigned.signing_input().unwrap();
    forged_cred.signature = ph_protocol::signing::sign_input(impostor.signing_key(), &sig_input);
    let inv = UnsignedInvite {
        circle_name: "c".into(),
        circle_root_key: w.auth.root_key(),
        credential: forged_cred.clone(),
        issuer_device_key: w.founder.public(),
        issuer_addrs: vec![],
        invite_expires_at: t0().plus_secs(600),
        nonce: ph_core::Nonce::random().unwrap(),
    }
    .sign(w.auth.signing_key())
    .unwrap();
    let r = validate_invite(&invite_to_bytes(&inv).unwrap(), &bob.public(), t0());
    assert!(
        matches!(
            r,
            Err(IdentityError::Invite(
                InviteRejection::CredentialNotFromRoot
            ))
        ),
        "{r:?}"
    );

    // An invite whose credential was issued by a different root than the invite's.
    let other_cred = impostor
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            3600,
            t0(),
        )
        .unwrap();
    let mut v = inv.to_value().unwrap();
    v["credential"] = other_cred.to_value().unwrap();
    let r = validate_invite(&serde_json::to_vec(&v).unwrap(), &bob.public(), t0());
    assert!(
        matches!(
            r,
            Err(IdentityError::Invite(
                InviteRejection::CredentialNotFromRoot
            ))
        ),
        "{r:?}"
    );

    // The registry refuses a proof whose credential was issued by a non-root key.
    let mut reg = w.reg.clone();
    let proof = accept_credential(&other_cred, &bob, t0()).unwrap();
    // Unknown circle (the impostor's) ...
    assert!(matches!(
        reg.add_proof(proof, t0()),
        Err(IdentityError::Membership(
            MembershipRejection::UnknownCircle
        ))
    ));
    // ... and a forged signature with the real issuer key.
    let acc = UnsignedAcceptance::for_credential(&forged_cred, t0())
        .unwrap()
        .sign(bob.signing_key())
        .unwrap();
    assert!(matches!(
        reg.add_proof(
            MembershipProof {
                credential: forged_cred,
                acceptance: acc
            },
            t0()
        ),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidProof(_)
        ))
    ));
    // Relabelled circle id with the impostor issuer is "issuer not root".
    let mut u = UnsignedMembershipCredential::new(
        impostor.root_key(),
        bob.public(),
        vec![Role::Owner],
        vec![Scope::all()],
        t0(),
        t0().plus_secs(3600),
    );
    u.circle_id = w.auth.circle_id();
    let sig = ph_protocol::signing::sign_input(impostor.signing_key(), &u.signing_input().unwrap());
    let cred = ph_protocol::MembershipCredential {
        unsigned: u,
        signature: sig,
    };
    let acc = UnsignedAcceptance::for_credential(&cred, t0())
        .unwrap()
        .sign(bob.signing_key())
        .unwrap();
    assert!(matches!(
        reg.add_proof(
            MembershipProof {
                credential: cred,
                acceptance: acc
            },
            t0()
        ),
        Err(IdentityError::Membership(
            MembershipRejection::IssuerNotRoot
        ))
    ));
    assert_eq!(
        reg.authorize(
            &w.auth.circle_id(),
            &bob.public(),
            &scope("a"),
            Capability::Read,
            t0()
        ),
        Err(DenyReason::NotMember)
    );
}

#[test]
fn forged_invite_signature_rejected() {
    let w = world();
    let bob = dev(2);
    let inv = w
        .auth
        .invite_member(
            "c",
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            w.founder.public(),
            vec![],
            t0(),
        )
        .unwrap();
    // Swap the issuer address after signing.
    let mut v = inv.to_value().unwrap();
    v["issuer_addrs"] = serde_json::json!(["/ip4/6.6.6.6/udp/1/quic-v1"]);
    let r = validate_invite(&serde_json::to_vec(&v).unwrap(), &bob.public(), t0());
    assert!(
        matches!(r, Err(IdentityError::Invite(InviteRejection::BadSignature))),
        "{r:?}"
    );

    // Re-signed by another key while claiming the real root.
    let impostor = authority(151);
    let mut forged: Invite = inv.clone();
    forged.signature = ph_protocol::signing::sign_input(
        impostor.signing_key(),
        &forged.unsigned.signing_input().unwrap(),
    );
    let r = validate_invite(&invite_to_bytes(&forged).unwrap(), &bob.public(), t0());
    assert!(
        matches!(r, Err(IdentityError::Invite(InviteRejection::BadSignature))),
        "{r:?}"
    );

    // Claiming a different root without changing the credential.
    let mut v = inv.to_value().unwrap();
    v["circle_root_key"] = serde_json::Value::String(impostor.root_key().to_string());
    let r = validate_invite(&serde_json::to_vec(&v).unwrap(), &bob.public(), t0());
    assert!(
        matches!(
            r,
            Err(IdentityError::Invite(
                InviteRejection::CredentialNotFromRoot
            ))
        ),
        "{r:?}"
    );
}

#[test]
fn malformed_invites_rejected() {
    let w = world();
    let bob = dev(2);
    let inv = w
        .auth
        .invite_member(
            "c",
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            w.founder.public(),
            vec![],
            t0(),
        )
        .unwrap();
    let good = invite_to_bytes(&inv).unwrap();
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        b"null".to_vec(),
        b"{}".to_vec(),
        b"[1,2,3]".to_vec(),
        vec![b'{'; 10_000],
        vec![b' '; 20_000],
        good[..good.len() - 1].to_vec(),
    ];
    let mut v = inv.to_value().unwrap();
    v["extra"] = serde_json::json!(1);
    cases.push(serde_json::to_vec(&v).unwrap());
    let mut v = inv.to_value().unwrap();
    v["schema"] = serde_json::json!("peerharness.invite/0.2");
    cases.push(serde_json::to_vec(&v).unwrap());
    // Duplicate key.
    let s = String::from_utf8(good.clone()).unwrap();
    cases.push(s.replacen("{", "{\"nonce\":\"x\",", 1).into_bytes());
    for (i, c) in cases.iter().enumerate() {
        let r = validate_invite(c, &bob.public(), t0());
        assert!(
            matches!(r, Err(IdentityError::Invite(InviteRejection::Malformed(_)))),
            "case {i}: {r:?}"
        );
    }
    // Oversized invite file.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.json");
    std::fs::write(&p, vec![b' '; ph_identity::MAX_INVITE_FILE_BYTES + 1]).unwrap();
    assert!(matches!(
        read_invite_file(&p),
        Err(IdentityError::FileTooLarge { .. })
    ));
    assert!(read_invite_file(dir.path()).is_err());
}

#[test]
fn acceptance_signed_by_wrong_key_rejected() {
    let mut w = world();
    let bob = dev(2);
    let mallory = dev(66);
    let cred = w
        .auth
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("a")],
            3600,
            t0(),
        )
        .unwrap();
    // Signature by mallory over an acceptance naming bob.
    let unsigned = UnsignedAcceptance::for_credential(&cred, t0()).unwrap();
    let sig =
        ph_protocol::signing::sign_input(mallory.signing_key(), &unsigned.signing_input().unwrap());
    let bad = MembershipProof {
        credential: cred.clone(),
        acceptance: Acceptance {
            unsigned,
            signature: sig,
        },
    };
    assert!(matches!(
        w.reg.add_proof(bad.clone(), t0()),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidProof(_)
        ))
    ));
    // accept_credential refuses to sign for another subject.
    assert!(matches!(
        accept_credential(&cred, &mallory, t0()),
        Err(IdentityError::KeyMismatch { .. })
    ));
    // An acceptance for a different credential does not match.
    let other = w
        .auth
        .issue_credential(
            bob.public(),
            vec![Role::Member],
            vec![scope("b")],
            3600,
            t0(),
        )
        .unwrap();
    let acc_other = accept_credential(&other, &bob, t0()).unwrap().acceptance;
    assert!(w
        .reg
        .add_proof(
            MembershipProof {
                credential: cred.clone(),
                acceptance: acc_other
            },
            t0()
        )
        .is_err());
    // Presented by mallory over the transport: subject mismatch is counted as rejected.
    let good = accept_credential(&cred, &bob, t0()).unwrap();
    let out = w
        .reg
        .accept_presented_proofs(&mallory.public(), &[good.clone(), bad], t0());
    assert!(out.active_circles.is_empty());
    assert_eq!(out.rejected, 2);
    assert_eq!(
        w.reg.authorize(
            &w.auth.circle_id(),
            &bob.public(),
            &scope("a"),
            Capability::Read,
            t0()
        ),
        Err(DenyReason::NotMember)
    );
    // Bob presenting his own proof works, and a duplicate is a no-op.
    let out = w
        .reg
        .accept_presented_proofs(&bob.public(), std::slice::from_ref(&good), t0());
    assert_eq!(out.active_circles, vec![w.auth.circle_id()]);
    assert_eq!(w.reg.add_proof(good, t0()).unwrap(), AddOutcome::Duplicate);
}

#[test]
fn registry_circle_rules() {
    let mut reg = MembershipRegistry::new();
    let a = authority(10);
    let b = authority(11);
    assert!(matches!(
        reg.add_circle(a.circle_id(), b.root_key()),
        Err(IdentityError::Membership(
            MembershipRejection::CircleRootMismatch
        ))
    ));
    assert_eq!(
        reg.add_circle(a.circle_id(), a.root_key()).unwrap(),
        AddOutcome::Added
    );
    assert_eq!(
        reg.add_circle(a.circle_id(), a.root_key()).unwrap(),
        AddOutcome::Duplicate
    );
    assert_eq!(reg.known_circles(), vec![a.circle_id()]);
    assert_eq!(reg.root_key(&a.circle_id()), Some(a.root_key()));
    assert!(reg.knows_circle(&a.circle_id()));
    let unknown = CircleId::derive(&dev(9).public());
    let k = dev(9).public();
    assert_eq!(
        reg.authorize(&unknown, &k, &Scope::all(), Capability::Read, t0()),
        Err(DenyReason::NotMember)
    );
    assert_eq!(
        reg.authorize(&a.circle_id(), &k, &Scope::all(), Capability::Read, t0()),
        Err(DenyReason::NotMember)
    );
    assert!(reg.members(&unknown, t0()).is_empty());
    assert!(reg.note_invite_issuer(&unknown, k).is_err());
    // A revocation for an unknown circle.
    let rev = b.issue_revocation(k, "", t0()).unwrap();
    assert!(matches!(
        reg.add_revocation(rev, t0()),
        Err(IdentityError::Membership(
            MembershipRejection::UnknownCircle
        ))
    ));
    // A tampered revocation (reason changed after signing).
    let mut tampered = a.issue_revocation(k, "x", t0()).unwrap();
    tampered.unsigned.reason = "y".into();
    assert!(matches!(
        reg.add_revocation(tampered, t0()),
        Err(IdentityError::Membership(
            MembershipRejection::InvalidRevocation(_)
        ))
    ));
    assert!(!reg.is_revoked(&a.circle_id(), &k));
    // A revocation dated ahead of this node's clock is accepted: it only ever denies,
    // so a fast clock on the issuer's side must not leave the device trusted here.
    let future = a.issue_revocation(k, "", t0().plus_days(1)).unwrap();
    assert_eq!(reg.add_revocation(future, t0()).unwrap(), AddOutcome::Added);
    assert!(reg.is_revoked(&a.circle_id(), &k));
    assert!(reg.remove_circle(&a.circle_id()));
    assert!(!reg.remove_circle(&a.circle_id()));
}

#[test]
fn members_listing() {
    let mut w = world();
    let bob = dev(2);
    join(&mut w, &bob, &["team/backend", "team/infra"]);
    let c = w.auth.circle_id();
    let now = t0().plus_secs(120);
    let members = w.reg.members(&c, now);
    assert_eq!(members.len(), 2);
    let mut keys: Vec<DeviceKey> = vec![w.founder.public(), bob.public()];
    keys.sort();
    assert_eq!(members.iter().map(|m| m.key).collect::<Vec<_>>(), keys);
    let f = members
        .iter()
        .find(|m| m.key == w.founder.public())
        .unwrap();
    assert_eq!(f.roles, vec![Role::Owner, Role::Member]);
    assert_eq!(f.scopes, vec![Scope::all()]);
    assert!(f.active && !f.revoked);
    let b = members.iter().find(|m| m.key == bob.public()).unwrap();
    assert_eq!(b.scopes, vec![scope("team/backend"), scope("team/infra")]);
    assert_eq!(b.expires_at, t0().plus_secs(30 * 86_400));
    assert_eq!(w.reg.plausible_circles_for(&bob.public()), vec![c]);
    assert!(w.reg.plausible_circles_for(&dev(99).public()).is_empty());
}

#[test]
fn founder_flow_with_keystore() {
    let home = tempfile::tempdir().unwrap();
    let ks =
        ph_identity::FileKeyStore::new(home.path(), ph_identity::PassphraseSource::fixed("pw"))
            .with_kdf_params(ph_identity::KdfParams::insecure_fast_for_tests());
    let me = DeviceIdentity::create(&ks).unwrap();
    let (auth, circle) = CircleAuthority::create(&ks).unwrap();
    assert_eq!(auth.circle_id(), circle);
    assert_ne!(auth.root_key(), me.public());
    let now = Timestamp::now();
    let proof = accept_credential(
        &auth.issue_founder_credential(me.public(), now).unwrap(),
        &me,
        now,
    )
    .unwrap();
    let mut reg = MembershipRegistry::new();
    reg.add_circle(circle, auth.root_key()).unwrap();
    reg.add_proof(proof, now).unwrap();
    // Reload everything from the keystore, as a later process would.
    let auth2 = CircleAuthority::load(&ks, &circle).unwrap();
    let me2 = DeviceIdentity::load(&ks).unwrap();
    assert_eq!(auth2.root_key(), auth.root_key());
    let bob = dev(2);
    let inv = auth2
        .invite_member(
            "Team",
            bob.public(),
            vec![Role::Member],
            vec![scope("x")],
            me2.public(),
            vec![],
            now,
        )
        .unwrap();
    let v = validate_invite(&invite_to_bytes(&inv).unwrap(), &bob.public(), now).unwrap();
    reg.add_proof(accept_invite(&v, &bob, now).unwrap(), now)
        .unwrap();
    assert_eq!(
        reg.authorize(
            &circle,
            &bob.public(),
            &scope("x/y"),
            Capability::Answer,
            now
        ),
        Ok(())
    );
}
