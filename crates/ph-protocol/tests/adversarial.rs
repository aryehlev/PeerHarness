//! Adversarial tests written during review: cross-context replay, event_id binding of
//! every envelope member, signature malleability, key-encoding attacks, nesting limits
//! inside wire frames, and the privacy of error / `Debug` output.

use ph_core::{CircleId, DeviceKey, Digest, EventId, Nonce, Role, Scope, Signature, Timestamp};
use ph_protocol::jcs::{self, ParseLimits};
use ph_protocol::signing::{self, Context};
use ph_protocol::wire::{Request, Response};
use ph_protocol::{
    validate_stateless, validate_stateless_value, verify_acceptance, verify_credential,
    verify_invite, verify_revocation, Acceptance, AdoptAction, Authorization, EnvelopeBuilder,
    EventBody, EventType, Invite, MembershipBody, MembershipCredential, ProposalAction,
    ProposalBody, ProtocolError, QuestionBody, Revocation, RevocationBody, SignedEnvelope,
    SigningKey, UnsignedAcceptance, UnsignedEnvelope, UnsignedInvite, UnsignedMembershipCredential,
    UnsignedRevocation,
};
use serde_json::{json, Value};

const MARK: &str = "SECRETMARK";

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> DeviceKey {
    DeviceKey::from_signing_key(&sk(seed))
}
fn now() -> Timestamp {
    "2026-11-09T18:10:00Z".parse().unwrap()
}
fn circle() -> CircleId {
    CircleId::derive(&pk(2))
}
fn scope() -> Scope {
    Scope::new("team/backend").unwrap()
}

fn question_body(text: &str) -> EventBody {
    EventBody::Question(QuestionBody {
        question: text.into(),
        topic: "package-manager".into(),
        related_candidate: None,
    })
}

fn question(text: &str) -> SignedEnvelope {
    EnvelopeBuilder::new(circle(), scope(), question_body(text))
        .nonce(Nonce::from_bytes([1; 16]))
        .sign(&sk(1), now())
        .unwrap()
}

fn credential() -> MembershipCredential {
    UnsignedMembershipCredential::new(
        pk(2),
        pk(1),
        vec![Role::Member],
        vec![scope()],
        now(),
        now().plus_days(30),
    )
    .sign(&sk(2))
    .unwrap()
}

fn acceptance() -> Acceptance {
    UnsignedAcceptance::for_credential(&credential(), now())
        .unwrap()
        .sign(&sk(1))
        .unwrap()
}

fn revocation() -> Revocation {
    UnsignedRevocation::new(
        pk(2),
        pk(3),
        now(),
        "lost".into(),
        Nonce::from_bytes([9; 16]),
    )
    .sign(&sk(2))
    .unwrap()
}

fn invite() -> Invite {
    UnsignedInvite {
        circle_name: "acme".into(),
        circle_root_key: pk(2),
        credential: credential(),
        issuer_device_key: pk(4),
        issuer_addrs: vec!["/ip4/127.0.0.1/udp/4001/quic-v1".into()],
        invite_expires_at: now().plus_days(1),
        nonce: Nonce::from_bytes([6; 16]),
    }
    .sign(&sk(2))
    .unwrap()
}

// ---------------------------------------------------------------------------------------
// Cross-context replay
// ---------------------------------------------------------------------------------------

#[test]
fn signature_never_verifies_under_another_context() {
    let k = sk(2);
    let signer = pk(2);
    let unsigned = json!({"schema": "x", "circle_id": circle().to_string(), "n": 1});
    for a in Context::ALL {
        let signed = signing::sign_object(a, &k, &unsigned).unwrap();
        let (u, sig, _) = signing::split_signed(a, &signed).unwrap();
        for b in Context::ALL {
            let input_b = signing::signing_input(b, &u).unwrap();
            let r = signing::verify_input(b, &signer, &input_b, &sig);
            assert_eq!(r.is_ok(), a == b, "{a:?} signature under {b:?}");
        }
    }
}

#[test]
fn typed_objects_reject_signatures_from_other_contexts() {
    // A credential signature (membership context) grafted onto the same root's
    // revocation must not verify, and vice versa.
    let cred = credential();
    let mut rev = revocation();
    rev.signature = cred.signature;
    assert!(matches!(
        verify_revocation(&rev, now()),
        Err(ProtocolError::BadSignature { .. })
    ));

    // A credential re-labelled as an invite signature.
    let mut inv = invite();
    inv.signature = cred.signature;
    assert!(matches!(
        verify_invite(&inv, now()),
        Err(ProtocolError::BadSignature { .. })
    ));

    // The subject signs the credential's exact bytes with the acceptance context: that
    // is not a valid acceptance (and the credential bytes are not an acceptance object).
    let acc = acceptance();
    let input = signing::domain_separated(
        Context::Acceptance.as_str(),
        jcs::canonicalize(&cred.unsigned.to_value().unwrap())
            .unwrap()
            .as_bytes(),
    );
    let forged = Acceptance {
        unsigned: acc.unsigned.clone(),
        signature: signing::sign_input(&sk(1), &input),
    };
    assert!(verify_acceptance(&forged, &cred, now()).is_err());
    assert!(verify_acceptance(&acc, &cred, now()).is_ok());

    // An event signature by the root does not make a credential valid.
    let rev_event = EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Revocation(RevocationBody {
            revocation: revocation(),
        }),
    )
    .sign(&sk(2), now())
    .unwrap();
    let mut cred2 = credential();
    cred2.signature = rev_event.signature;
    assert!(verify_credential(&cred2, now()).is_err());
}

// ---------------------------------------------------------------------------------------
// event_id binding
// ---------------------------------------------------------------------------------------

#[test]
fn every_envelope_member_is_bound_by_event_id_and_signature() {
    let e = question("Should this repository use pnpm rather than npm?");
    let base = e.envelope.clone();
    let variants: Vec<(&str, UnsignedEnvelope)> = vec![
        (
            "circle_id",
            UnsignedEnvelope {
                circle_id: CircleId::derive(&pk(5)),
                ..base.clone()
            },
        ),
        (
            "scope",
            UnsignedEnvelope {
                scope: Scope::new("team/backend/api").unwrap(),
                ..base.clone()
            },
        ),
        (
            "author",
            UnsignedEnvelope {
                author: pk(3),
                ..base.clone()
            },
        ),
        (
            "nonce",
            UnsignedEnvelope {
                nonce: Nonce::from_bytes([2; 16]),
                ..base.clone()
            },
        ),
        (
            "created_at",
            UnsignedEnvelope {
                created_at: base.created_at.minus_secs(1),
                ..base.clone()
            },
        ),
        (
            "expires_at",
            UnsignedEnvelope {
                expires_at: base.expires_at.plus_secs(1),
                ..base.clone()
            },
        ),
        (
            "body",
            UnsignedEnvelope {
                body: question_body("Should this repository use npm rather than pnpm?"),
                ..base.clone()
            },
        ),
        (
            "type",
            UnsignedEnvelope {
                body: EventBody::Proposal(ProposalBody {
                    charter: Digest::sha256(b"charter"),
                    title: "t".into(),
                    summary: String::new(),
                    action: ProposalAction::Adopt(AdoptAction {
                        skill_name: "pnpm".into(),
                        description: "d".into(),
                        bundle_digest: Digest::sha256(b"b"),
                        bundle_size: 1,
                        related_question: None,
                        supersedes: None,
                    }),
                }),
                ..base.clone()
            },
        ),
    ];
    let original_id = base.event_id().unwrap();
    assert_eq!(original_id, e.event_id);
    let mut ids = std::collections::HashSet::new();
    ids.insert(original_id);
    for (field, v) in variants {
        let id = v.event_id().unwrap();
        assert!(ids.insert(id), "changing {field} did not change event_id");

        // Splice the changed member into the transmitted object, keeping the original
        // signature and event_id: verification must fail.
        let tampered = SignedEnvelope {
            envelope: v.clone(),
            signature: e.signature,
            event_id: e.event_id,
        };
        let bytes = tampered.to_canonical_json().unwrap();
        let r = validate_stateless(bytes.as_bytes(), now());
        assert!(
            matches!(r, Err(ProtocolError::BadSignature { .. })),
            "{field}: {r:?}"
        );

        // Even with the event_id recomputed, the old signature does not cover it.
        let tampered = SignedEnvelope {
            envelope: v,
            signature: e.signature,
            event_id: id,
        };
        let bytes = tampered.to_canonical_json().unwrap();
        assert!(
            validate_stateless(bytes.as_bytes(), now()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn event_id_does_not_depend_on_signature_or_formatting() {
    let e = question("q?");
    let pretty = serde_json::to_vec_pretty(&e.to_value().unwrap()).unwrap();
    let v = validate_stateless(&pretty, now()).unwrap();
    assert_eq!(v.event_id(), e.event_id);
    assert_eq!(v.canonical_json(), e.to_canonical_json().unwrap());
    // reordered members
    let mut members: Vec<(String, Value)> = e
        .to_value()
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    members.reverse();
    let mut text = String::from("{");
    for (i, (k, val)) in members.iter().enumerate() {
        if i > 0 {
            text.push(',');
        }
        text.push_str(&serde_json::to_string(k).unwrap());
        text.push(':');
        text.push_str(&val.to_string());
    }
    text.push('}');
    assert_eq!(
        validate_stateless(text.as_bytes(), now())
            .unwrap()
            .event_id(),
        e.event_id
    );
}

// ---------------------------------------------------------------------------------------
// Signature malleability and key encodings
// ---------------------------------------------------------------------------------------

/// The Ed25519 group order l, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[test]
fn malleated_signature_rejected() {
    let e = question("q?");
    let mut sig = *e.signature.as_bytes();
    // S' = S + l (same value mod l, non-canonical encoding)
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(sig[32 + i]) + u16::from(L[i]) + carry;
        sig[32 + i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    let mut v = e.to_value().unwrap();
    v["signature"] = json!(Signature::from_bytes(sig).to_string());
    assert!(matches!(
        validate_stateless(v.to_string().as_bytes(), now()),
        Err(ProtocolError::BadSignature { .. })
    ));
}

#[test]
fn weak_or_non_canonical_author_keys_are_schema_errors() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let e = question("q?");
    let mut identity = [0u8; 32];
    identity[0] = 1;
    // y = p + 3: a valid, non-weak point in a non-canonical encoding
    let mut non_canonical = [0xffu8; 32];
    non_canonical[0] = 0xed + 3;
    non_canonical[31] = 0x7f;
    for bytes in [identity, non_canonical, [0u8; 32]] {
        let key = format!("ed25519:{}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(key.parse::<DeviceKey>().is_err());
        let mut v = e.to_value().unwrap();
        v["author"] = json!(key);
        assert!(matches!(
            validate_stateless(v.to_string().as_bytes(), now()),
            Err(ProtocolError::Schema { .. })
        ));
    }
}

#[test]
fn all_zero_signature_rejected() {
    let e = question("q?");
    let mut v = e.to_value().unwrap();
    v["signature"] = json!(Signature::from_bytes([0; 64]).to_string());
    assert!(matches!(
        validate_stateless(v.to_string().as_bytes(), now()),
        Err(ProtocolError::BadSignature { .. })
    ));
}

// ---------------------------------------------------------------------------------------
// Authorization mapping
// ---------------------------------------------------------------------------------------

#[test]
fn authorization_requirements() {
    use ph_core::Capability::*;
    let expected = [
        (EventType::Question, Authorization::Capability(Ask)),
        (EventType::Answer, Authorization::Capability(Answer)),
        // Decision events are authorized by the roll of the charter they name, never
        // by a credential capability.
        (EventType::Proposal, Authorization::Roll),
        (EventType::Vote, Authorization::Roll),
        (EventType::Result, Authorization::Roll),
        (EventType::Charter, Authorization::CircleRoot),
        (EventType::Membership, Authorization::EmbeddedCredential),
        (EventType::Revocation, Authorization::CircleRoot),
    ];
    assert_eq!(expected.len(), EventType::ALL.len());
    for (t, a) in expected {
        assert_eq!(t.authorization(), a, "{t}");
    }
    // A REVOCATION that validates statelessly is authored by the circle root.
    let rev_event = EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Revocation(RevocationBody {
            revocation: revocation(),
        }),
    )
    .sign(&sk(2), now())
    .unwrap();
    let v = validate_stateless(rev_event.to_canonical_json().unwrap().as_bytes(), now()).unwrap();
    assert_eq!(v.authorization(), Authorization::CircleRoot);
    assert!(v.circle_id.is_derived_from(&v.author));
    // A member cannot author one, even wrapping a genuine root-signed revocation.
    let forged = UnsignedEnvelope {
        author: pk(1),
        ..rev_event.envelope.clone()
    };
    assert!(forged.sign(&sk(1)).is_err());
    let mut v = rev_event.to_value().unwrap();
    v["author"] = json!(pk(1).to_string());
    assert!(validate_stateless(v.to_string().as_bytes(), now()).is_err());
}

#[test]
fn membership_event_for_another_circle_rejected() {
    let cred = credential();
    let acc = acceptance();
    let body = EventBody::Membership(MembershipBody {
        credential: cred,
        acceptance: acc,
    });
    let other_circle = CircleId::derive(&pk(5));
    let r = EnvelopeBuilder::new(other_circle, Scope::all(), body)
        .nonce(Nonce::from_bytes([3; 16]))
        .sign(&sk(1), now());
    assert!(matches!(r, Err(ProtocolError::Mismatch { .. })));
}

// ---------------------------------------------------------------------------------------
// Wire nesting
// ---------------------------------------------------------------------------------------

fn nest(depth: usize) -> Value {
    let mut v = json!(1);
    for _ in 0..depth.saturating_sub(1) {
        v = json!([v]);
    }
    json!({ "x": v })
}

#[test]
fn frames_carry_maximally_nested_envelopes() {
    assert_eq!(jcs::depth(&nest(8)), 8);
    let req = Request::PushEvents {
        events: vec![nest(8)],
    };
    let bytes = req.to_bytes().unwrap();
    assert_eq!(Request::from_bytes(&bytes).unwrap(), req);
    let resp = Response::Events {
        events: vec![nest(8)],
        more: false,
    };
    assert!(Response::from_bytes(&resp.to_bytes().unwrap()).is_ok());
    // One level more than an envelope may have is still refused per event.
    let too_deep = nest(9);
    assert!(validate_stateless_value(&too_deep, now()).is_err());
    // A frame deeper than MAX_FRAME_DEPTH is refused outright.
    let text = format!(r#"{{"type":"push_events","events":[{}]}}"#, nest(9));
    assert!(Request::from_bytes(text.as_bytes()).is_err());
}

#[test]
fn real_envelopes_validate_from_inside_frames() {
    let q = question("q?");
    let m = EnvelopeBuilder::new(
        circle(),
        Scope::all(),
        EventBody::Membership(MembershipBody {
            credential: credential(),
            acceptance: acceptance(),
        }),
    )
    .nonce(Nonce::from_bytes([4; 16]))
    .sign(&sk(1), now())
    .unwrap();
    let req = Request::PushEvents {
        events: vec![q.to_value().unwrap(), m.to_value().unwrap(), json!({})],
    };
    let parsed = Request::from_bytes(&req.to_bytes().unwrap()).unwrap();
    let Request::PushEvents { events } = parsed else {
        panic!("wrong variant");
    };
    let results: Vec<bool> = events
        .iter()
        .map(|e| validate_stateless_value(e, now()).is_ok())
        .collect();
    assert_eq!(results, vec![true, true, false]);
}

// ---------------------------------------------------------------------------------------
// Privacy of errors and Debug output
// ---------------------------------------------------------------------------------------

fn assert_private(e: &ProtocolError) {
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains(MARK), "leaked payload: {shown}");
}

#[test]
fn errors_never_echo_payload() {
    let e = question("q?");
    type Mutation = Box<dyn Fn(&mut Value)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|v| v["type"] = json!(MARK)),
        Box::new(|v| v["schema"] = json!(MARK)),
        Box::new(|v| v["scope"] = json!(MARK)),
        Box::new(|v| v["author"] = json!(format!("ed25519:{MARK}"))),
        Box::new(|v| v["nonce"] = json!(format!("base64url:{MARK}"))),
        Box::new(|v| v["created_at"] = json!(MARK)),
        Box::new(|v| v[MARK] = json!(MARK)),
        Box::new(|v| v["body"][MARK] = json!(1)),
        Box::new(|v| v["body"]["question"] = json!(format!("\u{1b}{MARK}"))),
        Box::new(|v| v["body"]["question"] = json!(MARK.repeat(1000))),
        Box::new(|v| v["body"]["topic"] = json!(format!("{MARK}\n"))),
        Box::new(|v| v["body"]["question"] = json!(MARK)), // bad signature
    ];
    for m in mutations {
        let mut v = e.to_value().unwrap();
        m(&mut v);
        let err = validate_stateless(v.to_string().as_bytes(), now()).unwrap_err();
        assert_private(&err);
    }
    for raw in [
        format!("{{\"{MARK}\":1,\"{MARK}\":2}}"),
        format!("{{\"a\": {MARK}}}"),
        format!("{{\"type\":\"{MARK}\"}}"),
        format!("[\"{MARK}\""),
    ] {
        for err in [
            validate_stateless(raw.as_bytes(), now()).unwrap_err(),
            Request::from_bytes(raw.as_bytes()).unwrap_err(),
            Response::from_bytes(raw.as_bytes()).unwrap_err(),
            MembershipCredential::from_json_bytes(raw.as_bytes()).unwrap_err(),
            Invite::from_json_bytes(raw.as_bytes()).unwrap_err(),
            Revocation::from_json_bytes(raw.as_bytes()).unwrap_err(),
            Acceptance::from_json_bytes(raw.as_bytes()).unwrap_err(),
        ] {
            assert_private(&err);
        }
    }
    // Credential with a hostile role / scope value.
    let mut v = credential().to_value().unwrap();
    v["roles"] = json!([MARK]);
    assert_private(&MembershipCredential::from_json_bytes(v.to_string().as_bytes()).unwrap_err());
    let mut v = credential().to_value().unwrap();
    v["scopes"] = json!([MARK]);
    assert_private(&MembershipCredential::from_json_bytes(v.to_string().as_bytes()).unwrap_err());
}

#[test]
fn debug_output_hides_free_text() {
    let e = question(&format!("Is {MARK} the right tool?"));
    for shown in [
        format!("{e:?}"),
        format!("{:?}", e.envelope),
        format!("{:?}", e.body),
    ] {
        assert!(!shown.contains(MARK), "{shown}");
    }
    let rev = UnsignedRevocation::new(pk(2), pk(3), now(), MARK.into(), Nonce::from_bytes([1; 16]));
    assert!(!format!("{rev:?}").contains(MARK));
    let mut inv = invite().unsigned;
    inv.circle_name = MARK.into();
    assert!(!format!("{inv:?}").contains(MARK));
    // ids are still visible for diagnostics
    assert!(format!("{e:?}").contains(&e.event_id.to_string()));
    let _: EventId = e.event_id;
}

#[test]
fn hostile_frames_parse_quickly_and_safely() {
    // Many duplicate-looking keys, deep nesting just under the limit, huge strings.
    let wide = format!(
        "{{\"type\":\"push_events\",\"events\":[{}]}}",
        vec!["{}"; 64].join(",")
    );
    assert!(Request::from_bytes(wide.as_bytes()).is_ok());
    let big_string = format!(
        "{{\"type\":\"hello\",\"versions\":[\"{}\"]}}",
        "a".repeat(400_000)
    );
    assert!(Request::from_bytes(big_string.as_bytes()).is_err());
    let limits = ParseLimits::FRAME;
    let deep = "[".repeat(100_000);
    assert!(jcs::parse_strict(deep.as_bytes(), limits).is_err());
}
