//! Golden test vectors.
//!
//! `generate()` rebuilds every vector from fixed seeds, nonces and timestamps. The test
//! `vectors_match_committed_files` compares the result byte-for-byte with the files in
//! `tests/vectors/`, so the protocol encoding cannot drift silently. To intentionally
//! regenerate after a protocol change, run
//! `PH_UPDATE_VECTORS=1 cargo test -p ph-protocol --test vectors` and review the diff.
//!
//! `vectors_verify_with_public_api` reads the committed files (not the generator) and
//! checks each one with the public API, as a third-party implementation would.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ph_core::{CircleId, DeviceKey, Digest, EventId, Nonce, Role, Scope, Timestamp};
use ph_protocol::bundle::{bundle_digest, manifest_for_files, BundleManifest};
use ph_protocol::jcs::{self, ParseLimits};
use ph_protocol::signing::{self, Context};
use ph_protocol::{
    validate_stateless, verify_acceptance, verify_charter_signature, verify_credential,
    verify_invite, verify_revocation, Acceptance, AdoptAction, AnswerBody, AnswerChoice, Charter,
    CharterBody, CharterContent, Electorate, EnvelopeBuilder, EventBody, Invite, JcsError,
    MembershipBody, MembershipCredential, ProposalAction, ProposalBody, QuestionBody, ResultBody,
    Revocation, RevocationBody, RollEntry, SignedEnvelope, SigningKey, Stance, StanceBody,
    UnsignedAcceptance, UnsignedCharter, UnsignedInvite, UnsignedMembershipCredential,
    UnsignedRevocation, VoteBody, VoteDecision,
};
use serde_json::{json, Value};

const DEVICE_SEED: [u8; 32] = [0x01; 32];
const ROOT_SEED: [u8; 32] = [0x02; 32];
const PEER_SEED: [u8; 32] = [0x03; 32];
const SKILL_MD: &str = "---\nname: pnpm-repository-convention\ndescription: Use pnpm when installing packages or running package scripts in the specified repository.\n---\n\nWhen working in this repository, use pnpm instead of npm for dependency\ninstallation and package scripts. Verify repository configuration before\nchanging lockfiles; do not convert package managers automatically.\n";

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}
fn device() -> SigningKey {
    SigningKey::from_bytes(&DEVICE_SEED)
}
fn root() -> SigningKey {
    SigningKey::from_bytes(&ROOT_SEED)
}
fn peer() -> SigningKey {
    SigningKey::from_bytes(&PEER_SEED)
}
fn pk(k: &SigningKey) -> DeviceKey {
    DeviceKey::from_signing_key(k)
}
fn circle() -> CircleId {
    CircleId::derive(&pk(&root()))
}
fn scope() -> Scope {
    Scope::new("team/backend").unwrap()
}
fn created() -> Timestamp {
    ts("2026-11-09T18:10:00Z")
}
fn nonce(b: u8) -> Nonce {
    Nonce::from_bytes([b; 16])
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// One signed-object vector.
fn signed_vector(
    name: &str,
    context: Context,
    signer: &DeviceKey,
    unsigned: Value,
    signed: Value,
    verify_at: Timestamp,
) -> Value {
    let canonical = jcs::canonicalize(&unsigned).unwrap();
    let input = signing::signing_input(context, &unsigned).unwrap();
    let digest = signing::digest_of_input(&input);
    let signature = signed["signature"].clone();
    let digest_key = if context == Context::Event {
        "event_id"
    } else {
        "digest"
    };
    json!({
        "name": name,
        "context": context.as_str(),
        "schema": context.schema(),
        "signer_public_key": signer.to_string(),
        "verify_at": verify_at.to_string(),
        "unsigned": unsigned,
        "canonical": canonical,
        "signing_input_hex": hex::encode(&input),
        "signature": signature,
        digest_key: digest.to_string(),
        "signed": signed,
        "signed_canonical": jcs::canonicalize(&signed).unwrap(),
    })
}

fn credential() -> MembershipCredential {
    UnsignedMembershipCredential::new(
        pk(&root()),
        pk(&device()),
        vec![Role::Member],
        vec![scope()],
        ts("2026-11-09T18:00:00Z"),
        ts("2026-12-09T18:00:00Z"),
    )
    .sign(&root())
    .unwrap()
}

fn acceptance() -> Acceptance {
    UnsignedAcceptance::for_credential(&credential(), ts("2026-11-09T18:05:00Z"))
        .unwrap()
        .sign(&device())
        .unwrap()
}

fn revocation() -> Revocation {
    UnsignedRevocation::new(
        pk(&root()),
        pk(&peer()),
        ts("2026-11-10T09:00:00Z"),
        "device lost".into(),
        nonce(0x30),
    )
    .sign(&root())
    .unwrap()
}

fn invite() -> Invite {
    UnsignedInvite {
        circle_name: "acme backend".into(),
        circle_root_key: pk(&root()),
        credential: credential(),
        issuer_device_key: pk(&peer()),
        issuer_addrs: vec!["/ip4/127.0.0.1/udp/4001/quic-v1".into()],
        invite_expires_at: ts("2026-11-10T18:00:00Z"),
        nonce: nonce(0x40),
    }
    .sign(&root())
    .unwrap()
}

fn bundle() -> BundleManifest {
    manifest_for_files(&[("SKILL.md", SKILL_MD.as_bytes())])
}

/// The founding charter: the device ("alice") is the only member.
fn charter_1() -> Charter {
    UnsignedCharter::founding(
        pk(&root()),
        CharterContent::founding(RollEntry::new(
            "alice",
            vec![pk(&device())],
            vec![Scope::all()],
        )),
        ts("2026-11-09T18:00:00Z"),
    )
    .sign(&root())
    .unwrap()
}

/// What the amendment in the vectors proposes: admit the peer as "bob".
fn charter_2_content() -> CharterContent {
    let mut next = charter_1().content.clone();
    next.roll
        .push(RollEntry::new("bob", vec![pk(&peer())], vec![scope()]));
    next.normalize();
    next
}

/// One named event vector: `(name, envelope, signer)`.
type EventVector = (&'static str, SignedEnvelope, DeviceKey);

/// The whole story, in order: a question and its answer; alice amends the charter to
/// admit bob (one member, so her approval is the majority); the root notarizes charter
/// 2; a rule is proposed under charter 2 and both members approve it; a repeal is
/// proposed; plus one MEMBERSHIP and one REVOCATION event.
fn story() -> (Vec<EventVector>, Charter) {
    let sign = |body: EventBody, scope: Scope, at: &str, n: u8, key: &SigningKey| {
        EnvelopeBuilder::new(circle(), scope, body)
            .created_at(ts(at))
            .nonce(nonce(n))
            .sign(key, created())
            .unwrap()
    };
    let vote = |proposal: &SignedEnvelope, scope: Scope, at: &str, n: u8, key: &SigningKey| {
        sign(
            EventBody::Vote(VoteBody {
                proposal_id: proposal.event_id,
                decision: VoteDecision::Approve,
                rationale: None,
            }),
            scope,
            at,
            n,
            key,
        )
    };

    let question = sign(
        EventBody::Question(QuestionBody {
            question: "Should this repository use pnpm rather than npm?".into(),
            topic: "package-manager".into(),
            related_candidate: Some(Digest::sha256(b"local-candidate-1")),
        }),
        scope(),
        "2026-11-09T18:10:00Z",
        0x10,
        &device(),
    );
    let answer = sign(
        EventBody::Answer(AnswerBody {
            question_id: question.event_id,
            answer: AnswerChoice::Agree,
            rationale: Some("We switched to pnpm in March; the lockfile is pnpm-lock.yaml.".into()),
        }),
        scope(),
        "2026-11-09T18:11:00Z",
        0x11,
        &peer(),
    );

    // Charter 1 -> charter 2: admit bob.
    let c1 = charter_1();
    let amend = sign(
        EventBody::Proposal(ProposalBody {
            charter: c1.digest().unwrap(),
            title: "Admit bob".into(),
            summary: "Bob joins the backend team.".into(),
            action: ProposalAction::Amend {
                next: charter_2_content(),
            },
        }),
        Scope::all(),
        "2026-11-09T18:01:00Z",
        0x20,
        &device(),
    );
    let amend_vote = vote(
        &amend,
        Scope::all(),
        "2026-11-09T18:02:00Z",
        0x21,
        &device(),
    );
    let amend_result = sign(
        EventBody::Result(ResultBody::new(amend.event_id, vec![amend_vote.event_id])),
        Scope::all(),
        "2026-11-09T18:03:00Z",
        0x22,
        &device(),
    );
    let c2 = UnsignedCharter::successor(
        &c1,
        charter_2_content(),
        amend_result.event_id,
        ts("2026-11-09T18:04:00Z"),
    )
    .unwrap()
    .sign(&root())
    .unwrap();
    let charter_event = sign(
        EventBody::Charter(CharterBody {
            charter: c2.clone(),
        }),
        Scope::all(),
        "2026-11-09T18:04:00Z",
        0x23,
        &root(),
    );

    // A rule proposed and passed under charter 2 (two members, both must approve).
    let manifest = bundle();
    let adopt = sign(
        EventBody::Proposal(ProposalBody {
            charter: c2.digest().unwrap(),
            title: "Use pnpm, not npm, in this repository".into(),
            summary: "Corrected twice locally; peer agreed.".into(),
            action: ProposalAction::Adopt(AdoptAction {
                skill_name: "pnpm-repository-convention".into(),
                description: "Use pnpm when installing packages or running package scripts in the specified repository.".into(),
                bundle_digest: bundle_digest(&manifest).unwrap(),
                bundle_size: manifest.total_size(),
                related_question: Some(question.event_id),
                supersedes: None,
            }),
        }),
        scope(),
        "2026-11-09T18:30:00Z",
        0x12,
        &device(),
    );
    let vote_alice = vote(&adopt, scope(), "2026-11-09T18:31:00Z", 0x13, &device());
    let vote_bob = vote(&adopt, scope(), "2026-11-09T18:40:00Z", 0x14, &peer());
    let adopt_result = sign(
        EventBody::Result(ResultBody::new(
            adopt.event_id,
            vec![vote_alice.event_id, vote_bob.event_id],
        )),
        scope(),
        "2026-11-09T18:50:00Z",
        0x15,
        &peer(),
    );
    let repeal = sign(
        EventBody::Proposal(ProposalBody {
            charter: c2.digest().unwrap(),
            title: "Drop the pnpm rule".into(),
            summary: "The repository moved to bun.".into(),
            action: ProposalAction::Repeal {
                target: adopt.event_id,
            },
        }),
        scope(),
        "2026-11-10T08:00:00Z",
        0x16,
        &peer(),
    );

    let membership = sign(
        EventBody::Membership(MembershipBody {
            credential: credential(),
            acceptance: acceptance(),
        }),
        Scope::all(),
        "2026-11-09T18:05:00Z",
        0x17,
        &device(),
    );
    let revocation_event = sign(
        EventBody::Revocation(RevocationBody {
            revocation: revocation(),
        }),
        Scope::all(),
        "2026-11-10T09:00:00Z",
        0x18,
        &root(),
    );

    // Bob keeps the rule off his own machine and puts that on the record, under the
    // charter that lists him.
    let stance = sign(
        EventBody::Stance(StanceBody {
            proposal_id: adopt.event_id,
            charter: c2.digest().unwrap(),
            stance: Stance::OptedOut,
            reason: Some("Our CI images only ship npm.".into()),
        }),
        scope(),
        "2026-11-10T10:00:00Z",
        0x19,
        &peer(),
    );

    let events = vec![
        ("QUESTION", question, pk(&device())),
        ("ANSWER", answer, pk(&peer())),
        ("PROPOSAL/amend", amend, pk(&device())),
        ("VOTE/amend", amend_vote, pk(&device())),
        ("RESULT/amend", amend_result, pk(&device())),
        ("CHARTER", charter_event, pk(&root())),
        ("PROPOSAL/adopt", adopt, pk(&device())),
        ("VOTE/adopt-alice", vote_alice, pk(&device())),
        ("VOTE/adopt-bob", vote_bob, pk(&peer())),
        ("RESULT/adopt", adopt_result, pk(&peer())),
        ("PROPOSAL/repeal", repeal, pk(&peer())),
        ("MEMBERSHIP", membership, pk(&device())),
        ("REVOCATION", revocation_event, pk(&root())),
        ("STANCE", stance, pk(&peer())),
    ];
    (events, c2)
}

fn jcs_vectors() -> Value {
    let valid: &[(&str, &str)] = &[
        (
            "rfc8785-3.2.3-key-ordering",
            "{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\",\"\\u00f6\":\"Latin Small Letter O With Diaeresis\"}",
        ),
        (
            "rfc8785-3.2.2-string-escaping",
            r#"{"string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}"#,
        ),
        (
            "rfc8785-3.2.2-integer-subset",
            r#"{"numbers": [333333333, 4, 0, -7], "literals": [null, true, false]}"#,
        ),
        ("numeric-string-keys", r#"{"10": "ten", "1": "one", "2": "two", "": "empty"}"#),
        ("case-ordering", r#"{"b": 1, "B": 2, "a": 3, "A": 4, "_": 5}"#),
        (
            "control-characters",
            r#"["\u0000\u0001\u0007\b\t\n\u000b\f\r\u000e\u001f\u007f", "\u2028\u2029"]"#,
        ),
        ("safe-integer-bounds", "[9007199254740991, -9007199254740991, 0, 1, -1]"),
        ("empty-containers", r#"{"a": {}, "b": [], "c": [{}, []]}"#),
        ("nested-sorting", r#"{"z": {"y": 1, "x": [{"b": 2, "a": 1}]}, "a": null}"#),
        ("whitespace-removed", " \n { \"a\" : [ 1 , 2 ] , \"b\" : \"x y\" } \t "),
        ("non-ascii-literal", r#"{"text": "caf\u00e9 \u2603 \ud83d\ude00", "slash": "a/b"}"#),
        (
            "utf16-surrogate-ordering",
            r#"{"\uffff": 1, "\ud800\udc00": 2, "\ue000": 3, "\ud7ff": 4}"#,
        ),
        ("key-prefix-ordering", r#"{"abc": 1, "ab": 2, "a": 3, "b": 4}"#),
    ];
    let invalid: &[(&str, &str, &str)] = &[
        ("duplicate-key", r#"{"a": 1, "a": 2}"#, "duplicate_key"),
        (
            "duplicate-key-escaped",
            r#"{"a": 1, "\u0061": 2}"#,
            "duplicate_key",
        ),
        ("float", r#"{"a": 1.5}"#, "non_integer"),
        ("integral-float", "[1.0]", "non_integer"),
        ("exponent", "[1e2]", "non_integer"),
        ("negative-zero", "[-0]", "non_integer"),
        (
            "integer-too-large",
            "[9007199254740992]",
            "integer_out_of_range",
        ),
        (
            "integer-too-small",
            "[-9007199254740992]",
            "integer_out_of_range",
        ),
        (
            "duplicate-key-nested-in-array",
            r#"{"x": [1, {"y": {"k": 1, "k": 2}}]}"#,
            "duplicate_key",
        ),
        ("too-deep", "[[[[[[[[[1]]]]]]]]]", "too_deep"),
        ("lone-surrogate", r#"["\ud800"]"#, "malformed"),
        ("trailing-data", r#"{"a": 1} {}"#, "malformed"),
        ("trailing-comma", "[1, 2,]", "malformed"),
    ];
    let limits = ParseLimits::EVENT;
    let valid: Vec<Value> = valid
        .iter()
        .map(|(name, input)| {
            let v = jcs::parse_strict_str(input, limits).unwrap();
            json!({"name": name, "input": input, "canonical": jcs::canonicalize(&v).unwrap()})
        })
        .collect();
    let invalid: Vec<Value> = invalid
        .iter()
        .map(|(name, input, err)| {
            let got = jcs::parse_strict_str(input, limits).unwrap_err();
            assert_eq!(error_code(&got), *err, "{name}");
            json!({"name": name, "input": input, "error": err})
        })
        .collect();
    json!({
        "description": "JCS (RFC 8785, integer-only subset). Parse 'input' strictly (max depth 8), canonicalize, compare to 'canonical' byte-for-byte. Every 'invalid' input must be rejected.",
        "max_depth": 8,
        "valid": valid,
        "invalid": invalid,
    })
}

/// The `error` code used in `jcs.json` for each rejection kind.
fn error_code(e: &JcsError) -> &'static str {
    match e {
        JcsError::TooLarge { .. } => "too_large",
        JcsError::TooDeep { .. } => "too_deep",
        JcsError::DuplicateKey => "duplicate_key",
        JcsError::NonInteger => "non_integer",
        JcsError::IntegerOutOfRange => "integer_out_of_range",
        JcsError::Malformed { .. } => "malformed",
    }
}

/// A copy of `v` whose object members are inserted in byte-wise key order at every
/// level. serde_json's default `Map` is a `BTreeMap` (already in that order), but if
/// Cargo ever unified the `preserve_order` feature into this build (any crate in the
/// graph enabling it), `Map` would become an insertion-ordered `IndexMap` and
/// `to_string_pretty` would follow `json!`/serializer field order instead. Rebuilding
/// in sorted order gives the same bytes under both representations.
fn sorted_keys(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut members: Vec<(&String, &Value)> = m.iter().collect();
            members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            let mut out = serde_json::Map::new();
            for (k, v) in members {
                out.insert(k.clone(), sorted_keys(v));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted_keys).collect()),
        other => other.clone(),
    }
}

/// Pretty JSON with sorted keys (see [`sorted_keys`]) and a trailing newline.
fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(&sorted_keys(v)).unwrap() + "\n"
}

fn generate() -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();

    let keys = json!({
        "description": "Ed25519 seeds (RFC 8032 secret keys) used by every vector.",
        "device": {
            "seed_hex": hex::encode(DEVICE_SEED),
            "public_key": pk(&device()).to_string(),
            "fingerprint": pk(&device()).fingerprint(),
        },
        "peer": {
            "seed_hex": hex::encode(PEER_SEED),
            "public_key": pk(&peer()).to_string(),
            "fingerprint": pk(&peer()).fingerprint(),
        },
        "root": {
            "seed_hex": hex::encode(ROOT_SEED),
            "public_key": pk(&root()).to_string(),
            "fingerprint": pk(&root()).fingerprint(),
            "circle_id": circle().to_string(),
            "circle_id_input_hex": hex::encode([b"peerharness-circle-v0\0".as_slice(), pk(&root()).as_bytes().as_slice()].concat()),
        },
    });
    out.insert("keys.json", pretty(&keys));
    out.insert("jcs.json", pretty(&jcs_vectors()));

    let (story_events, c2) = story();
    let evs: Vec<Value> = story_events
        .into_iter()
        .map(|(name, e, signer)| {
            signed_vector(
                name,
                Context::Event,
                &signer,
                e.envelope.to_value().unwrap(),
                e.to_value().unwrap(),
                created().plus_days(1),
            )
        })
        .collect();
    out.insert("events.json", pretty(&Value::Array(evs)));

    let cred = credential();
    let acc = acceptance();
    let rev = revocation();
    let inv = invite();
    let verify_at = ts("2026-11-10T12:00:00Z");
    let creds = json!({
        "membership_credential": signed_vector("membership_credential", Context::Membership, &pk(&root()), cred.unsigned.to_value().unwrap(), cred.to_value().unwrap(), verify_at),
        "acceptance": signed_vector("acceptance", Context::Acceptance, &pk(&device()), acc.unsigned.to_value().unwrap(), acc.to_value().unwrap(), verify_at),
        "revocation": signed_vector("revocation", Context::Revocation, &pk(&root()), rev.unsigned.to_value().unwrap(), rev.to_value().unwrap(), verify_at),
        "invite": signed_vector("invite", Context::Invite, &pk(&root()), inv.unsigned.to_value().unwrap(), inv.to_value().unwrap(), verify_at),
    });
    out.insert("credentials.json", pretty(&creds));

    let c1 = charter_1();
    let charter_vector = |name: &str, c: &Charter| {
        let mut v = signed_vector(
            name,
            Context::Charter,
            &pk(&root()),
            c.unsigned.to_value().unwrap(),
            c.to_value().unwrap(),
            verify_at,
        );
        let whole: Vec<&str> = c
            .content
            .electorate(&Electorate::WholeRoll)
            .map(|m| m.member.as_str())
            .collect();
        let backend_scope = scope();
        let backend_electorate = Electorate::Scope(&backend_scope);
        let backend: Vec<&str> = c
            .content
            .electorate(&backend_electorate)
            .map(|m| m.member.as_str())
            .collect();
        v["electorates"] = json!({
            "amend": {"members": whole, "need_pass": c.content.rules.pass.need(whole.len()), "need_amend": c.content.rules.amend.need(whole.len())},
            "scope team/backend": {"members": backend, "need_pass": c.content.rules.pass.need(backend.len())},
        });
        v
    };
    let charters = json!({
        "description": "The charter chain used by events.json. 'digest' is what a PROPOSAL names in its 'charter' member. charter_2.previous is charter_1.digest and charter_2.justification is the event_id of RESULT/amend. need(n, num/den) = floor(n*num/den) + 1.",
        "charter_1": charter_vector("charter_1", &c1),
        "charter_2": charter_vector("charter_2", &c2),
    });
    out.insert("charters.json", pretty(&charters));

    let m = bundle();
    let b = json!({
        "context": "peerharness-bundle-v0",
        "files": [{"path": "SKILL.md", "content": SKILL_MD}],
        "manifest": m.to_value().unwrap(),
        "canonical": m.to_canonical_json().unwrap(),
        "digest_input_hex": hex::encode(m.digest_input().unwrap()),
        "digest": bundle_digest(&m).unwrap().to_string(),
    });
    out.insert("bundle.json", pretty(&b));
    out
}

#[test]
fn pretty_output_is_independent_of_member_order() {
    // Build the same object with members inserted in two different orders; under
    // `preserve_order` the raw maps would serialize differently.
    let mut a = serde_json::Map::new();
    a.insert("b".into(), json!({"y": 1, "x": [ {"d": 1, "c": 2} ]}));
    a.insert("a".into(), json!(null));
    let mut b = serde_json::Map::new();
    b.insert("a".into(), json!(null));
    b.insert("b".into(), json!({"x": [ {"c": 2, "d": 1} ], "y": 1}));
    let (a, b) = (Value::Object(a), Value::Object(b));
    assert_eq!(pretty(&a), pretty(&b));
    let text = pretty(&a);
    let pos = |needle: &str| text.find(needle).unwrap();
    assert!(pos("\"a\"") < pos("\"b\""));
    assert!(pos("\"x\"") < pos("\"y\""));
    assert!(pos("\"c\"") < pos("\"d\""));
}

#[test]
fn vectors_match_committed_files() {
    let dir = vectors_dir();
    let update = std::env::var_os("PH_UPDATE_VECTORS").is_some();
    for (name, content) in generate() {
        let path = dir.join(name);
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &content).unwrap();
            continue;
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing {name}; run PH_UPDATE_VECTORS=1 cargo test -p ph-protocol --test vectors"
            )
        });
        assert!(
            on_disk == content,
            "{name} drifted from the generator; if intentional, regenerate with PH_UPDATE_VECTORS=1"
        );
    }
}

fn load(name: &str) -> Value {
    let s = std::fs::read_to_string(vectors_dir().join(name)).unwrap();
    serde_json::from_str(&s).unwrap()
}

fn check_common(v: &Value, context: Context) -> Timestamp {
    let unsigned = &v["unsigned"];
    assert_eq!(v["context"], context.as_str());
    let canonical = jcs::canonicalize(unsigned).unwrap();
    assert_eq!(canonical, v["canonical"].as_str().unwrap());
    let input = signing::signing_input(context, unsigned).unwrap();
    assert_eq!(
        hex::encode(&input),
        v["signing_input_hex"].as_str().unwrap()
    );
    let signer: DeviceKey = v["signer_public_key"].as_str().unwrap().parse().unwrap();
    let digest = signing::verify_object(context, &v["signed"], &signer).unwrap();
    let key = if context == Context::Event {
        "event_id"
    } else {
        "digest"
    };
    assert_eq!(digest.to_string(), v[key].as_str().unwrap());
    // tampering with any unsigned member breaks the signature
    let mut tampered = v["signed"].clone();
    tampered["schema"] = json!("tampered");
    assert!(signing::verify_object(context, &tampered, &signer).is_err());
    v["verify_at"].as_str().unwrap().parse().unwrap()
}

#[test]
fn vectors_verify_with_public_api() {
    let keys = load("keys.json");
    assert_eq!(keys["root"]["circle_id"], circle().to_string());
    let root_key: DeviceKey = keys["root"]["public_key"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        CircleId::derive(&root_key).to_string(),
        keys["root"]["circle_id"]
    );

    let jcs_v = load("jcs.json");
    for case in jcs_v["valid"].as_array().unwrap() {
        let v = jcs::parse_strict_str(case["input"].as_str().unwrap(), ParseLimits::EVENT).unwrap();
        assert_eq!(
            jcs::canonicalize(&v).unwrap(),
            case["canonical"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
    for case in jcs_v["invalid"].as_array().unwrap() {
        let err =
            jcs::parse_strict_str(case["input"].as_str().unwrap(), ParseLimits::EVENT).unwrap_err();
        assert_eq!(error_code(&err), case["error"], "{}", case["name"]);
    }

    let events = load("events.json");
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 14);
    let names: Vec<&str> = events.iter().map(|v| v["name"].as_str().unwrap()).collect();
    for t in ph_protocol::EventType::ALL {
        assert!(
            names
                .iter()
                .any(|n| n.split('/').next() == Some(t.as_str())),
            "no vector for {t}"
        );
    }
    for v in events {
        let at = check_common(v, Context::Event);
        let raw = v["signed_canonical"].as_str().unwrap();
        let verified = validate_stateless(raw.as_bytes(), at).unwrap();
        assert_eq!(
            verified.event_id().to_string(),
            v["event_id"].as_str().unwrap()
        );
        assert_eq!(
            verified.event_type().as_str(),
            v["name"].as_str().unwrap().split('/').next().unwrap()
        );
        assert_eq!(v["unsigned"]["type"], verified.event_type().as_str());
        // Permanent records verify at any later time; the others do not.
        let much_later = at.plus_days(3650);
        assert_eq!(
            validate_stateless(raw.as_bytes(), much_later).is_ok(),
            verified.event_type().is_permanent(),
            "{}",
            v["name"]
        );
        assert_eq!(verified.canonical_json(), raw);
        assert_eq!(
            verified.envelope.to_canonical_json().unwrap(),
            v["canonical"].as_str().unwrap()
        );
        let parsed = SignedEnvelope::from_json_bytes(raw.as_bytes()).unwrap();
        assert_eq!(
            parsed.event_id,
            v["event_id"].as_str().unwrap().parse::<EventId>().unwrap()
        );
    }

    let creds = load("credentials.json");
    let c = &creds["membership_credential"];
    let at = check_common(c, Context::Membership);
    let cred =
        MembershipCredential::from_json_bytes(c["signed_canonical"].as_str().unwrap().as_bytes())
            .unwrap();
    verify_credential(&cred, at).unwrap();
    assert_eq!(
        cred.digest().unwrap().to_string(),
        c["digest"].as_str().unwrap()
    );

    let a = &creds["acceptance"];
    let at = check_common(a, Context::Acceptance);
    let acc =
        Acceptance::from_json_bytes(a["signed_canonical"].as_str().unwrap().as_bytes()).unwrap();
    verify_acceptance(&acc, &cred, at).unwrap();
    assert_eq!(
        acc.credential_digest.to_string(),
        c["digest"].as_str().unwrap()
    );

    let r = &creds["revocation"];
    let at = check_common(r, Context::Revocation);
    let rev =
        Revocation::from_json_bytes(r["signed_canonical"].as_str().unwrap().as_bytes()).unwrap();
    verify_revocation(&rev, at).unwrap();

    let i = &creds["invite"];
    let at = check_common(i, Context::Invite);
    let inv = Invite::from_json_bytes(i["signed_canonical"].as_str().unwrap().as_bytes()).unwrap();
    verify_invite(&inv, at).unwrap();

    // The charter chain, and how the events refer to it.
    let charters = load("charters.json");
    let load_charter = |key: &str| -> Charter {
        let v = &charters[key];
        check_common(v, Context::Charter);
        let c =
            Charter::from_json_bytes(v["signed_canonical"].as_str().unwrap().as_bytes()).unwrap();
        verify_charter_signature(&c).unwrap();
        assert_eq!(
            c.digest().unwrap().to_string(),
            v["digest"].as_str().unwrap()
        );
        c
    };
    let c1 = load_charter("charter_1");
    let c2 = load_charter("charter_2");
    assert_eq!((c1.seq, c2.seq), (1, 2));
    assert_eq!(c2.previous, Some(c1.digest().unwrap()));
    let event = |name: &str| -> &Value { events.iter().find(|v| v["name"] == name).unwrap() };
    let body = |name: &str| -> &Value { &event(name)["unsigned"]["body"] };
    // The amendment was proposed under charter 1 and proposes exactly charter 2's content.
    assert_eq!(
        body("PROPOSAL/amend")["charter"],
        c1.digest().unwrap().to_string()
    );
    let proposed: CharterContent =
        serde_json::from_value(body("PROPOSAL/amend")["next"].clone()).unwrap();
    assert_eq!(proposed, c2.content);
    // Charter 2 is justified by the result of that amendment, which the CHARTER event carries.
    assert_eq!(
        c2.justification.unwrap().to_string(),
        event("RESULT/amend")["event_id"].as_str().unwrap()
    );
    assert_eq!(body("CHARTER")["charter"], c2.to_value().unwrap());
    assert_eq!(
        body("RESULT/amend")["proposal_id"],
        event("PROPOSAL/amend")["event_id"]
    );
    assert_eq!(
        body("RESULT/amend")["approvals"],
        json!([event("VOTE/amend")["event_id"]])
    );
    // One member under charter 1: her approval alone is the majority.
    assert_eq!(c1.content.rules.pass.need(c1.content.roll.len()), 1);
    // The rule was proposed under charter 2, where both members must approve.
    assert_eq!(
        body("PROPOSAL/adopt")["charter"],
        c2.digest().unwrap().to_string()
    );
    assert_eq!(c2.content.rules.pass.need(c2.content.roll.len()), 2);
    let approvals = body("RESULT/adopt")["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 2);
    for vote in ["VOTE/adopt-alice", "VOTE/adopt-bob"] {
        assert!(approvals.contains(&event(vote)["event_id"]));
        assert_eq!(
            body(vote)["proposal_id"],
            event("PROPOSAL/adopt")["event_id"]
        );
        let signer: DeviceKey = event(vote)["signer_public_key"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(c2.content.member_of(&signer).is_some());
    }
    assert_eq!(
        body("PROPOSAL/repeal")["target"],
        event("PROPOSAL/adopt")["event_id"]
    );

    let b = load("bundle.json");
    let files = b["files"].as_array().unwrap();
    let content = files[0]["content"].as_str().unwrap();
    let m = manifest_for_files(&[(files[0]["path"].as_str().unwrap(), content.as_bytes())]);
    assert_eq!(m.to_value().unwrap(), b["manifest"]);
    assert_eq!(
        m.to_canonical_json().unwrap(),
        b["canonical"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(m.digest_input().unwrap()),
        b["digest_input_hex"].as_str().unwrap()
    );
    assert_eq!(
        bundle_digest(&m).unwrap().to_string(),
        b["digest"].as_str().unwrap()
    );
    let parsed: BundleManifest = serde_json::from_value(b["manifest"].clone()).unwrap();
    assert_eq!(parsed, m);
}
