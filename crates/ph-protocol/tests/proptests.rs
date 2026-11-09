//! Property tests: hostile input never panics, JCS is idempotent, and any mutation of a
//! signed envelope's body is detected.

use ph_core::{CircleId, DeviceKey, Nonce, Scope, Timestamp};
use ph_protocol::jcs::{self, ParseLimits};
use ph_protocol::wire::{Request, Response};
use ph_protocol::{
    validate_stateless, EnvelopeBuilder, EventBody, Invite, MembershipCredential, QuestionBody,
    SignedEnvelope, SigningKey,
};
use proptest::prelude::*;
use serde_json::{Map, Number, Value};

fn now() -> Timestamp {
    "2026-11-09T18:10:00Z".parse().unwrap()
}

fn signed_question(question: String, topic: String) -> Option<SignedEnvelope> {
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let root = DeviceKey::from_signing_key(&SigningKey::from_bytes(&[2u8; 32]));
    EnvelopeBuilder::new(
        CircleId::derive(&root),
        Scope::new("team/backend").unwrap(),
        EventBody::Question(QuestionBody {
            question,
            topic,
            related_candidate: None,
        }),
    )
    .nonce(Nonce::from_bytes([7; 16]))
    .sign(&sk, now())
    .ok()
}

/// Arbitrary JSON values within the integer-only subset.
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-(1i64 << 53) + 1..(1i64 << 53)).prop_map(|n| Value::Number(Number::from(n))),
        "\\PC{0,12}".prop_map(Value::String),
        // control characters and escapes
        proptest::collection::vec(0u32..0x30, 0..6)
            .prop_map(|v| Value::String(v.into_iter().filter_map(char::from_u32).collect())),
    ];
    leaf.prop_recursive(6, 64, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::btree_map("\\PC{0,6}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn strict_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = jcs::parse_strict(&bytes, ParseLimits::EVENT);
    }

    #[test]
    fn validate_never_panics_on_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = validate_stateless(&bytes, now());
        let _ = Request::from_bytes(&bytes);
        let _ = Response::from_bytes(&bytes);
        let _ = MembershipCredential::from_json_bytes(&bytes);
        let _ = Invite::from_json_bytes(&bytes);
    }

    #[test]
    fn validate_never_panics_on_json(v in arb_json()) {
        let bytes = v.to_string().into_bytes();
        prop_assert!(validate_stateless(&bytes, now()).is_err());
        let _ = Request::from_bytes(&bytes);
    }

    #[test]
    fn jcs_idempotent(v in arb_json()) {
        let c1 = jcs::canonicalize(&v).unwrap();
        let reparsed = jcs::parse_strict_str(&c1, ParseLimits { max_bytes: 1 << 20, max_depth: 16 }).unwrap();
        prop_assert_eq!(&reparsed, &v);
        let c2 = jcs::canonicalize(&reparsed).unwrap();
        prop_assert_eq!(c1, c2);
    }

    #[test]
    fn jcs_ignores_input_formatting(v in arb_json()) {
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        let reparsed = jcs::parse_strict_str(&pretty, ParseLimits { max_bytes: 1 << 20, max_depth: 16 }).unwrap();
        prop_assert_eq!(jcs::canonicalize(&reparsed).unwrap(), jcs::canonicalize(&v).unwrap());
    }

    #[test]
    fn mutated_body_fails(
        q in "[a-zA-Z0-9 ?]{1,200}",
        replacement in "[a-zA-Z0-9 ?]{1,200}",
    ) {
        prop_assume!(q != replacement);
        let e = signed_question(q, "topic".into()).unwrap();
        let ok = e.to_canonical_json().unwrap();
        prop_assert!(validate_stateless(ok.as_bytes(), now()).is_ok());
        let mut v = e.to_value().unwrap();
        v["body"]["question"] = Value::String(replacement);
        let bytes = v.to_string().into_bytes();
        prop_assert!(validate_stateless(&bytes, now()).is_err());
    }

    #[test]
    fn single_byte_flip_detected(idx in any::<prop::sample::Index>(), bit in 0u8..8) {
        let e = signed_question("Should we use pnpm?".into(), "pm".into()).unwrap();
        let mut bytes = e.to_canonical_json().unwrap().into_bytes();
        let i = idx.index(bytes.len());
        bytes[i] ^= 1 << bit;
        // A flip may still decode to the same canonical object only if it hit
        // insignificant formatting, which canonical text has none of.
        if let Ok(v) = validate_stateless(&bytes, now()) {
            prop_assert_eq!(v.event_id(), e.event_id);
        }
    }
}
