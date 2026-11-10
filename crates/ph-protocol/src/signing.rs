//! Domain-separated signing (architecture section 4).
//!
//! ```text
//! unsigned      = the JSON object with the top-level "signature" and "event_id" members removed
//! signing_input = UTF8(context) || 0x00 || JCS(unsigned)
//! signature     = Ed25519-Sign(key, signing_input)        (RFC 8032, pure Ed25519)
//! object_digest = "sha256:" + hex(SHA-256(signing_input))
//! event_id      = object_digest of an envelope
//! ```
//!
//! Verification always uses `verify_strict` (rejects small-order keys and
//! non-canonical signatures).

use ed25519_dalek::{Signer as _, SigningKey};
use ph_core::{DeviceKey, Digest, EventId, Signature};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::ProtocolError;
use crate::jcs;

/// Name of the transmitted signature member.
pub const SIGNATURE_FIELD: &str = "signature";
/// Name of the transmitted event id member (envelopes only).
pub const EVENT_ID_FIELD: &str = "event_id";

/// The signed object kinds and their domain-separation contexts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Context {
    /// Event envelope, schema `peerharness.event/0.1`, context `peerharness-event-v0`.
    Event,
    /// Membership credential, schema `peerharness.membership/0.1`, context
    /// `peerharness-membership-v0`.
    Membership,
    /// Acceptance, schema `peerharness.acceptance/0.1`, context `peerharness-acceptance-v0`.
    Acceptance,
    /// Revocation, schema `peerharness.revocation/0.1`, context `peerharness-revocation-v0`.
    Revocation,
    /// Invitation, schema `peerharness.invite/0.1`, context `peerharness-invite-v0`.
    Invite,
    /// Charter, schema `peerharness.charter/0.1`, context `peerharness-charter-v0`.
    Charter,
}

impl Context {
    /// All contexts.
    pub const ALL: [Context; 6] = [
        Context::Event,
        Context::Membership,
        Context::Acceptance,
        Context::Revocation,
        Context::Invite,
        Context::Charter,
    ];

    /// The context string (without the trailing NUL).
    pub const fn as_str(self) -> &'static str {
        match self {
            Context::Event => "peerharness-event-v0",
            Context::Membership => "peerharness-membership-v0",
            Context::Acceptance => "peerharness-acceptance-v0",
            Context::Revocation => "peerharness-revocation-v0",
            Context::Invite => "peerharness-invite-v0",
            Context::Charter => "peerharness-charter-v0",
        }
    }

    /// The `schema` value objects of this kind carry.
    pub const fn schema(self) -> &'static str {
        match self {
            Context::Event => "peerharness.event/0.1",
            Context::Membership => "peerharness.membership/0.1",
            Context::Acceptance => "peerharness.acceptance/0.1",
            Context::Revocation => "peerharness.revocation/0.1",
            Context::Invite => "peerharness.invite/0.1",
            Context::Charter => "peerharness.charter/0.1",
        }
    }

    /// A short object name for error messages.
    pub const fn object_name(self) -> &'static str {
        match self {
            Context::Event => "event",
            Context::Membership => "membership credential",
            Context::Acceptance => "acceptance",
            Context::Revocation => "revocation",
            Context::Invite => "invite",
            Context::Charter => "charter",
        }
    }

    /// Whether objects of this kind also transmit an `event_id`.
    pub const fn has_event_id(self) -> bool {
        matches!(self, Context::Event)
    }
}

/// `UTF8(context) || 0x00 || canonical`.
pub fn domain_separated(context: &str, canonical: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + 1 + canonical.len());
    out.extend_from_slice(context.as_bytes());
    out.push(0);
    out.extend_from_slice(canonical);
    out
}

/// The signing input for an *unsigned* object.
///
/// Fails if `unsigned` is not a JSON object, contains a top-level `signature` (or, for
/// [`Context::Event`], `event_id`) member, or is outside the JCS subset.
pub fn signing_input(context: Context, unsigned: &Value) -> Result<Vec<u8>, ProtocolError> {
    let obj = unsigned.as_object().ok_or(ProtocolError::Schema {
        object: context.object_name(),
    })?;
    if obj.contains_key(SIGNATURE_FIELD) || obj.contains_key(EVENT_ID_FIELD) {
        return Err(ProtocolError::Schema {
            object: context.object_name(),
        });
    }
    let canonical = jcs::canonicalize_bytes(unsigned)?;
    Ok(domain_separated(context.as_str(), &canonical))
}

/// `sha256:` digest of a signing input.
pub fn digest_of_input(input: &[u8]) -> Digest {
    Digest::sha256(input)
}

/// The object digest of an unsigned object (the `event_id` for envelopes, the
/// `credential_digest` for credentials).
pub fn object_digest(context: Context, unsigned: &Value) -> Result<Digest, ProtocolError> {
    signing_input(context, unsigned).map(|i| digest_of_input(&i))
}

/// Signs raw bytes.
pub fn sign_input(key: &SigningKey, input: &[u8]) -> Signature {
    Signature::from_dalek(&key.sign(input))
}

/// Verifies a signature over raw bytes with `verify_strict`.
pub fn verify_input(
    context: Context,
    key: &DeviceKey,
    input: &[u8],
    sig: &Signature,
) -> Result<(), ProtocolError> {
    let bad = ProtocolError::BadSignature {
        object: context.object_name(),
    };
    let vk = key.to_verifying_key().map_err(|_| bad.clone())?;
    vk.verify_strict(input, &sig.to_dalek()).map_err(|_| bad)
}

/// Serializes `unsigned` and returns the signed JSON object: the unsigned members plus
/// `signature` (and `event_id` for [`Context::Event`]).
pub fn sign_object<T: Serialize + ?Sized>(
    context: Context,
    key: &SigningKey,
    unsigned: &T,
) -> Result<Value, ProtocolError> {
    let value = jcs::to_value(unsigned)?;
    let input = signing_input(context, &value)?;
    let sig = sign_input(key, &input);
    let Value::Object(mut obj) = value else {
        return Err(ProtocolError::Schema {
            object: context.object_name(),
        });
    };
    obj.insert(SIGNATURE_FIELD.to_owned(), Value::String(sig.to_string()));
    if context.has_event_id() {
        let id = EventId::from_digest(digest_of_input(&input));
        obj.insert(EVENT_ID_FIELD.to_owned(), Value::String(id.to_string()));
    }
    Ok(Value::Object(obj))
}

/// Splits a signed object into `(unsigned, signature, event_id)`.
///
/// `event_id` is required for [`Context::Event`] and rejected otherwise.
pub fn split_signed(
    context: Context,
    signed: &Value,
) -> Result<(Value, Signature, Option<EventId>), ProtocolError> {
    let schema_err = || ProtocolError::Schema {
        object: context.object_name(),
    };
    let obj = signed.as_object().ok_or_else(schema_err)?;
    let mut unsigned: Map<String, Value> = obj.clone();
    let sig = unsigned
        .remove(SIGNATURE_FIELD)
        .and_then(|v| v.as_str().and_then(|s| s.parse::<Signature>().ok()))
        .ok_or_else(schema_err)?;
    let event_id = match unsigned.remove(EVENT_ID_FIELD) {
        Some(v) if context.has_event_id() => Some(
            v.as_str()
                .and_then(|s| s.parse::<EventId>().ok())
                .ok_or_else(schema_err)?,
        ),
        Some(_) => return Err(schema_err()),
        None if context.has_event_id() => return Err(schema_err()),
        None => None,
    };
    Ok((Value::Object(unsigned), sig, event_id))
}

/// Verifies a signed JSON object: strips `signature` (and `event_id`), recomputes the
/// signing input, checks the signature by `signer` with `verify_strict`, and for
/// envelopes checks that the transmitted `event_id` equals the recomputed digest.
///
/// Returns the object digest. This checks only the signature, not the schema; use the
/// typed `validate`/`verify_*` functions for full validation.
pub fn verify_object(
    context: Context,
    signed: &Value,
    signer: &DeviceKey,
) -> Result<Digest, ProtocolError> {
    let (unsigned, sig, event_id) = split_signed(context, signed)?;
    let input = signing_input(context, &unsigned)?;
    verify_input(context, signer, &input, &sig)?;
    let digest = digest_of_input(&input);
    if let Some(id) = event_id {
        if id.digest() != digest {
            return Err(ProtocolError::EventIdMismatch);
        }
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    #[test]
    fn signing_input_layout() {
        let v = json!({"b": 1, "a": "x"});
        let input = signing_input(Context::Membership, &v).unwrap();
        assert_eq!(
            input,
            b"peerharness-membership-v0\0{\"a\":\"x\",\"b\":1}".to_vec()
        );
        assert!(signing_input(Context::Event, &json!({"signature": "x"})).is_err());
        assert!(signing_input(Context::Event, &json!([1])).is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let k = key();
        let pk = DeviceKey::from_signing_key(&k);
        let unsigned = json!({"schema": "peerharness.event/0.1", "n": 1});
        let signed = sign_object(Context::Event, &k, &unsigned).unwrap();
        let d = verify_object(Context::Event, &signed, &pk).unwrap();
        assert_eq!(d, object_digest(Context::Event, &unsigned).unwrap());
        assert_eq!(signed["event_id"], json!(d.to_string()));

        // modified body
        let mut m = signed.clone();
        m["n"] = json!(2);
        assert_eq!(
            verify_object(Context::Event, &m, &pk),
            Err(ProtocolError::BadSignature { object: "event" })
        );
        // wrong event id
        let mut m = signed.clone();
        m["event_id"] = json!(Digest::sha256(b"x").to_string());
        assert_eq!(
            verify_object(Context::Event, &m, &pk),
            Err(ProtocolError::EventIdMismatch)
        );
        // wrong key
        let other = DeviceKey::from_signing_key(&SigningKey::from_bytes(&[9u8; 32]));
        assert!(verify_object(Context::Event, &signed, &other).is_err());
        // cross-context replay
        let mut no_id = signed.clone();
        no_id.as_object_mut().unwrap().remove("event_id");
        assert!(verify_object(Context::Membership, &no_id, &pk).is_err());
        // missing event_id for events
        assert!(verify_object(Context::Event, &no_id, &pk).is_err());
    }

    #[test]
    fn non_event_contexts_reject_event_id() {
        let k = key();
        let pk = DeviceKey::from_signing_key(&k);
        let signed = sign_object(Context::Acceptance, &k, &json!({"a": 1})).unwrap();
        assert!(signed.get("event_id").is_none());
        assert!(verify_object(Context::Acceptance, &signed, &pk).is_ok());
        let mut m = signed;
        m["event_id"] = json!(Digest::sha256(b"x").to_string());
        assert!(verify_object(Context::Acceptance, &m, &pk).is_err());
    }
}
