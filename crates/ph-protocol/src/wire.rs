//! Wire messages for `/peerharness/req/0.1.0` (architecture section 7).
//!
//! ## Encoding
//!
//! Each frame body is one JSON object, **internally tagged** by a `"type"` member with a
//! `snake_case` variant name; the variant's fields are siblings of `"type"`:
//!
//! ```json
//! {"type":"hello","versions":["0.1"]}
//! {"type":"fetch_events","circle_id":"sha256:…","known":["sha256:…"],"limit":100,"after":"sha256:…"}
//! {"type":"error","code":"unauthorized"}
//! ```
//!
//! Request types: `hello`, `authenticate`, `push_events`, `fetch_events`,
//! `fetch_bundle`. Response types: `hello`, `authenticated`, `push_result`, `events`,
//! `bundle`, `error`. Unknown members are rejected. [`Request::to_bytes`] emits JCS
//! canonical JSON; [`Request::from_bytes`] parses strictly (512 KiB, depth
//! [`MAX_FRAME_DEPTH`], duplicate keys) and enforces every collection bound with
//! `validate()`.
//!
//! Framing (4-byte big-endian length prefix) is done by `ph-network`.
//!
//! Envelopes inside `push_events` / `events` are carried as raw JSON values so that one
//! bad event does not invalidate the whole frame: validate each with
//! [`crate::envelope::validate_stateless_value`].

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ph_core::{CircleId, Digest, EventId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::credentials::{check_addrs, some, MembershipProof};
use crate::error::ProtocolError;
use crate::jcs::{self, ParseLimits};
use crate::limits::{
    MAX_AUTH_MEMBERSHIPS, MAX_BUNDLE_FILES, MAX_BUNDLE_PATH_BYTES, MAX_FETCH_LIMIT, MAX_KNOWN_IDS,
    MAX_PUSH_EVENTS, MAX_SHARED_CIRCLES, MAX_VERSION_BYTES, MAX_VERSION_ENTRIES,
};
pub use crate::limits::{MAX_BUNDLE_BYTES, MAX_EVENT_BYTES, MAX_FRAME_BYTES, MAX_FRAME_DEPTH};

/// libp2p request-response protocol id.
pub const PROTOCOL_ID: &str = "/peerharness/req/0.1.0";
/// The protocol version string exchanged in `hello`.
pub const PROTOCOL_VERSION: &str = "0.1";
/// Capability string: event sync.
pub const CAP_EVENTS: &str = "events";
/// Capability string: bundle fetch.
pub const CAP_BUNDLES: &str = "bundles";

/// A request frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Version negotiation; the only request answered before authentication.
    Hello {
        /// Supported protocol versions (at most 8).
        versions: Vec<String>,
    },
    /// Prove membership(s) and announce listen addresses.
    Authenticate {
        /// Credentials with acceptances, one per circle (at most 16).
        memberships: Vec<MembershipProof>,
        /// The requester's listen multiaddrs (at most 8, each at most 256 bytes).
        listen_addrs: Vec<String>,
    },
    /// Deliver events.
    PushEvents {
        /// Raw envelopes (at most 64).
        events: Vec<Value>,
    },
    /// Ask for events the requester does not have.
    FetchEvents {
        /// Circle.
        circle_id: CircleId,
        /// Event ids the requester already has (at most 4096).
        known: Vec<EventId>,
        /// Maximum events to return (at most 256).
        limit: u32,
        /// Cursor: the last event of an earlier `events` answer **from this responder**
        /// for this circle. The responder serves events in the order it stored them and
        /// continues after this one. Absent, or naming an event the responder does not
        /// hold, means from the beginning. It selects where to start and nothing else:
        /// what the requester may read is decided as for any other request.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "some"
        )]
        after: Option<EventId>,
    },
    /// Ask for a bundle by digest.
    FetchBundle {
        /// Circle.
        circle_id: CircleId,
        /// Bundle digest.
        digest: Digest,
    },
}

/// Status of one pushed event.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushStatus {
    /// Validated and stored.
    Accepted,
    /// Already known.
    Duplicate,
    /// Failed validation or authorization (no reason is given to the peer).
    Rejected,
}

/// Result for one event of a `push_events` request, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushOutcome {
    /// The event id, omitted when the pushed value had no parseable `event_id`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    pub event_id: Option<EventId>,
    /// Outcome.
    pub status: PushStatus,
}

/// One file of a `bundle` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireFile {
    /// Path inside the bundle (at most 256 bytes; policy checked by `ph-skills`).
    pub path: String,
    /// Content, standard base64 (RFC 4648 section 4) **with** padding.
    pub content_b64: String,
}

impl WireFile {
    /// Encodes a file.
    pub fn new(path: &str, content: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            content_b64: STANDARD.encode(content),
        }
    }

    /// The decoded length implied by the padded base64 text (exact for valid input).
    pub fn decoded_len(&self) -> usize {
        let b = self.content_b64.as_bytes();
        let pad = b.iter().rev().take(2).take_while(|&&c| c == b'=').count();
        (b.len().div_ceil(4) * 3).saturating_sub(pad)
    }

    /// Decodes the content (canonical base64 required).
    pub fn decode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.content_b64.len() > encoded_len_bound(MAX_BUNDLE_BYTES) {
            return Err(ProtocolError::TooLarge {
                what: "bundle file",
                size: self.content_b64.len(),
                max: encoded_len_bound(MAX_BUNDLE_BYTES),
            });
        }
        STANDARD
            .decode(&self.content_b64)
            .map_err(|_| ProtocolError::field("content_b64", "invalid base64"))
    }
}

fn encoded_len_bound(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

/// Error codes. The same code is returned whether or not a circle exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Not authenticated or not authorized.
    Unauthorized,
    /// Over a rate limit.
    RateLimited,
    /// Malformed or out-of-bounds request.
    BadRequest,
    /// Frame or object too large.
    TooLarge,
    /// Temporarily unavailable (for example the bundle is not stored locally).
    Unavailable,
}

impl ErrorCode {
    /// The code to answer with when decoding or validating a request failed.
    pub fn for_decode_error(e: &ProtocolError) -> ErrorCode {
        match e {
            ProtocolError::TooLarge { .. }
            | ProtocolError::Jcs(crate::error::JcsError::TooLarge { .. }) => ErrorCode::TooLarge,
            _ => ErrorCode::BadRequest,
        }
    }
}

/// A response frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Answer to `hello`.
    Hello {
        /// Supported versions (at most 8).
        versions: Vec<String>,
        /// Generic capabilities, e.g. `["events","bundles"]` (at most 8).
        capabilities: Vec<String>,
    },
    /// Answer to `authenticate`, given only to a requester whose device is an active
    /// member of at least one circle the responder holds.
    Authenticated {
        /// The responder's credentials with acceptances (at most 16; the reference
        /// implementation sends none, since membership is the roll).
        memberships: Vec<MembershipProof>,
        /// The circles the responder holds in which the requester's device is an active
        /// member (at most 64). A device that has just been admitted learns here which
        /// circle to fetch; it is told about no other circle.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        circles: Vec<CircleId>,
    },
    /// Answer to `push_events`.
    PushResult {
        /// One result per pushed event (at most 64).
        results: Vec<PushOutcome>,
    },
    /// Answer to `fetch_events`.
    Events {
        /// Raw envelopes (at most 256; the responder must also keep the frame under
        /// 512 KiB and set `more`).
        events: Vec<Value>,
        /// Whether more events are available.
        more: bool,
    },
    /// Answer to `fetch_bundle`.
    Bundle {
        /// Bundle digest.
        digest: Digest,
        /// Files (at most 16, total decoded size at most 256 KiB).
        files: Vec<WireFile>,
    },
    /// Error answer to any request.
    Error {
        /// The code.
        code: ErrorCode,
    },
}

fn bound(field: &'static str, len: usize, max: usize) -> Result<(), ProtocolError> {
    if len > max {
        Err(ProtocolError::field(field, "too many entries"))
    } else {
        Ok(())
    }
}

fn check_short_strings(field: &'static str, v: &[String]) -> Result<(), ProtocolError> {
    bound(field, v.len(), MAX_VERSION_ENTRIES)?;
    if v.iter().any(|s| {
        s.is_empty() || s.len() > MAX_VERSION_BYTES || !s.bytes().all(|b| b.is_ascii_graphic())
    }) {
        return Err(ProtocolError::field(field, "invalid entry"));
    }
    Ok(())
}

fn check_events(field: &'static str, events: &[Value], max: usize) -> Result<(), ProtocolError> {
    bound(field, events.len(), max)?;
    if events.iter().any(|e| !e.is_object()) {
        return Err(ProtocolError::field(field, "events must be objects"));
    }
    Ok(())
}

fn encode<T: Serialize>(t: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes = jcs::to_canonical_string(t)?.into_bytes();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::TooLarge {
            what: "frame",
            size: bytes.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], object: &'static str) -> Result<T, ProtocolError> {
    let v = jcs::parse_strict(bytes, ParseLimits::FRAME)?;
    serde_json::from_value(v).map_err(|_| ProtocolError::Schema { object })
}

impl Request {
    /// The standard `hello` request.
    pub fn hello() -> Self {
        Request::Hello {
            versions: vec![PROTOCOL_VERSION.to_owned()],
        }
    }

    /// The `type` tag of this request.
    pub const fn kind(&self) -> &'static str {
        match self {
            Request::Hello { .. } => "hello",
            Request::Authenticate { .. } => "authenticate",
            Request::PushEvents { .. } => "push_events",
            Request::FetchEvents { .. } => "fetch_events",
            Request::FetchBundle { .. } => "fetch_bundle",
        }
    }

    /// Checks every collection bound.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Request::Hello { versions } => check_short_strings("versions", versions),
            Request::Authenticate {
                memberships,
                listen_addrs,
            } => {
                bound("memberships", memberships.len(), MAX_AUTH_MEMBERSHIPS)?;
                check_addrs("listen_addrs", listen_addrs)
            }
            Request::PushEvents { events } => check_events("events", events, MAX_PUSH_EVENTS),
            Request::FetchEvents { known, limit, .. } => {
                bound("known", known.len(), MAX_KNOWN_IDS)?;
                if *limit == 0 || *limit > MAX_FETCH_LIMIT {
                    return Err(ProtocolError::field("limit", "out of bounds"));
                }
                Ok(())
            }
            Request::FetchBundle { .. } => Ok(()),
        }
    }

    /// Canonical JSON bytes (at most 512 KiB).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        encode(self)
    }

    /// Strictly parses and validates a request frame body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let r: Request = decode(bytes, "request")?;
        r.validate()?;
        Ok(r)
    }
}

impl Response {
    /// The standard `hello` response.
    pub fn hello() -> Self {
        Response::Hello {
            versions: vec![PROTOCOL_VERSION.to_owned()],
            capabilities: vec![CAP_EVENTS.to_owned(), CAP_BUNDLES.to_owned()],
        }
    }

    /// An error response.
    pub const fn error(code: ErrorCode) -> Self {
        Response::Error { code }
    }

    /// The `type` tag of this response.
    pub const fn kind(&self) -> &'static str {
        match self {
            Response::Hello { .. } => "hello",
            Response::Authenticated { .. } => "authenticated",
            Response::PushResult { .. } => "push_result",
            Response::Events { .. } => "events",
            Response::Bundle { .. } => "bundle",
            Response::Error { .. } => "error",
        }
    }

    /// Checks every collection bound.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Response::Hello {
                versions,
                capabilities,
            } => {
                check_short_strings("versions", versions)?;
                check_short_strings("capabilities", capabilities)
            }
            Response::Authenticated {
                memberships,
                circles,
            } => {
                bound("memberships", memberships.len(), MAX_AUTH_MEMBERSHIPS)?;
                bound("circles", circles.len(), MAX_SHARED_CIRCLES)
            }
            Response::PushResult { results } => bound("results", results.len(), MAX_PUSH_EVENTS),
            Response::Events { events, .. } => {
                check_events("events", events, MAX_FETCH_LIMIT as usize)
            }
            Response::Bundle { files, .. } => {
                bound("files", files.len(), MAX_BUNDLE_FILES)?;
                let mut total = 0usize;
                for f in files {
                    if f.path.is_empty() || f.path.len() > MAX_BUNDLE_PATH_BYTES {
                        return Err(ProtocolError::field("path", "length out of bounds"));
                    }
                    total = total.saturating_add(f.decoded_len());
                }
                if total > MAX_BUNDLE_BYTES {
                    return Err(ProtocolError::TooLarge {
                        what: "bundle",
                        size: total,
                        max: MAX_BUNDLE_BYTES,
                    });
                }
                Ok(())
            }
            Response::Error { .. } => Ok(()),
        }
    }

    /// Canonical JSON bytes (at most 512 KiB).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        encode(self)
    }

    /// Strictly parses and validates a response frame body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let r: Response = decode(bytes, "response")?;
        r.validate()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest() -> Digest {
        Digest::sha256(b"x")
    }

    #[test]
    fn explicit_form() {
        assert_eq!(
            String::from_utf8(Request::hello().to_bytes().unwrap()).unwrap(),
            r#"{"type":"hello","versions":["0.1"]}"#
        );
        assert_eq!(
            String::from_utf8(Response::error(ErrorCode::Unauthorized).to_bytes().unwrap())
                .unwrap(),
            r#"{"code":"unauthorized","type":"error"}"#
        );
        let r = Request::FetchEvents {
            circle_id: CircleId::from_digest(digest()),
            known: vec![EventId::from_digest(digest())],
            limit: 10,
            after: None,
        };
        let s = String::from_utf8(r.to_bytes().unwrap()).unwrap();
        assert!(s.contains(r#""type":"fetch_events""#));
        // No cursor is no member, so a request without one is what it always was.
        assert!(!s.contains("after"));
        assert_eq!(Request::from_bytes(s.as_bytes()).unwrap(), r);
        let with_cursor = Request::FetchEvents {
            circle_id: CircleId::from_digest(digest()),
            known: vec![],
            limit: 10,
            after: Some(EventId::from_digest(digest())),
        };
        let s = String::from_utf8(with_cursor.to_bytes().unwrap()).unwrap();
        assert!(s.starts_with(r#"{"after":"sha256:"#));
        assert_eq!(Request::from_bytes(s.as_bytes()).unwrap(), with_cursor);
        // An explicit null is not "no cursor".
        let null = s.replace(&format!("\"{}\"", EventId::from_digest(digest())), "null");
        assert!(null.contains(r#""after":null"#));
        assert!(Request::from_bytes(null.as_bytes()).is_err());

        let plain = Response::Authenticated {
            memberships: vec![],
            circles: vec![],
        };
        assert_eq!(
            String::from_utf8(plain.to_bytes().unwrap()).unwrap(),
            r#"{"memberships":[],"type":"authenticated"}"#
        );
        let shared = Response::Authenticated {
            memberships: vec![],
            circles: vec![CircleId::from_digest(digest())],
        };
        let s = shared.to_bytes().unwrap();
        assert_eq!(Response::from_bytes(&s).unwrap(), shared);
        let too_many = Response::Authenticated {
            memberships: vec![],
            circles: vec![CircleId::from_digest(digest()); MAX_SHARED_CIRCLES + 1],
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn roundtrips() {
        let reqs = vec![
            Request::hello(),
            Request::Authenticate {
                memberships: vec![],
                listen_addrs: vec!["/ip4/127.0.0.1/udp/1/quic-v1".into()],
            },
            Request::PushEvents {
                events: vec![json!({"a": 1})],
            },
            Request::FetchBundle {
                circle_id: CircleId::from_digest(digest()),
                digest: digest(),
            },
        ];
        for r in reqs {
            let b = r.to_bytes().unwrap();
            assert_eq!(Request::from_bytes(&b).unwrap(), r, "{}", r.kind());
        }
        let resps = vec![
            Response::hello(),
            Response::Authenticated {
                memberships: vec![],
                circles: vec![CircleId::from_digest(digest())],
            },
            Response::PushResult {
                results: vec![
                    PushOutcome {
                        event_id: Some(EventId::from_digest(digest())),
                        status: PushStatus::Accepted,
                    },
                    PushOutcome {
                        event_id: None,
                        status: PushStatus::Rejected,
                    },
                ],
            },
            Response::Events {
                events: vec![],
                more: false,
            },
            Response::Bundle {
                digest: digest(),
                files: vec![WireFile::new("SKILL.md", b"hello")],
            },
        ];
        for r in resps {
            let b = r.to_bytes().unwrap();
            assert_eq!(Response::from_bytes(&b).unwrap(), r, "{}", r.kind());
        }
        assert_eq!(
            WireFile::new("SKILL.md", b"hello").decode().unwrap(),
            b"hello"
        );
        assert!(WireFile {
            path: "x".into(),
            content_b64: "!!!".into()
        }
        .decode()
        .is_err());
    }

    #[test]
    fn membership_proofs_roundtrip_in_tagged_enum() {
        use crate::credentials::{UnsignedAcceptance, UnsignedMembershipCredential};
        use ed25519_dalek::SigningKey;
        use ph_core::{DeviceKey, Role, Scope, Timestamp};
        let root = SigningKey::from_bytes(&[2; 32]);
        let dev = SigningKey::from_bytes(&[1; 32]);
        let t: Timestamp = "2026-11-09T18:00:00Z".parse().unwrap();
        let cred = UnsignedMembershipCredential::new(
            DeviceKey::from_signing_key(&root),
            DeviceKey::from_signing_key(&dev),
            vec![Role::Member],
            vec![Scope::new("team").unwrap()],
            t,
            t.plus_days(30),
        )
        .sign(&root)
        .unwrap();
        let acc = UnsignedAcceptance::for_credential(&cred, t)
            .unwrap()
            .sign(&dev)
            .unwrap();
        let proof = MembershipProof {
            credential: cred,
            acceptance: acc,
        };
        let req = Request::Authenticate {
            memberships: vec![proof.clone()],
            listen_addrs: vec![],
        };
        let back = Request::from_bytes(&req.to_bytes().unwrap()).unwrap();
        assert_eq!(back, req);
        let resp = Response::Authenticated {
            memberships: vec![proof],
            circles: vec![],
        };
        let back = Response::from_bytes(&resp.to_bytes().unwrap()).unwrap();
        assert_eq!(back, resp);
        crate::credentials::verify_membership_proof(
            match &back {
                Response::Authenticated { memberships, .. } => &memberships[0],
                _ => unreachable!(),
            },
            t,
        )
        .unwrap();
        // an unknown member inside a nested credential is rejected
        let mut v: Value = serde_json::from_slice(&req.to_bytes().unwrap()).unwrap();
        v["memberships"][0]["credential"]["extra"] = json!(1);
        assert!(Request::from_bytes(v.to_string().as_bytes()).is_err());
    }

    #[test]
    fn rejects() {
        for bad in [
            r#"{"type":"hello","versions":["0.1"],"extra":1}"#,
            r#"{"type":"gossip"}"#,
            r#"{"versions":["0.1"]}"#,
            r#"{"type":"hello","type":"hello","versions":[]}"#,
            r#"{"type":"fetch_events","circle_id":"sha256:00","known":[],"limit":1}"#,
            r#"{"type":"push_events","events":[1]}"#,
            r#"{"type":"push_events","events":[{"a":1.5}]}"#,
            r#"[]"#,
        ] {
            assert!(Request::from_bytes(bad.as_bytes()).is_err(), "{bad}");
        }
        let c = CircleId::from_digest(digest());
        let too_many = Request::FetchEvents {
            circle_id: c,
            known: vec![EventId::from_digest(digest()); MAX_KNOWN_IDS + 1],
            limit: 1,
            after: None,
        };
        assert!(too_many.validate().is_err());
        let limit = Request::FetchEvents {
            circle_id: c,
            known: vec![],
            limit: MAX_FETCH_LIMIT + 1,
            after: None,
        };
        assert!(limit.validate().is_err());
        let push = Request::PushEvents {
            events: vec![json!({}); MAX_PUSH_EVENTS + 1],
        };
        assert!(push.validate().is_err());
        let addrs = Request::Authenticate {
            memberships: vec![],
            listen_addrs: vec!["/a".into(); 9],
        };
        assert!(addrs.validate().is_err());
        let big = vec![b' '; MAX_FRAME_BYTES + 1];
        let e = Request::from_bytes(&big).unwrap_err();
        assert_eq!(ErrorCode::for_decode_error(&e), ErrorCode::TooLarge);
        let e = Request::from_bytes(b"{").unwrap_err();
        assert_eq!(ErrorCode::for_decode_error(&e), ErrorCode::BadRequest);
        let huge_bundle = Response::Bundle {
            digest: digest(),
            files: vec![WireFile::new("SKILL.md", &vec![0u8; MAX_BUNDLE_BYTES + 10])],
        };
        assert!(huge_bundle.validate().is_err());
    }
}
