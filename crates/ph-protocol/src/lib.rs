//! # ph-protocol
//!
//! The PeerHarness v0 protocol (architecture sections 4-7 and 11):
//!
//! * [`jcs`]: our own RFC 8785 JSON Canonicalization over an integer-only JSON subset,
//!   plus a strict parser (duplicate keys, depth and size limits).
//! * [`signing`]: domain-separated Ed25519 signing (`context || 0x00 || JCS(unsigned)`),
//!   object digests and generic sign/verify helpers.
//! * [`envelope`]: event envelopes, typed bodies and stateless validation.
//! * [`credentials`]: membership credentials, acceptances, revocations and invites.
//! * [`charter`]: the circle charter (voting rules, roll of members, carried rules).
//! * [`bundle`]: skill bundle manifests and the bundle digest.
//! * [`wire`]: request/response messages for `/peerharness/req/0.1.0`.
//! * [`limits`]: every size, count, depth and time limit in one place.
//! * [`text`]: bounds and character checks for free-text fields.
//!
//! Golden cross-language test vectors live in `crates/ph-protocol/tests/vectors/`.
//!
//! ## Privacy
//!
//! Error messages ([`ProtocolError`], [`JcsError`]) never contain payload contents: no
//! field values, no object keys from the input, no `serde_json` messages (which can quote
//! input). They name the object kind, a static field name, sizes or limits only.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bundle;
pub mod charter;
pub mod credentials;
pub mod envelope;
pub mod error;
pub mod jcs;
pub mod limits;
pub mod signing;
pub mod text;
pub mod wire;

pub use bundle::{bundle_digest, manifest_for_files, BundleFile, BundleManifest};
pub use charter::{
    is_valid_member_name, verify_charter_signature, Charter, CharterContent, CharterRules,
    Electorate, RollEntry, Threshold, UnsignedCharter,
};
pub use credentials::{
    verify_acceptance, verify_acceptance_signature, verify_credential, verify_credential_signature,
    verify_invite, verify_invite_for_subject, verify_membership_proof, verify_revocation,
    verify_revocation_signature, Acceptance, Invite, MembershipCredential, MembershipProof,
    Revocation, UnsignedAcceptance, UnsignedInvite, UnsignedMembershipCredential,
    UnsignedRevocation,
};
pub use envelope::{
    check_time_rules, check_time_rules_for, validate_stateless, validate_stateless_value,
    AdoptAction, AnswerBody, AnswerChoice, Authorization, CharterBody, EnvelopeBuilder, EventBody,
    EventType, MembershipBody, ProposalAction, ProposalBody, ProposalKind, QuestionBody,
    ResultBody, RevocationBody, SignedEnvelope, UnsignedEnvelope, VerifiedEnvelope, VoteBody,
    VoteDecision,
};
pub use error::{JcsError, ProtocolError, TimeRule};
pub use signing::{object_digest, sign_object, signing_input, verify_object, Context};

/// Re-export so dependants use the same `ed25519-dalek` types.
pub use ed25519_dalek::SigningKey;
