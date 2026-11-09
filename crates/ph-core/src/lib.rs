//! # ph-core
//!
//! Foundation types shared by every PeerHarness crate (see `docs/architecture.md`
//! sections 3, 9 and 13):
//!
//! * [`encoding`]: strictly parsed, self-describing string encodings for public keys
//!   ([`DeviceKey`]), signatures ([`Signature`]), nonces ([`Nonce`]) and SHA-256 digests
//!   ([`Digest`], plus the distinct ID newtypes [`EventId`] and [`CircleId`]).
//! * [`timestamp`]: [`Timestamp`], RFC 3339 UTC with whole seconds and a `Z` suffix.
//! * [`scope`]: [`Scope`] syntax and the `covers` relation.
//! * [`role`]: [`Role`] and [`Capability`] and the role-to-capability mapping.
//! * [`candidate`]: the [`CandidateStatus`] state machine and [`transition`].
//! * [`observation`]: [`NormalizedObservation`] and [`SkillCandidate`].
//! * [`mod@redact`]: heuristic secret and home-path redaction ([`redact()`]).
//! * [`clock`]: the [`Clock`] trait, [`SystemClock`] and [`FixedClock`].
//! * [`membership`]: the [`MembershipOracle`] trait and [`DenyReason`].
//! * [`names`]: Agent Skills name validation shared by several crates.
//!
//! ## Privacy
//!
//! No `Display` or error message in this crate contains parsed payload contents. Errors
//! only name the kind of value that failed and a static reason. `Debug` output of the
//! observation and candidate types omits their text and shows only lengths.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod candidate;
pub mod clock;
pub mod encoding;
pub mod error;
pub mod membership;
pub mod names;
pub mod observation;
pub mod redact;
pub mod role;
pub mod scope;
pub mod timestamp;

pub use candidate::{transition, Actor, CandidateStatus, TransitionError};
pub use clock::{Clock, FixedClock, SystemClock};
pub use encoding::{fingerprint, CircleId, DeviceKey, Digest, EventId, Nonce, Signature};
pub use error::{ParseError, RandomnessError};
pub use membership::{DenyAllOracle, DenyReason, MembershipOracle};
pub use names::is_valid_skill_name;
pub use observation::{
    bound_text, Confidence, NormalizedObservation, ObservationId, ObservationKind,
    ObservationSource, SkillCandidate, MAX_OBSERVATION_TEXT_BYTES,
};
pub use redact::{redact, Redacted, REDACTED};
pub use role::{roles_grant, Capability, Role};
pub use scope::Scope;
pub use timestamp::Timestamp;
