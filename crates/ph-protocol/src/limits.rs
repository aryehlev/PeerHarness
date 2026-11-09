//! Every protocol limit in one place.

/// Maximum canonical size of one event envelope.
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
/// Maximum size of a wire frame body (requests and responses).
pub const MAX_FRAME_BYTES: usize = 512 * 1024;
/// Maximum total decoded size of a skill bundle.
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024;
/// Maximum JSON nesting depth of a signed object (an object or array at the top level
/// has depth 1).
pub const MAX_DEPTH: usize = 8;
/// Maximum JSON nesting depth of a wire frame: envelopes are nested two levels deep in
/// `PushEvents` / `Events`, so a frame may be `MAX_DEPTH + 2` deep. Each embedded
/// envelope is still checked against [`MAX_DEPTH`] on its own.
pub const MAX_FRAME_DEPTH: usize = MAX_DEPTH + 2;
/// Maximum size of a standalone credential, acceptance, revocation or invite document.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

/// Allowed clock skew for "not in the future" checks, in seconds.
pub const CLOCK_SKEW_SECS: i64 = 300;
/// Maximum `expires_at - created_at` of an event, in seconds (400 days).
pub const MAX_EVENT_LIFETIME_SECS: i64 = 400 * 86_400;
/// Maximum `expires_at - issued_at` of a membership credential, in seconds (400 days).
pub const MAX_CREDENTIAL_LIFETIME_SECS: i64 = 400 * 86_400;

/// Default event lifetimes, in seconds.
pub mod lifetimes {
    /// QUESTION: 30 days.
    pub const QUESTION_SECS: i64 = 30 * 86_400;
    /// ANSWER: 30 days.
    pub const ANSWER_SECS: i64 = 30 * 86_400;
    /// PROPOSAL: 90 days.
    pub const PROPOSAL_SECS: i64 = 90 * 86_400;
    /// VOTE: 90 days.
    pub const VOTE_SECS: i64 = 90 * 86_400;
    /// RELEASE: 365 days.
    pub const RELEASE_SECS: i64 = 365 * 86_400;
    /// REVOCATION: 365 days.
    pub const REVOCATION_SECS: i64 = 365 * 86_400;
    /// Default invite validity: 24 hours.
    pub const INVITE_SECS: i64 = 86_400;
    /// Default credential validity: 30 days.
    pub const CREDENTIAL_SECS: i64 = 30 * 86_400;
}

/// Event body text limits, in Unicode scalar values (code points).
pub mod text {
    /// QUESTION `question`.
    pub const QUESTION: usize = 2000;
    /// QUESTION `topic`.
    pub const TOPIC: usize = 128;
    /// ANSWER / VOTE `rationale`.
    pub const RATIONALE: usize = 2000;
    /// PROPOSAL `description`.
    pub const DESCRIPTION: usize = 1024;
    /// PROPOSAL `title`.
    pub const TITLE: usize = 200;
    /// PROPOSAL `provenance_summary`.
    pub const PROVENANCE_SUMMARY: usize = 1000;
    /// REVOCATION `reason`.
    pub const REVOCATION_REASON: usize = 200;
    /// INVITE `circle_name`.
    pub const CIRCLE_NAME: usize = 64;
}

/// Maximum approvals listed in a RELEASE.
pub const MAX_RELEASE_APPROVALS: usize = 64;
/// Maximum scopes in a credential.
pub const MAX_CREDENTIAL_SCOPES: usize = 16;
/// Maximum roles in a credential (each role at most once).
pub const MAX_CREDENTIAL_ROLES: usize = 2;
/// Maximum issuer addresses in an invite / listen addresses in `Authenticate`.
pub const MAX_ADDRS: usize = 8;
/// Maximum length of one multiaddr string, in bytes.
pub const MAX_ADDR_BYTES: usize = 256;

/// Maximum events in `PushEvents`.
pub const MAX_PUSH_EVENTS: usize = 64;
/// Maximum ids in `FetchEvents.known`.
pub const MAX_KNOWN_IDS: usize = 4096;
/// Maximum `FetchEvents.limit` and events in an `Events` response.
pub const MAX_FETCH_LIMIT: u32 = 256;
/// Maximum memberships in `Authenticate` / `Authenticated`.
pub const MAX_AUTH_MEMBERSHIPS: usize = 16;
/// Maximum entries in `versions` / `capabilities` lists.
pub const MAX_VERSION_ENTRIES: usize = 8;
/// Maximum length of one version or capability string, in bytes.
pub const MAX_VERSION_BYTES: usize = 32;
/// Maximum files in a `Bundle` response.
pub const MAX_BUNDLE_FILES: usize = 16;
/// Maximum length of a bundle file path, in bytes.
pub const MAX_BUNDLE_PATH_BYTES: usize = 256;
