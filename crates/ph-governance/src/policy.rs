//! Quorum policy (architecture section 10).
//!
//! * [`CirclePolicy`] is the circle-wide rule set, stored with the circle
//!   (`circles.policy_json` / `circles.policy_hash`). The default is
//!   `{min_approvals: 2, require_non_proposer: true, block_on_reject: true}`.
//! * [`LocalPolicy`] is a node's own addition (for example "the repository owner must
//!   approve"). It can only make eligibility **stricter**: it adds required approvers and
//!   can raise the approval count, never lower it.

use std::fmt;

use ph_core::{DeviceKey, Digest};
use serde::{Deserialize, Serialize};

/// Domain-separation context for [`CirclePolicy::policy_hash`].
pub const POLICY_HASH_CONTEXT: &str = "peerharness-policy-v0";

/// Upper bound for `min_approvals`: a RELEASE can list at most 64 approvals
/// (`ph_protocol::limits::MAX_RELEASE_APPROVALS`), so a larger quorum could never be
/// evidenced.
pub const MAX_MIN_APPROVALS: u32 = ph_protocol::limits::MAX_RELEASE_APPROVALS as u32;

/// Why a policy document was refused. `Display` never quotes the input.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum PolicyError {
    /// The JSON is malformed, has unknown or duplicate fields, or misses a field.
    #[error("policy document is malformed")]
    Malformed,
    /// `min_approvals` is outside `1..=MAX_MIN_APPROVALS`.
    #[error("policy min_approvals is out of range")]
    MinApprovalsOutOfRange,
}

/// The circle-wide quorum policy.
///
/// Serialized exactly as `{"block_on_reject":bool,"min_approvals":int,"require_non_proposer":bool}`
/// (all fields required, unknown fields rejected).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CirclePolicy {
    /// Minimum number of distinct eligible approvers (`1..=64`).
    pub min_approvals: u32,
    /// At least one approver must be someone other than the proposer.
    pub require_non_proposer: bool,
    /// Any eligible voter whose latest decision is `reject` or `revise` blocks
    /// eligibility.
    pub block_on_reject: bool,
}

impl Default for CirclePolicy {
    fn default() -> Self {
        Self {
            min_approvals: 2,
            require_non_proposer: true,
            block_on_reject: true,
        }
    }
}

impl CirclePolicy {
    /// Checks `min_approvals` is in `1..=MAX_MIN_APPROVALS`.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if (1..=MAX_MIN_APPROVALS).contains(&self.min_approvals) {
            Ok(())
        } else {
            Err(PolicyError::MinApprovalsOutOfRange)
        }
    }

    /// Strictly parses a policy document (duplicate keys, unknown fields, floats and
    /// missing fields are rejected) and validates it.
    pub fn from_json(s: &str) -> Result<Self, PolicyError> {
        let limits = ph_protocol::jcs::ParseLimits {
            max_bytes: 4096,
            max_depth: 2,
        };
        let v =
            ph_protocol::jcs::parse_strict_str(s, limits).map_err(|_| PolicyError::Malformed)?;
        let p: CirclePolicy = serde_json::from_value(v).map_err(|_| PolicyError::Malformed)?;
        p.validate()?;
        Ok(p)
    }

    /// The RFC 8785 canonical JSON of the policy (the form stored as `policy_json`).
    ///
    /// Produced directly (the struct is three scalars with integer values below
    /// 2^53, so the JCS form is fixed); a unit test checks it equals
    /// `ph_protocol::jcs::to_canonical_string`.
    pub fn canonical_json(&self) -> String {
        format!(
            "{{\"block_on_reject\":{},\"min_approvals\":{},\"require_non_proposer\":{}}}",
            self.block_on_reject, self.min_approvals, self.require_non_proposer
        )
    }

    /// `Digest::domain("peerharness-policy-v0", JCS(policy))`, i.e.
    /// `SHA-256("peerharness-policy-v0" || 0x00 || canonical_json)`.
    pub fn policy_hash(&self) -> Digest {
        Digest::domain(POLICY_HASH_CONTEXT, self.canonical_json().as_bytes())
    }

    /// The number of approvals required once `local` is applied (never below 1).
    pub fn required_approvals(&self, local: &LocalPolicy) -> u32 {
        self.min_approvals
            .max(local.extra_min_approvals.unwrap_or(0))
            .max(1)
    }
}

/// A node's own stricter-than-circle requirements (from local config).
///
/// Every field can only add requirements: `required_approvers` must all be among the
/// approvers, and `extra_min_approvals` raises (never lowers) the approval count to
/// `max(circle.min_approvals, extra_min_approvals)`. Two nodes with different local
/// policies can reach different conclusions about the same proposal; that is intended
/// (distinct local views).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalPolicy {
    /// Keys that must each be among the approvers.
    pub required_approvers: Vec<DeviceKey>,
    /// A higher approval count than the circle policy (ignored if not higher).
    pub extra_min_approvals: Option<u32>,
}

impl LocalPolicy {
    /// Whether this local policy adds no requirement.
    pub fn is_empty(&self) -> bool {
        self.required_approvers.is_empty() && self.extra_min_approvals.is_none()
    }
}

impl fmt::Display for CirclePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "min_approvals={} require_non_proposer={} block_on_reject={}",
            self.min_approvals, self.require_non_proposer, self.block_on_reject
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_canonical_form() {
        let p = CirclePolicy::default();
        assert_eq!(p.min_approvals, 2);
        assert!(p.require_non_proposer && p.block_on_reject);
        let jcs = ph_protocol::jcs::to_canonical_string(&p).unwrap();
        assert_eq!(p.canonical_json(), jcs);
        assert_eq!(
            jcs,
            r#"{"block_on_reject":true,"min_approvals":2,"require_non_proposer":true}"#
        );
        for p in [
            CirclePolicy {
                min_approvals: 64,
                require_non_proposer: false,
                block_on_reject: false,
            },
            CirclePolicy {
                min_approvals: 1,
                require_non_proposer: true,
                block_on_reject: false,
            },
        ] {
            assert_eq!(
                p.canonical_json(),
                ph_protocol::jcs::to_canonical_string(&p).unwrap()
            );
            assert_eq!(CirclePolicy::from_json(&p.canonical_json()), Ok(p));
        }
    }

    #[test]
    fn hash_is_domain_separated_and_stable() {
        let p = CirclePolicy::default();
        assert_eq!(p.policy_hash(), p.policy_hash());
        assert_ne!(
            p.policy_hash(),
            Digest::sha256(p.canonical_json().as_bytes())
        );
        let q = CirclePolicy {
            min_approvals: 3,
            ..p
        };
        assert_ne!(p.policy_hash(), q.policy_hash());
    }

    #[test]
    fn strict_parse() {
        let bad = [
            r#"{"min_approvals":2,"require_non_proposer":true}"#,
            r#"{"block_on_reject":true,"min_approvals":2,"require_non_proposer":true,"x":1}"#,
            r#"{"block_on_reject":true,"min_approvals":2.5,"require_non_proposer":true}"#,
            r#"{"block_on_reject":true,"block_on_reject":false,"min_approvals":2,"require_non_proposer":true}"#,
            r#"{"block_on_reject":true,"min_approvals":-1,"require_non_proposer":true}"#,
            "[]",
            "",
        ];
        for b in bad {
            assert_eq!(
                CirclePolicy::from_json(b),
                Err(PolicyError::Malformed),
                "{b}"
            );
        }
        for n in [0, 65, 1000] {
            let s = format!(
                r#"{{"block_on_reject":true,"min_approvals":{n},"require_non_proposer":true}}"#
            );
            assert_eq!(
                CirclePolicy::from_json(&s),
                Err(PolicyError::MinApprovalsOutOfRange)
            );
        }
    }

    #[test]
    fn local_can_only_raise() {
        let c = CirclePolicy::default();
        let mut l = LocalPolicy::default();
        assert!(l.is_empty());
        assert_eq!(c.required_approvals(&l), 2);
        l.extra_min_approvals = Some(1);
        assert_eq!(c.required_approvals(&l), 2);
        l.extra_min_approvals = Some(4);
        assert_eq!(c.required_approvals(&l), 4);
        let zero = CirclePolicy {
            min_approvals: 0,
            ..c
        };
        assert_eq!(zero.required_approvals(&LocalPolicy::default()), 1);
        let parsed: LocalPolicy = serde_json::from_str("{}").unwrap();
        assert!(parsed.is_empty());
        assert!(serde_json::from_str::<LocalPolicy>(r#"{"bogus":1}"#).is_err());
    }
}
