//! A node's own conditions for following a passed rule (architecture section 10.9).
//!
//! The rules of the vote live in the charter ([`ph_protocol::CharterRules`]) and are the
//! same for every member. [`LocalPolicy`] is different: it is one node's private
//! condition for installing a rule **without asking**, for example "only when the
//! repository owner approved it".
//!
//! A local policy never changes whether a rule passed. It can only hold a passed rule
//! back for the owner's confirmation on this machine.

use serde::{Deserialize, Serialize};

/// Why a local policy document was refused. `Display` never quotes the input.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, thiserror::Error)]
pub enum PolicyError {
    /// A required member handle is not a valid member name.
    #[error("local policy names an invalid member")]
    InvalidMember,
    /// `min_approvals` is zero or larger than a roll can be.
    #[error("local policy min_approvals is out of range")]
    MinApprovalsOutOfRange,
}

/// A node's own conditions for following a passed rule without asking (from local
/// config).
///
/// Two nodes with different local policies can install the same passed rule at
/// different moments; that is intended. Whether the rule passed is the same for both.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalPolicy {
    /// Members that must each be among the approvers.
    pub required_members: Vec<String>,
    /// A minimum number of approving members, on top of whatever the charter needed.
    pub min_approvals: Option<u32>,
}

impl LocalPolicy {
    /// Whether this policy adds no condition.
    pub fn is_empty(&self) -> bool {
        self.required_members.is_empty() && self.min_approvals.is_none()
    }

    /// Checks the member handles and the approval count.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !self
            .required_members
            .iter()
            .all(|m| ph_protocol::is_valid_member_name(m))
        {
            return Err(PolicyError::InvalidMember);
        }
        match self.min_approvals {
            Some(n) if n == 0 || n as usize > ph_protocol::limits::MAX_ROLL_MEMBERS => {
                Err(PolicyError::MinApprovalsOutOfRange)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_validation() {
        let p = LocalPolicy::default();
        assert!(p.is_empty());
        p.validate().unwrap();

        let p = LocalPolicy {
            required_members: vec!["alice".into()],
            min_approvals: Some(3),
        };
        assert!(!p.is_empty());
        p.validate().unwrap();

        let bad = LocalPolicy {
            required_members: vec!["Alice".into()],
            min_approvals: None,
        };
        assert_eq!(bad.validate(), Err(PolicyError::InvalidMember));
        for n in [0u32, 65] {
            let bad = LocalPolicy {
                required_members: Vec::new(),
                min_approvals: Some(n),
            };
            assert_eq!(bad.validate(), Err(PolicyError::MinApprovalsOutOfRange));
        }
    }

    #[test]
    fn serde_is_strict_and_defaults() {
        let p: LocalPolicy = serde_json::from_str("{}").unwrap();
        assert!(p.is_empty());
        let p: LocalPolicy =
            serde_json::from_str(r#"{"required_members":["bob"],"min_approvals":2}"#).unwrap();
        assert_eq!(p.required_members, ["bob"]);
        assert_eq!(p.min_approvals, Some(2));
        assert!(serde_json::from_str::<LocalPolicy>(r#"{"block_on_reject":true}"#).is_err());
    }
}
