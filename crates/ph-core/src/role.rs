//! [`Role`] and [`Capability`] (architecture section 3).
//!
//! | role | capabilities |
//! |---|---|
//! | `member` | `read`, `ask`, `answer`, `propose`, `vote`, `publish` |
//! | `owner` | all of the above plus `invite` and `revoke` |
//!
//! Unknown role or capability strings are rejected at parse time, so an unknown role can
//! never grant anything.

use std::fmt;
use std::str::FromStr;

use crate::encoding::string_serde;
use crate::error::ParseError;

/// A circle role carried in a membership credential.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Role {
    /// Full control, including `invite` and `revoke`.
    Owner,
    /// Ordinary member.
    Member,
}

/// An action a credential may authorize.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Capability {
    /// Send QUESTION events.
    Ask,
    /// Send ANSWER events.
    Answer,
    /// Send PROPOSAL events.
    Propose,
    /// Send VOTE events.
    Vote,
    /// Send RELEASE events.
    Publish,
    /// Invite new members (issue credentials).
    Invite,
    /// Revoke members.
    Revoke,
    /// Read circle events and bundles within the credential's scopes.
    Read,
}

const MEMBER_CAPS: &[Capability] = &[
    Capability::Read,
    Capability::Ask,
    Capability::Answer,
    Capability::Propose,
    Capability::Vote,
    Capability::Publish,
];

const OWNER_CAPS: &[Capability] = &[
    Capability::Read,
    Capability::Ask,
    Capability::Answer,
    Capability::Propose,
    Capability::Vote,
    Capability::Publish,
    Capability::Invite,
    Capability::Revoke,
];

impl Role {
    /// All roles.
    pub const ALL: [Role; 2] = [Role::Owner, Role::Member];

    /// The wire / storage string (`"owner"` or `"member"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }

    /// The capabilities this role grants.
    pub const fn capabilities(self) -> &'static [Capability] {
        match self {
            Role::Owner => OWNER_CAPS,
            Role::Member => MEMBER_CAPS,
        }
    }

    /// Whether this role grants `cap`.
    pub fn grants(self, cap: Capability) -> bool {
        self.capabilities().contains(&cap)
    }
}

/// Whether any of `roles` grants `cap`. An empty slice grants nothing.
pub fn roles_grant(roles: &[Role], cap: Capability) -> bool {
    roles.iter().any(|r| r.grants(cap))
}

impl Capability {
    /// All capabilities.
    pub const ALL: [Capability; 8] = [
        Capability::Ask,
        Capability::Answer,
        Capability::Propose,
        Capability::Vote,
        Capability::Publish,
        Capability::Invite,
        Capability::Revoke,
        Capability::Read,
    ];

    /// The lowercase string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Ask => "ask",
            Capability::Answer => "answer",
            Capability::Propose => "propose",
            Capability::Vote => "vote",
            Capability::Publish => "publish",
            Capability::Invite => "invite",
            Capability::Revoke => "revoke",
            Capability::Read => "read",
        }
    }
}

impl FromStr for Role {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "owner" => Ok(Role::Owner),
            "member" => Ok(Role::Member),
            _ => Err(ParseError::new("role", "unknown role")),
        }
    }
}

impl FromStr for Capability {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        Capability::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or(ParseError::new("capability", "unknown capability"))
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

string_serde!(Role, "a role (owner or member)");
string_serde!(Capability, "a capability string");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        use Capability::*;
        for c in [Read, Ask, Answer, Propose, Vote, Publish] {
            assert!(Role::Member.grants(c));
            assert!(Role::Owner.grants(c));
        }
        for c in [Invite, Revoke] {
            assert!(!Role::Member.grants(c));
            assert!(Role::Owner.grants(c));
        }
        assert!(!roles_grant(&[], Read));
        assert!(roles_grant(&[Role::Member, Role::Owner], Revoke));
        assert_eq!(Role::Owner.capabilities().len(), Capability::ALL.len());
    }

    #[test]
    fn parse() {
        assert_eq!("owner".parse::<Role>().unwrap(), Role::Owner);
        assert_eq!("member".parse::<Role>().unwrap(), Role::Member);
        for bad in ["admin", "Owner", "MEMBER", "", " member", "*"] {
            assert!(bad.parse::<Role>().is_err());
        }
        for c in Capability::ALL {
            assert_eq!(c.as_str().parse::<Capability>().unwrap(), c);
        }
        assert!("write".parse::<Capability>().is_err());
        assert_eq!(
            serde_json::from_str::<Vec<Role>>("[\"member\",\"owner\"]").unwrap(),
            vec![Role::Member, Role::Owner]
        );
        assert!(serde_json::from_str::<Vec<Role>>("[\"superuser\"]").is_err());
    }
}
