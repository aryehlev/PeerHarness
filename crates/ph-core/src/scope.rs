//! [`Scope`]: hierarchical authorization scopes (architecture section 3).
//!
//! A scope is either exactly `*` or matches
//! `^[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63}){0,7}$` and is at most 128
//! bytes. That is: 1 to 8 `/`-separated segments, each 1-64 characters, starting with a
//! lowercase letter or digit, continuing with lowercase letters, digits, `.`, `_` or `-`.
//!
//! A granted scope `g` [covers](Scope::covers) an object scope `o` iff `g == "*"`, or
//! `g == o`, or `o` starts with `g + "/"`. There is no other wildcard syntax: a `*`
//! inside a path is not valid, and the object scope `*` is covered only by the granted
//! scope `*`.

use std::fmt;
use std::str::FromStr;

use crate::encoding::string_serde;
use crate::error::ParseError;

/// Maximum length of a scope in bytes.
pub const MAX_SCOPE_BYTES: usize = 128;
/// Maximum number of `/`-separated segments.
pub const MAX_SCOPE_SEGMENTS: usize = 8;
/// Maximum length of a single segment in bytes.
pub const MAX_SEGMENT_BYTES: usize = 64;

const WHAT: &str = "scope";

/// A validated scope string. See the [module docs](self).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope(String);

impl Scope {
    /// The wildcard scope `*`, which covers every scope.
    pub fn all() -> Self {
        Self("*".to_owned())
    }

    /// Validates and wraps a scope string.
    pub fn new(s: &str) -> Result<Self, ParseError> {
        validate(s)?;
        Ok(Self(s.to_owned()))
    }

    /// The scope as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the wildcard scope `*`.
    pub fn is_wildcard(&self) -> bool {
        self.0 == "*"
    }

    /// Whether this *granted* scope covers the *object* scope `object`.
    ///
    /// `"team/back"` does **not** cover `"team/backend"`; it covers `"team/back"` and
    /// `"team/back/..."` only.
    pub fn covers(&self, object: &Scope) -> bool {
        covers(self.as_str(), object.as_str())
    }

    /// Whether any of the `granted` scopes covers `object`.
    pub fn any_covers(granted: &[Scope], object: &Scope) -> bool {
        granted.iter().any(|g| g.covers(object))
    }
}

/// String-level `covers` relation, see [`Scope::covers`]. Both arguments are assumed to
/// be valid scopes; for invalid input the result is still well defined (pure string
/// comparison) but meaningless.
pub fn covers(granted: &str, object: &str) -> bool {
    if granted == "*" || granted == object {
        return true;
    }
    match object.strip_prefix(granted) {
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

fn validate(s: &str) -> Result<(), ParseError> {
    if s == "*" {
        return Ok(());
    }
    if s.is_empty() {
        return Err(ParseError::new(WHAT, "empty"));
    }
    if s.len() > MAX_SCOPE_BYTES {
        return Err(ParseError::new(WHAT, "longer than 128 bytes"));
    }
    let mut segments = 0usize;
    for seg in s.split('/') {
        segments += 1;
        if segments > MAX_SCOPE_SEGMENTS {
            return Err(ParseError::new(WHAT, "more than 8 segments"));
        }
        let bytes = seg.as_bytes();
        let Some((&first, rest)) = bytes.split_first() else {
            return Err(ParseError::new(WHAT, "empty segment"));
        };
        if bytes.len() > MAX_SEGMENT_BYTES {
            return Err(ParseError::new(WHAT, "segment longer than 64 bytes"));
        }
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(ParseError::new(
                WHAT,
                "segment must start with a lowercase letter or digit",
            ));
        }
        if !rest.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-'
        }) {
            return Err(ParseError::new(WHAT, "invalid character"));
        }
    }
    Ok(())
}

impl FromStr for Scope {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        Self::new(s)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scope({})", self.0)
    }
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

string_serde!(Scope, "a scope string such as team/backend or *");

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Scope {
        Scope::new(v).unwrap()
    }

    #[test]
    fn valid_scopes() {
        for v in [
            "*",
            "a",
            "0",
            "team",
            "team/backend",
            "team/back-end_v2.0",
            "a/b/c/d/e/f/g/h",
            &"a".repeat(64),
            &format!("{}/{}", "a".repeat(63), "b".repeat(64)),
        ] {
            assert!(Scope::new(v).is_ok(), "rejected {v:?}");
        }
    }

    #[test]
    fn invalid_scopes() {
        let long = format!("{}/{}/{}", "a".repeat(64), "b".repeat(64), "c");
        assert!(long.len() > 128);
        for v in [
            "",
            "**",
            "team/*",
            "*/team",
            "Team",
            "team/Backend",
            "/team",
            "team/",
            "team//backend",
            "-team",
            ".team",
            "_team",
            "team/.hidden",
            "team/..",
            "team backend",
            "team\\backend",
            "a/b/c/d/e/f/g/h/i",
            &"a".repeat(65),
            &long,
            "tëam",
            "team/backend\n",
        ] {
            assert!(Scope::new(v).is_err(), "accepted {v:?}");
        }
    }

    #[test]
    fn covers_table() {
        let cases: &[(&str, &str, bool)] = &[
            ("*", "*", true),
            ("*", "team", true),
            ("*", "team/backend/x", true),
            ("team", "*", false),
            ("team", "team", true),
            ("team", "team/backend", true),
            ("team", "team/backend/api", true),
            ("team/backend", "team", false),
            ("team/backend", "team/backend", true),
            ("team/backend", "team/backend/api", true),
            ("team/backend", "team/frontend", false),
            // prefix confusion
            ("team/back", "team/backend", false),
            ("team/back", "team/back-end", false),
            ("team/back", "team/back.end", false),
            ("team/back", "team/back_end", false),
            ("team/back", "team/back/end", true),
            ("team", "teams", false),
            ("team", "team-a/x", false),
            ("team", "teamx/team", false),
            ("a", "ab", false),
            ("a/b", "a/bc/d", false),
            ("team/finance", "team/frontend", false),
            ("team/frontend", "team/finance", false),
            ("x/team", "team", false),
        ];
        for (g, o, want) in cases {
            assert_eq!(s(g).covers(&s(o)), *want, "{g} covers {o}");
        }
    }

    #[test]
    fn any_covers() {
        let granted = [s("team/frontend"), s("ops")];
        assert!(Scope::any_covers(&granted, &s("ops/oncall")));
        assert!(!Scope::any_covers(&granted, &s("team/finance")));
        assert!(!Scope::any_covers(&[], &s("team")));
    }

    fn segment() -> impl proptest::strategy::Strategy<Value = String> {
        // small alphabet so prefixes and collisions are frequent
        proptest::string::string_regex("[ab][ab.-]{0,3}").unwrap()
    }

    proptest::proptest! {
        /// `covers` is exactly "segment-wise prefix", never a string prefix.
        #[test]
        fn covers_is_segment_prefix(
            g in proptest::collection::vec(segment(), 1..4),
            o in proptest::collection::vec(segment(), 1..4),
        ) {
            let gs = Scope::new(&g.join("/")).unwrap();
            let os = Scope::new(&o.join("/")).unwrap();
            let want = g.len() <= o.len() && g[..] == o[..g.len()];
            proptest::prop_assert_eq!(gs.covers(&os), want);
            proptest::prop_assert!(Scope::all().covers(&os));
            proptest::prop_assert!(!gs.covers(&Scope::all()));
        }

        #[test]
        fn new_never_panics(v in "\\PC{0,140}") {
            let _ = Scope::new(&v);
        }
    }

    #[test]
    fn serde() {
        let v: Scope = serde_json::from_str("\"team/backend\"").unwrap();
        assert_eq!(v.as_str(), "team/backend");
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"team/backend\"");
        assert!(serde_json::from_str::<Scope>("\"team/*\"").is_err());
    }
}
