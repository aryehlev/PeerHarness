//! The circle charter (architecture section 10): the rules of the vote, the roll of
//! members, and the rules carried over from the previous charter, in one signed object.
//!
//! * [`Threshold`] and [`CharterRules`]: what fraction of an electorate must approve.
//! * [`RollEntry`]: one member (a person) with their device keys and scopes.
//! * [`CharterContent`]: the votable part of a charter, `{rules, roll, carried}`. An
//!   `amend` proposal carries exactly this as its `next`.
//! * [`UnsignedCharter`] / [`Charter`]: the content plus its place in the chain
//!   (`seq`, `previous`, `justification`), signed by the circle root key.
//!
//! Deserializing checks only the schema. [`verify_charter_signature`] checks structure
//! and signature. Whether a charter is a legitimate *successor* of another is a stateful
//! question answered by `ph-governance`.
//!
//! A charter carries no free text, so its derived `Debug` output is safe to log.

use std::collections::HashSet;
use std::ops::Deref;

use ed25519_dalek::SigningKey;
use ph_core::{CircleId, DeviceKey, Digest, EventId, Scope, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::credentials::{parse_document, some};
use crate::error::ProtocolError;
use crate::jcs::{self, ParseLimits};
use crate::limits::{
    MAX_CARRIED_RULES, MAX_DEPTH, MAX_EVENT_BYTES, MAX_MEMBER_DEVICES, MAX_MEMBER_NAME_BYTES,
    MAX_MEMBER_SCOPES, MAX_ROLL_MEMBERS, MAX_THRESHOLD_DEN,
};
use crate::signing::{self, Context};

const OBJECT: &str = "charter";

const CHARTER_LIMITS: ParseLimits = ParseLimits {
    max_bytes: MAX_EVENT_BYTES,
    max_depth: MAX_DEPTH,
};

// =======================================================================================
// Threshold and rules
// =======================================================================================

/// A voting threshold: a proposal needs approvals from **more than** `num/den` of its
/// electorate.
///
/// Valid thresholds satisfy `1 <= num < den <= 100` and `2*num >= den`, so nothing can
/// pass without a strict majority.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    /// Numerator.
    pub num: u32,
    /// Denominator.
    pub den: u32,
}

impl Threshold {
    /// More than one half: a simple majority of the electorate.
    pub const MAJORITY: Threshold = Threshold { num: 1, den: 2 };
    /// More than two thirds of the electorate.
    pub const TWO_THIRDS: Threshold = Threshold { num: 2, den: 3 };

    /// Checks `1 <= num < den <= 100` and `2*num >= den`.
    pub fn check(&self, field: &'static str) -> Result<(), ProtocolError> {
        let ok = self.num >= 1
            && self.num < self.den
            && self.den <= MAX_THRESHOLD_DEN
            && 2 * self.num >= self.den;
        if ok {
            Ok(())
        } else {
            Err(ProtocolError::field(field, "invalid threshold"))
        }
    }

    /// The number of approving members needed from an electorate of `n` members:
    /// `floor(n * num / den) + 1`. An empty electorate needs one approval, which it can
    /// never produce, so nothing passes.
    pub fn need(&self, n: usize) -> usize {
        // n <= 64 and num < den <= 100 for every valid charter, so this cannot overflow;
        // saturating arithmetic keeps arbitrary inputs well defined anyway.
        let den = (self.den.max(1)) as usize;
        n.saturating_mul(self.num as usize) / den + 1
    }

    /// Whether this threshold is at least as demanding as `other`
    /// (`self.num/self.den >= other.num/other.den`).
    pub fn at_least(&self, other: &Threshold) -> bool {
        u64::from(self.num) * u64::from(other.den) >= u64::from(other.num) * u64::from(self.den)
    }
}

/// The rules of the vote.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterRules {
    /// Threshold for `adopt` and `repeal` proposals, and for `amend` proposals that
    /// leave the rules unchanged.
    pub pass: Threshold,
    /// Threshold for `amend` proposals that change the rules. At least `pass`.
    pub amend: Threshold,
    /// Whether a passed rule is installed for every member by default (section 10.9).
    pub binding: bool,
}

impl Default for CharterRules {
    /// Simple majority to pass, two thirds to change the rules, binding.
    fn default() -> Self {
        Self {
            pass: Threshold::MAJORITY,
            amend: Threshold::TWO_THIRDS,
            binding: true,
        }
    }
}

impl CharterRules {
    /// Checks both thresholds and `amend >= pass`.
    pub fn check(&self) -> Result<(), ProtocolError> {
        self.pass.check("rules.pass")?;
        self.amend.check("rules.amend")?;
        if !self.amend.at_least(&self.pass) {
            return Err(ProtocolError::field(
                "rules.amend",
                "must be at least rules.pass",
            ));
        }
        Ok(())
    }
}

// =======================================================================================
// Roll
// =======================================================================================

/// One member of a circle: a person, the device keys that may sign for them, and the
/// scopes they vote in.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollEntry {
    /// The member's handle within the circle: `^[a-z0-9][a-z0-9._-]{0,31}$`.
    pub member: String,
    /// Device keys (1-4, unique, sorted by their string encoding).
    pub devices: Vec<DeviceKey>,
    /// Scopes the member votes in (1-16, unique, sorted). `*` covers everything.
    pub scopes: Vec<Scope>,
}

impl RollEntry {
    /// Builds an entry, sorting `devices` and `scopes` into canonical order. Duplicates
    /// are kept so that [`CharterContent::check_structure`] can refuse them.
    pub fn new(member: &str, mut devices: Vec<DeviceKey>, mut scopes: Vec<Scope>) -> Self {
        devices.sort_by_key(DeviceKey::to_string);
        scopes.sort();
        Self {
            member: member.to_owned(),
            devices,
            scopes,
        }
    }

    /// Whether `device` is one of this member's devices.
    pub fn has_device(&self, device: &DeviceKey) -> bool {
        self.devices.contains(device)
    }

    /// Whether one of this member's scopes covers `scope`.
    pub fn covers(&self, scope: &Scope) -> bool {
        Scope::any_covers(&self.scopes, scope)
    }
}

/// Whether `s` is a valid member handle: `^[a-z0-9][a-z0-9._-]{0,31}$`.
pub fn is_valid_member_name(s: &str) -> bool {
    let b = s.as_bytes();
    let Some(first) = b.first() else {
        return false;
    };
    b.len() <= MAX_MEMBER_NAME_BYTES
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// Whether `items` is strictly increasing under `less` (so sorted and free of duplicates).
fn strictly_sorted<T>(items: &[T], less: impl Fn(&T, &T) -> bool) -> bool {
    items.windows(2).all(|w| match w {
        [a, b] => less(a, b),
        _ => true,
    })
}

// =======================================================================================
// Content
// =======================================================================================

/// The votable part of a charter. An `amend` proposal carries the complete proposed
/// content; when it passes, the next charter's content equals it exactly.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterContent {
    /// The rules of the vote.
    pub rules: CharterRules,
    /// The members (1-64, unique, sorted by `member`).
    pub roll: Vec<RollEntry>,
    /// The `adopt` proposals in force when this charter begins (at most 256, unique,
    /// sorted).
    pub carried: Vec<EventId>,
}

/// Which members form the electorate of a proposal (section 10.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Electorate<'a> {
    /// Every member on the roll: `amend` proposals.
    WholeRoll,
    /// The members concerned by `scope`: every member when it is `*`, otherwise the
    /// members with a scope that covers it. `adopt` and `repeal` proposals.
    Scope(&'a Scope),
}

impl CharterContent {
    /// The founding content: default rules, `founder` as the only member, nothing carried.
    pub fn founding(founder: RollEntry) -> Self {
        Self {
            rules: CharterRules::default(),
            roll: vec![founder],
            carried: Vec::new(),
        }
    }

    /// Puts `roll` and `carried` into canonical order (entries by member, carried by
    /// id). Does not remove duplicates; [`Self::check_structure`] refuses those.
    pub fn normalize(&mut self) {
        self.roll.sort_by(|a, b| a.member.cmp(&b.member));
        self.carried.sort_by_key(EventId::to_string);
    }

    /// Checks every structure rule of section 10.2 that concerns the content.
    pub fn check_structure(&self) -> Result<(), ProtocolError> {
        self.rules.check()?;
        if self.roll.is_empty() || self.roll.len() > MAX_ROLL_MEMBERS {
            return Err(ProtocolError::field("roll", "must have 1-64 members"));
        }
        if !strictly_sorted(&self.roll, |a, b| a.member < b.member) {
            return Err(ProtocolError::field(
                "roll",
                "members must be unique and sorted",
            ));
        }
        let mut seen_devices = HashSet::new();
        for entry in &self.roll {
            if !is_valid_member_name(&entry.member) {
                return Err(ProtocolError::field("roll", "invalid member name"));
            }
            if entry.devices.is_empty() || entry.devices.len() > MAX_MEMBER_DEVICES {
                return Err(ProtocolError::field(
                    "roll",
                    "a member must have 1-4 devices",
                ));
            }
            if !strictly_sorted(&entry.devices, |a, b| a.to_string() < b.to_string()) {
                return Err(ProtocolError::field(
                    "roll",
                    "devices must be unique and sorted",
                ));
            }
            if entry.scopes.is_empty() || entry.scopes.len() > MAX_MEMBER_SCOPES {
                return Err(ProtocolError::field(
                    "roll",
                    "a member must have 1-16 scopes",
                ));
            }
            if !strictly_sorted(&entry.scopes, |a, b| a.as_str() < b.as_str()) {
                return Err(ProtocolError::field(
                    "roll",
                    "scopes must be unique and sorted",
                ));
            }
            for device in &entry.devices {
                if !seen_devices.insert(*device) {
                    return Err(ProtocolError::field(
                        "roll",
                        "a device may belong to only one member",
                    ));
                }
            }
        }
        if self.carried.len() > MAX_CARRIED_RULES {
            return Err(ProtocolError::field("carried", "too many carried rules"));
        }
        if !strictly_sorted(&self.carried, |a, b| a.to_string() < b.to_string()) {
            return Err(ProtocolError::field(
                "carried",
                "entries must be unique and sorted",
            ));
        }
        Ok(())
    }

    /// The member that `device` signs for, if it is on the roll.
    pub fn member_of(&self, device: &DeviceKey) -> Option<&RollEntry> {
        self.roll.iter().find(|e| e.has_device(device))
    }

    /// The entry for the member named `member`.
    pub fn member(&self, member: &str) -> Option<&RollEntry> {
        self.roll.iter().find(|e| e.member == member)
    }

    /// Whether `entry` belongs to `electorate`.
    pub fn in_electorate(entry: &RollEntry, electorate: &Electorate<'_>) -> bool {
        match electorate {
            Electorate::WholeRoll => true,
            Electorate::Scope(scope) => scope.is_wildcard() || entry.covers(scope),
        }
    }

    /// The members of `electorate`, in roll order.
    pub fn electorate<'a>(
        &'a self,
        electorate: &'a Electorate<'a>,
    ) -> impl Iterator<Item = &'a RollEntry> + 'a {
        self.roll
            .iter()
            .filter(move |e| Self::in_electorate(e, electorate))
    }

    /// The member `device` signs for, if that member belongs to `electorate`.
    pub fn voter(&self, device: &DeviceKey, electorate: &Electorate<'_>) -> Option<&RollEntry> {
        self.member_of(device)
            .filter(|e| Self::in_electorate(e, electorate))
    }
}

// =======================================================================================
// Charter
// =======================================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CharterRepr {
    schema: String,
    circle_id: CircleId,
    seq: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    previous: Option<Digest>,
    rules: CharterRules,
    roll: Vec<RollEntry>,
    carried: Vec<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    justification: Option<EventId>,
    issued_at: Timestamp,
    issuer_key: DeviceKey,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some"
    )]
    signature: Option<Signature>,
}

/// The unsigned members of a [`Charter`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "CharterRepr", into = "CharterRepr")]
pub struct UnsignedCharter {
    /// Circle; must equal `CircleId::derive(issuer_key)`.
    pub circle_id: CircleId,
    /// Position in the chain, starting at 1.
    pub seq: u64,
    /// Digest of the charter with `seq - 1`. Absent exactly when `seq == 1`.
    pub previous: Option<Digest>,
    /// Rules, roll and carried rules (flattened into the JSON object).
    pub content: CharterContent,
    /// A `RESULT` event that passed the `amend` proposal this charter enacts. Absent
    /// exactly when `seq == 1`.
    pub justification: Option<EventId>,
    /// When the root key signed it (informational).
    pub issued_at: Timestamp,
    /// The circle root key.
    pub issuer_key: DeviceKey,
}

/// A charter signed by the circle root key.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "CharterRepr", into = "CharterRepr")]
pub struct Charter {
    /// The signed members.
    pub unsigned: UnsignedCharter,
    /// Signature by `issuer_key`.
    pub signature: Signature,
}

impl Deref for Charter {
    type Target = UnsignedCharter;
    fn deref(&self) -> &UnsignedCharter {
        &self.unsigned
    }
}

impl From<UnsignedCharter> for CharterRepr {
    fn from(u: UnsignedCharter) -> Self {
        CharterRepr {
            schema: Context::Charter.schema().to_owned(),
            circle_id: u.circle_id,
            seq: u.seq,
            previous: u.previous,
            rules: u.content.rules,
            roll: u.content.roll,
            carried: u.content.carried,
            justification: u.justification,
            issued_at: u.issued_at,
            issuer_key: u.issuer_key,
            signature: None,
        }
    }
}

impl From<Charter> for CharterRepr {
    fn from(c: Charter) -> Self {
        let mut repr = CharterRepr::from(c.unsigned);
        repr.signature = Some(c.signature);
        repr
    }
}

impl CharterRepr {
    fn split(self) -> Result<(UnsignedCharter, Option<Signature>), ProtocolError> {
        if self.schema != Context::Charter.schema() {
            return Err(ProtocolError::UnsupportedSchema { object: OBJECT });
        }
        Ok((
            UnsignedCharter {
                circle_id: self.circle_id,
                seq: self.seq,
                previous: self.previous,
                content: CharterContent {
                    rules: self.rules,
                    roll: self.roll,
                    carried: self.carried,
                },
                justification: self.justification,
                issued_at: self.issued_at,
                issuer_key: self.issuer_key,
            },
            self.signature,
        ))
    }
}

impl TryFrom<CharterRepr> for UnsignedCharter {
    type Error = ProtocolError;
    fn try_from(r: CharterRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (u, None) => Ok(u),
            _ => Err(ProtocolError::Schema { object: OBJECT }),
        }
    }
}

impl TryFrom<CharterRepr> for Charter {
    type Error = ProtocolError;
    fn try_from(r: CharterRepr) -> Result<Self, ProtocolError> {
        match r.split()? {
            (unsigned, Some(signature)) => Ok(Self {
                unsigned,
                signature,
            }),
            _ => Err(ProtocolError::Schema { object: OBJECT }),
        }
    }
}

impl UnsignedCharter {
    /// The founding charter of the circle rooted at `root_key`: `seq` 1, no
    /// predecessor, `content` as given (normally [`CharterContent::founding`]).
    pub fn founding(root_key: DeviceKey, content: CharterContent, issued_at: Timestamp) -> Self {
        Self {
            circle_id: CircleId::derive(&root_key),
            seq: 1,
            previous: None,
            content,
            justification: None,
            issued_at,
            issuer_key: root_key,
        }
    }

    /// The charter that follows `current`, enacting `content` on the strength of the
    /// `RESULT` event `justification`.
    pub fn successor(
        current: &Charter,
        content: CharterContent,
        justification: EventId,
        issued_at: Timestamp,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            circle_id: current.circle_id,
            seq: current.seq + 1,
            previous: Some(current.digest()?),
            content,
            justification: Some(justification),
            issued_at,
            issuer_key: current.issuer_key,
        })
    }

    /// The unsigned JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// `"peerharness-charter-v0\0" || JCS(unsigned)`.
    pub fn signing_input(&self) -> Result<Vec<u8>, ProtocolError> {
        signing::signing_input(Context::Charter, &self.to_value()?)
    }

    /// The charter digest: the object digest of the signing input. Proposals name the
    /// charter they are voted under by this value.
    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        Ok(signing::digest_of_input(&self.signing_input()?))
    }

    /// Checks the content ([`CharterContent::check_structure`]), the circle/issuer
    /// binding, and that `previous` and `justification` are absent exactly when
    /// `seq == 1`.
    pub fn check_structure(&self) -> Result<(), ProtocolError> {
        self.content.check_structure()?;
        if !self.circle_id.is_derived_from(&self.issuer_key) {
            return Err(ProtocolError::Mismatch {
                what: "charter circle_id and issuer_key",
            });
        }
        if self.seq == 0 || self.seq > jcs::MAX_SAFE_INTEGER {
            return Err(ProtocolError::field("seq", "out of range"));
        }
        let founding = self.seq == 1;
        if founding != self.previous.is_none() || founding != self.justification.is_none() {
            return Err(ProtocolError::field(
                "seq",
                "previous and justification are absent exactly when seq is 1",
            ));
        }
        Ok(())
    }

    /// Signs with the circle root key, which must match `issuer_key`.
    pub fn sign(self, root_key: &SigningKey) -> Result<Charter, ProtocolError> {
        if DeviceKey::from_signing_key(root_key) != self.issuer_key {
            return Err(ProtocolError::Mismatch {
                what: "signing key and issuer_key",
            });
        }
        self.check_structure()?;
        let signature = signing::sign_input(root_key, &self.signing_input()?);
        Ok(Charter {
            unsigned: self,
            signature,
        })
    }
}

impl Charter {
    /// Strictly parses a standalone charter JSON document (schema only).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        parse_document(bytes, CHARTER_LIMITS, Context::Charter)
    }

    /// The signed JSON object.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// The canonical (JCS) JSON text of the signed object.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        jcs::to_canonical_string(self)
    }
}

/// Checks a charter's structure and its signature by the circle root key. There are no
/// time rules: a charter is a permanent record and outcomes never depend on a clock.
pub fn verify_charter_signature(charter: &Charter) -> Result<(), ProtocolError> {
    charter.check_structure()?;
    signing::verify_input(
        Context::Charter,
        &charter.issuer_key,
        &charter.signing_input()?,
        &charter.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&sk(seed))
    }

    fn t0() -> Timestamp {
        "2026-11-09T18:00:00Z".parse().unwrap()
    }

    fn entry(member: &str, seeds: &[u8], scopes: &[&str]) -> RollEntry {
        RollEntry::new(
            member,
            seeds.iter().map(|s| pk(*s)).collect(),
            scopes.iter().map(|s| Scope::new(s).unwrap()).collect(),
        )
    }

    fn content() -> CharterContent {
        let mut c = CharterContent {
            rules: CharterRules::default(),
            roll: vec![
                entry("carol", &[13], &["team/frontend"]),
                entry("alice", &[11, 21], &["*"]),
                entry("bob", &[12], &["team/backend", "docs"]),
            ],
            carried: Vec::new(),
        };
        c.normalize();
        c
    }

    fn founding() -> Charter {
        UnsignedCharter::founding(pk(1), content(), t0())
            .sign(&sk(1))
            .unwrap()
    }

    #[test]
    fn need_matches_the_documented_table() {
        let half = Threshold::MAJORITY;
        let two_thirds = Threshold::TWO_THIRDS;
        let ns = [1usize, 2, 3, 4, 5, 6, 7, 10];
        assert_eq!(
            ns.map(|n| half.need(n)),
            [1, 2, 2, 3, 3, 4, 4, 6],
            "more than one half"
        );
        assert_eq!(
            ns.map(|n| two_thirds.need(n)),
            [1, 2, 3, 3, 4, 5, 5, 7],
            "more than two thirds"
        );
        // An empty electorate needs one approval and so can never pass anything.
        assert_eq!(half.need(0), 1);
        // need never exceeds the electorate (for n >= 1) and always exceeds half of it.
        for den in 2..=100u32 {
            for num in den.div_ceil(2)..den {
                let t = Threshold { num, den };
                t.check("t").unwrap();
                for n in 1..=64usize {
                    let need = t.need(n);
                    assert!(need <= n, "{num}/{den} n={n}");
                    assert!(2 * need > n, "{num}/{den} n={n}");
                }
            }
        }
    }

    #[test]
    fn threshold_bounds() {
        for (num, den) in [(0, 2), (1, 3), (2, 2), (3, 2), (1, 0), (51, 101), (49, 100)] {
            assert!(
                Threshold { num, den }.check("t").is_err(),
                "{num}/{den} must be refused"
            );
        }
        for (num, den) in [(1, 2), (2, 3), (3, 4), (99, 100), (50, 100)] {
            Threshold { num, den }.check("t").unwrap();
        }
        assert!(Threshold::TWO_THIRDS.at_least(&Threshold::MAJORITY));
        assert!(Threshold::MAJORITY.at_least(&Threshold { num: 50, den: 100 }));
        assert!(!Threshold::MAJORITY.at_least(&Threshold::TWO_THIRDS));
        // amend below pass is refused
        let rules = CharterRules {
            pass: Threshold::TWO_THIRDS,
            amend: Threshold::MAJORITY,
            binding: true,
        };
        assert!(rules.check().is_err());
    }

    #[test]
    fn member_names() {
        for ok in ["alice", "a", "0x", "a.b_c-d", &"a".repeat(32)] {
            assert!(is_valid_member_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Alice",
            "-a",
            ".a",
            "a b",
            "a/b",
            "al\u{e9}",
            &"a".repeat(33),
        ] {
            assert!(!is_valid_member_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn sign_verify_and_roundtrip() {
        let c = founding();
        verify_charter_signature(&c).unwrap();
        assert_eq!(c.seq, 1);
        assert_eq!(c.circle_id, CircleId::derive(&pk(1)));
        let json = c.to_canonical_json().unwrap();
        let back = Charter::from_json_bytes(json.as_bytes()).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.digest().unwrap(), c.digest().unwrap());
        // rules, roll and carried are top-level members of the JSON object
        let v = c.to_value().unwrap();
        for k in [
            "schema",
            "circle_id",
            "seq",
            "rules",
            "roll",
            "carried",
            "issued_at",
            "issuer_key",
            "signature",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert!(v.get("previous").is_none() && v.get("justification").is_none());
        assert_eq!(v["schema"], "peerharness.charter/0.1");
        // the wrong key cannot sign
        assert!(UnsignedCharter::founding(pk(1), content(), t0())
            .sign(&sk(2))
            .is_err());
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let c = founding();
        let mut m = c.clone();
        m.unsigned.content.rules.pass = Threshold { num: 3, den: 4 };
        m.unsigned.content.rules.amend = Threshold { num: 3, den: 4 };
        assert!(verify_charter_signature(&m).is_err());
        let mut m = c.clone();
        m.unsigned.content.roll.pop();
        assert!(verify_charter_signature(&m).is_err());
        let mut m = c;
        m.unsigned.issued_at = t0().plus_secs(1);
        assert!(verify_charter_signature(&m).is_err());
    }

    #[test]
    fn successor_links_to_its_predecessor() {
        let c1 = founding();
        let justification = EventId::from_digest(Digest::sha256(b"result"));
        let mut next = content();
        next.roll.push(entry("dave", &[14], &["*"]));
        next.normalize();
        let c2 = UnsignedCharter::successor(&c1, next, justification, t0().plus_secs(60))
            .unwrap()
            .sign(&sk(1))
            .unwrap();
        verify_charter_signature(&c2).unwrap();
        assert_eq!(c2.seq, 2);
        assert_eq!(c2.previous, Some(c1.digest().unwrap()));
        assert_eq!(c2.justification, Some(justification));
        assert_ne!(c2.digest().unwrap(), c1.digest().unwrap());
    }

    #[test]
    fn seq_and_chain_fields_must_agree() {
        let base = UnsignedCharter::founding(pk(1), content(), t0());
        let d = Digest::sha256(b"x");
        let mut u = base.clone();
        u.previous = Some(d);
        assert!(u.check_structure().is_err(), "seq 1 with previous");
        let mut u = base.clone();
        u.justification = Some(EventId::from_digest(d));
        assert!(u.check_structure().is_err(), "seq 1 with justification");
        let mut u = base.clone();
        u.seq = 2;
        assert!(u.check_structure().is_err(), "seq 2 without chain fields");
        let mut u = base.clone();
        u.seq = 2;
        u.previous = Some(d);
        assert!(u.check_structure().is_err(), "seq 2 without justification");
        let mut u = base.clone();
        u.seq = 0;
        assert!(u.check_structure().is_err(), "seq 0");
        // a circle id that is not derived from the issuer
        let mut u = base;
        u.circle_id = CircleId::derive(&pk(9));
        assert!(u.check_structure().is_err());
    }

    #[test]
    fn roll_structure_rules() {
        let ok = content();
        ok.check_structure().unwrap();

        let mut c = ok.clone();
        c.roll.clear();
        assert!(c.check_structure().is_err(), "empty roll");

        let mut c = ok.clone();
        c.roll.swap(0, 1);
        assert!(c.check_structure().is_err(), "unsorted members");

        let mut c = ok.clone();
        c.roll.push(entry("carol", &[40], &["*"]));
        assert!(c.check_structure().is_err(), "duplicate member");

        let mut c = ok.clone();
        c.roll.push(entry("dave", &[12], &["*"])); // bob's device
        c.normalize();
        assert!(c.check_structure().is_err(), "device on two members");

        let mut c = ok.clone();
        c.roll.push(entry("dave", &[], &["*"]));
        c.normalize();
        assert!(c.check_structure().is_err(), "no devices");

        let mut c = ok.clone();
        c.roll.push(entry("dave", &[31, 32, 33, 34, 35], &["*"]));
        c.normalize();
        assert!(c.check_structure().is_err(), "too many devices");

        let mut c = ok.clone();
        c.roll.push(entry("dave", &[31], &[]));
        c.normalize();
        assert!(c.check_structure().is_err(), "no scopes");

        let mut c = ok.clone();
        c.roll.push(RollEntry {
            member: "dave".into(),
            devices: vec![pk(31), pk(31)],
            scopes: vec![Scope::all()],
        });
        c.normalize();
        assert!(c.check_structure().is_err(), "duplicate device");

        let mut c = ok.clone();
        c.roll.push(entry("Dave", &[31], &["*"]));
        c.normalize();
        assert!(c.check_structure().is_err(), "invalid member name");

        let mut c = ok.clone();
        let id = EventId::from_digest(Digest::sha256(b"r"));
        c.carried = vec![id, id];
        assert!(c.check_structure().is_err(), "duplicate carried rule");

        let mut c = ok;
        c.roll = (0..=MAX_ROLL_MEMBERS)
            .map(|i| entry(&format!("m{i:03}"), &[100 + i as u8], &["*"]))
            .collect();
        c.normalize();
        assert!(c.check_structure().is_err(), "more than 64 members");
    }

    #[test]
    fn electorates() {
        let c = content();
        let names = |e: Electorate<'_>| -> Vec<String> {
            c.electorate(&e).map(|m| m.member.clone()).collect()
        };
        let scope = |s: &str| Scope::new(s).unwrap();
        assert_eq!(names(Electorate::WholeRoll), ["alice", "bob", "carol"]);
        // `*` concerns everyone, whatever their own scopes are
        assert_eq!(
            names(Electorate::Scope(&Scope::all())),
            ["alice", "bob", "carol"]
        );
        // a narrower scope: only members with a covering scope
        assert_eq!(
            names(Electorate::Scope(&scope("team/backend"))),
            ["alice", "bob"]
        );
        assert_eq!(
            names(Electorate::Scope(&scope("team/backend/db"))),
            ["alice", "bob"]
        );
        assert_eq!(
            names(Electorate::Scope(&scope("team/frontend"))),
            ["alice", "carol"]
        );
        assert_eq!(names(Electorate::Scope(&scope("finance"))), ["alice"]);
        // one member, two devices: both map to the same member
        assert_eq!(c.member_of(&pk(11)).unwrap().member, "alice");
        assert_eq!(c.member_of(&pk(21)).unwrap().member, "alice");
        assert!(c.member_of(&pk(99)).is_none());
        // a member outside the electorate is not a voter there
        let backend = scope("team/backend");
        assert!(c.voter(&pk(13), &Electorate::Scope(&backend)).is_none());
        assert!(c.voter(&pk(12), &Electorate::Scope(&backend)).is_some());
        assert!(c.voter(&pk(13), &Electorate::WholeRoll).is_some());
    }

    #[test]
    fn strict_schema() {
        let c = founding();
        let v = c.to_value().unwrap();
        // unknown member
        let mut m = v.clone();
        m["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Charter>(m).is_err());
        // wrong schema string
        let mut m = v.clone();
        m["schema"] = serde_json::json!("peerharness.charter/0.2");
        assert!(serde_json::from_value::<Charter>(m).is_err());
        // unsigned form refuses a signature, signed form requires one
        assert!(serde_json::from_value::<UnsignedCharter>(v.clone()).is_err());
        let mut m = v;
        m.as_object_mut().unwrap().remove("signature");
        assert!(serde_json::from_value::<Charter>(m.clone()).is_err());
        serde_json::from_value::<UnsignedCharter>(m).unwrap();
    }
}
