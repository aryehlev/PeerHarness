//! Self-describing string encodings (architecture section 3).
//!
//! | type | encoding |
//! |---|---|
//! | [`DeviceKey`] | `ed25519:` + base64url (no padding) of 32 bytes |
//! | [`Signature`] | `base64url:` + base64url (no padding) of 64 bytes |
//! | [`Nonce`] | `base64url:` + base64url (no padding) of 16 bytes |
//! | [`Digest`], [`EventId`], [`CircleId`] | `sha256:` + 64 lowercase hex chars |
//!
//! Parsing is strict: the prefix is case-sensitive, base64 must be canonical (no padding,
//! no non-zero trailing bits) and hex must be lowercase. Every type serializes with serde
//! as its prefixed string.
//!
//! [`EventId`] and [`CircleId`] are *distinct* newtypes around a [`Digest`] so the type
//! system keeps event ids, circle ids and content digests apart. All three share the
//! same string format; convert with [`EventId::from_digest`] / [`EventId::digest`] etc.

use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::TryRng as _;
use sha2::{Digest as _, Sha256};

use crate::error::{ParseError, RandomnessError};

/// Domain-separation context for [`CircleId::derive`].
pub const CIRCLE_ID_CONTEXT: &str = "peerharness-circle-v0";
/// Domain-separation context for [`fingerprint`].
pub const FINGERPRINT_CONTEXT: &str = "peerharness-fingerprint-v0";

const KEY_PREFIX: &str = "ed25519:";
const B64_PREFIX: &str = "base64url:";
const DIGEST_PREFIX: &str = "sha256:";

/// Implements `Serialize`/`Deserialize` through `Display`/`FromStr`.
macro_rules! string_serde {
    ($ty:ty, $expecting:literal) => {
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl serde::de::Visitor<'_> for V {
                    type Value = $ty;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$ty, E> {
                        v.parse().map_err(E::custom)
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}
pub(crate) use string_serde;

/// Decodes canonical unpadded base64url into exactly `N` bytes.
fn decode_b64<const N: usize>(what: &'static str, s: &str) -> Result<[u8; N], ParseError> {
    // Upper bound on encoded length avoids decoding huge inputs.
    let expected_len = (N * 4).div_ceil(3);
    if s.len() != expected_len {
        return Err(ParseError::new(what, "wrong encoded length"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ParseError::new(what, "not canonical base64url"))?;
    let arr: [u8; N] = bytes
        .try_into()
        .map_err(|_| ParseError::new(what, "wrong byte length"))?;
    // Re-encoding must reproduce the input exactly (canonical form).
    if URL_SAFE_NO_PAD.encode(arr) != s {
        return Err(ParseError::new(what, "not canonical base64url"));
    }
    Ok(arr)
}

/// SHA-256 of `context || 0x00 || data`.
pub fn domain_hash(context: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(context.as_bytes());
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

// ---------------------------------------------------------------------------------------
// DeviceKey
// ---------------------------------------------------------------------------------------

/// An Ed25519 public key (a device key or a circle root key), encoded as
/// `ed25519:` + base64url-nopad of the 32-byte compressed point.
///
/// Parsing rejects bytes that are not a valid curve point, non-canonical point encodings
/// (a `y` coordinate `>= p`, which would give one point two different key strings) and
/// small-order ("weak") keys, so every `DeviceKey` can be turned into an
/// [`ed25519_dalek::VerifyingKey`] and every point has exactly one `DeviceKey`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceKey([u8; 32]);

impl DeviceKey {
    /// Builds a key from raw bytes, validating that they are the canonical encoding of a
    /// usable (not small-order) Ed25519 point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ParseError> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| ParseError::new("device key", "not a valid ed25519 point"))?;
        if vk.to_edwards().compress().to_bytes() != bytes {
            return Err(ParseError::new(
                "device key",
                "non-canonical point encoding",
            ));
        }
        if vk.is_weak() {
            return Err(ParseError::new("device key", "weak (small-order) key"));
        }
        Ok(Self(bytes))
    }

    /// The device key of an Ed25519 verifying key.
    ///
    /// The key is not re-checked for weakness; keys produced by
    /// [`ed25519_dalek::SigningKey::verifying_key`] are never weak.
    pub fn from_verifying_key(vk: &ed25519_dalek::VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }

    /// The public key of a signing key.
    pub fn from_signing_key(sk: &ed25519_dalek::SigningKey) -> Self {
        Self::from_verifying_key(&sk.verifying_key())
    }

    /// The raw 32 public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts into a verifying key. This cannot fail for a validated `DeviceKey`, but
    /// returns a `Result` rather than panicking.
    pub fn to_verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, ParseError> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| ParseError::new("device key", "not a valid ed25519 point"))
    }

    /// The human-readable fingerprint of this key (see [`fingerprint`]).
    pub fn fingerprint(&self) -> String {
        fingerprint(self)
    }
}

impl fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({self})")
    }
}

impl FromStr for DeviceKey {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let rest = s
            .strip_prefix(KEY_PREFIX)
            .ok_or(ParseError::new("device key", "missing ed25519: prefix"))?;
        Self::from_bytes(decode_b64::<32>("device key", rest)?)
    }
}

string_serde!(DeviceKey, "an ed25519: public key string");

/// Human fingerprint of a public key: the first 20 hex chars of
/// `SHA-256("peerharness-fingerprint-v0\0" || pubkey)`, grouped as
/// `xxxx-xxxx-xxxx-xxxx-xxxx`.
pub fn fingerprint(key: &DeviceKey) -> String {
    let hex = hex::encode(domain_hash(FINGERPRINT_CONTEXT, key.as_bytes()));
    let mut out = String::with_capacity(24);
    for (i, c) in hex.chars().take(20).enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------------------

/// A 64-byte Ed25519 signature, encoded as `base64url:` + base64url-nopad.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wraps raw signature bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw 64 signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Converts from an `ed25519_dalek` signature.
    pub fn from_dalek(sig: &ed25519_dalek::Signature) -> Self {
        Self(sig.to_bytes())
    }

    /// Converts into an `ed25519_dalek` signature.
    pub fn to_dalek(&self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{B64_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl FromStr for Signature {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let rest = s
            .strip_prefix(B64_PREFIX)
            .ok_or(ParseError::new("signature", "missing base64url: prefix"))?;
        Ok(Self(decode_b64::<64>("signature", rest)?))
    }
}

string_serde!(Signature, "a base64url: signature string");

// ---------------------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------------------

/// A 128-bit random nonce, encoded as `base64url:` + base64url-nopad of 16 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nonce([u8; 16]);

impl Nonce {
    /// Wraps raw nonce bytes (use for fixed test vectors).
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Draws a fresh nonce from the operating system RNG.
    pub fn random() -> Result<Self, RandomnessError> {
        let mut b = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut b)
            .map_err(|_| RandomnessError)?;
        Ok(Self(b))
    }

    /// The raw 16 nonce bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{B64_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({self})")
    }
}

impl FromStr for Nonce {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let rest = s
            .strip_prefix(B64_PREFIX)
            .ok_or(ParseError::new("nonce", "missing base64url: prefix"))?;
        Ok(Self(decode_b64::<16>("nonce", rest)?))
    }
}

string_serde!(Nonce, "a base64url: nonce string");

// ---------------------------------------------------------------------------------------
// Digest, EventId, CircleId
// ---------------------------------------------------------------------------------------

/// A SHA-256 digest, encoded as `sha256:` + 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Wraps raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Plain SHA-256 of `data` (no domain separation). Used for bundle file hashes.
    pub fn sha256(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    /// Domain-separated SHA-256: `SHA-256(context || 0x00 || data)`.
    pub fn domain(context: &str, data: &[u8]) -> Self {
        Self(domain_hash(context, data))
    }

    /// The raw 32 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 64 lowercase hex characters without the `sha256:` prefix (used for example
    /// as a content-addressed directory name).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn parse_named(what: &'static str, s: &str) -> Result<Self, ParseError> {
        let rest = s
            .strip_prefix(DIGEST_PREFIX)
            .ok_or(ParseError::new(what, "missing sha256: prefix"))?;
        if rest.len() != 64 {
            return Err(ParseError::new(what, "expected 64 hex characters"));
        }
        if !rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ParseError::new(what, "expected lowercase hex"));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(rest, &mut out)
            .map_err(|_| ParseError::new(what, "expected lowercase hex"))?;
        Ok(Self(out))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{DIGEST_PREFIX}{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl FromStr for Digest {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        Self::parse_named("digest", s)
    }
}

string_serde!(Digest, "a sha256: digest string");

macro_rules! digest_newtype {
    ($(#[$m:meta])* $name:ident, $what:literal, $expecting:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Digest);

        impl $name {
            /// Wraps a digest.
            pub const fn from_digest(d: Digest) -> Self {
                Self(d)
            }

            /// The underlying digest.
            pub const fn digest(&self) -> Digest {
                self.0
            }

            /// The raw 32 bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// Lowercase hex without the `sha256:` prefix.
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl From<Digest> for $name {
            fn from(d: Digest) -> Self {
                Self(d)
            }
        }

        impl From<$name> for Digest {
            fn from(v: $name) -> Digest {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = ParseError;
            fn from_str(s: &str) -> Result<Self, ParseError> {
                Digest::parse_named($what, s).map(Self)
            }
        }

        string_serde!($name, $expecting);
    };
}

digest_newtype!(
    /// Identifier of a signed event envelope: the envelope's object digest
    /// (`sha256:` + hex of `SHA-256("peerharness-event-v0\0" || JCS(unsigned))`).
    EventId,
    "event id",
    "a sha256: event id string"
);

digest_newtype!(
    /// Identifier of a trust circle, derived from its root public key with
    /// [`CircleId::derive`].
    CircleId,
    "circle id",
    "a sha256: circle id string"
);

impl CircleId {
    /// `"sha256:" + hex(SHA-256("peerharness-circle-v0\0" || root_pubkey_32_bytes))`.
    pub fn derive(root_key: &DeviceKey) -> Self {
        Self(Digest::domain(CIRCLE_ID_CONTEXT, root_key.as_bytes()))
    }

    /// Whether this circle id is the one derived from `root_key`.
    pub fn is_derived_from(&self, root_key: &DeviceKey) -> bool {
        *self == Self::derive(root_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> DeviceKey {
        DeviceKey::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    #[test]
    fn device_key_roundtrip() {
        let k = key(1);
        let s = k.to_string();
        assert!(s.starts_with("ed25519:"));
        assert_eq!(s.len(), 8 + 43);
        assert_eq!(s.parse::<DeviceKey>().unwrap(), k);
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, format!("\"{s}\""));
        assert_eq!(serde_json::from_str::<DeviceKey>(&json).unwrap(), k);
    }

    #[test]
    fn device_key_rejects_bad_input() {
        let s = key(1).to_string();
        let body = &s[8..];
        for bad in [
            String::new(),
            body.to_string(),
            format!("ED25519:{body}"),
            format!("ed25519:{body}="),
            format!("ed25519:{body}A"),
            format!("ed25519:{}", &body[1..]),
            format!("ed25519:+{}", &body[1..]),
            format!(" ed25519:{body}"),
        ] {
            assert!(bad.parse::<DeviceKey>().is_err(), "accepted {bad:?}");
        }
        // Small-order point (identity) is rejected.
        let mut id = [0u8; 32];
        id[0] = 1;
        assert!(DeviceKey::from_bytes(id).is_err());
        // Every small-order point in its canonical encoding is rejected.
        for b in WEAK_POINTS {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&b).expect("valid point");
            assert!(vk.is_weak(), "vector is not small-order");
            assert!(DeviceKey::from_bytes(b).is_err());
        }
    }

    /// The eight small-order points of edwards25519 (canonical encodings).
    const WEAK_POINTS: [[u8; 32]; 8] = {
        let mut out = [[0u8; 32]; 8];
        // identity (0, 1)
        out[0][0] = 1;
        // (0, -1): y = p - 1
        out[1] = [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        // (+-sqrt(-1), 0): y = 0, both signs
        out[3][31] = 0x80;
        // order-8 points
        out[4] = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ];
        out[5] = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x85,
        ];
        out[6] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];
        out[7] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0xfa,
        ];
        out
    };

    #[test]
    fn device_key_rejects_non_canonical_encoding() {
        // y' + p for small y' (the encoding of y = y' with an unreduced coordinate). Some of
        // these decode to valid, non-weak points; all must be rejected, because the
        // canonical encoding of the same point is a different string.
        let mut decodable_non_weak = 0;
        for yp in 0u8..=18 {
            for high in [0x7fu8, 0xff] {
                let mut b = [0xffu8; 32];
                b[0] = 0xed + yp;
                b[31] = high;
                if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&b) {
                    if !vk.is_weak() {
                        decodable_non_weak += 1;
                    }
                }
                assert!(DeviceKey::from_bytes(b).is_err(), "y'={yp} high={high:#x}");
            }
        }
        assert!(decodable_non_weak > 0, "test vector set lost its teeth");
        // Canonical keys still round-trip.
        let k = key(7);
        assert_eq!(DeviceKey::from_bytes(*k.as_bytes()).unwrap(), k);
    }

    #[test]
    fn base64_noncanonical_trailing_bits_rejected() {
        // 16 bytes -> 22 chars; last char carries 2 unused bits.
        let n = Nonce::from_bytes([0u8; 16]).to_string();
        assert!(n.ends_with('A'));
        let tweaked = format!("{}B", &n[..n.len() - 1]);
        assert!(tweaked.parse::<Nonce>().is_err());
    }

    #[test]
    fn signature_and_nonce_roundtrip() {
        let sig = Signature::from_bytes([7u8; 64]);
        assert_eq!(sig.to_string().parse::<Signature>().unwrap(), sig);
        let n = Nonce::random().unwrap();
        assert_eq!(n.to_string().parse::<Nonce>().unwrap(), n);
        assert_ne!(Nonce::random().unwrap(), n);
        assert!("base64url:AAAA".parse::<Nonce>().is_err());
        assert!("base64url:AAAA".parse::<Signature>().is_err());
    }

    #[test]
    fn digest_parse_strict() {
        let d = Digest::sha256(b"test");
        let s = d.to_string();
        assert_eq!(
            s,
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(s.parse::<Digest>().unwrap(), d);
        assert!(s.to_uppercase().parse::<Digest>().is_err());
        assert!(s.replace("sha256:", "SHA256:").parse::<Digest>().is_err());
        assert!(s[..s.len() - 1].parse::<Digest>().is_err());
        assert!(format!("{s}0").parse::<Digest>().is_err());
        let eid: EventId = s.parse().unwrap();
        assert_eq!(eid.digest(), d);
        let cid: CircleId = serde_json::from_str(&format!("\"{s}\"")).unwrap();
        assert_eq!(Digest::from(cid), d);
    }

    #[test]
    fn circle_derivation_and_fingerprint() {
        let k = key(2);
        let c = CircleId::derive(&k);
        let mut pre = b"peerharness-circle-v0\0".to_vec();
        pre.extend_from_slice(k.as_bytes());
        assert_eq!(c.digest(), Digest::sha256(&pre));
        assert!(c.is_derived_from(&k));
        assert!(!c.is_derived_from(&key(3)));

        let fp = k.fingerprint();
        assert_eq!(fp.len(), 24);
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|p| p.len() == 4));
        let mut pre = b"peerharness-fingerprint-v0\0".to_vec();
        pre.extend_from_slice(k.as_bytes());
        assert_eq!(fp.replace('-', ""), Digest::sha256(&pre).to_hex()[..20]);
    }

    #[test]
    fn errors_do_not_echo_input() {
        let secret = "ed25519:SECRETSECRETSECRETSECRETSECRETSECRETSECRE";
        let e = secret.parse::<DeviceKey>().unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
        let e = serde_json::from_str::<Digest>("\"sha256:SECRET\"").unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }
}
