//! Skill bundle manifests and digests (architecture section 11).
//!
//! ```json
//! {"schema":"peerharness.bundle/0.1","files":[{"path":"SKILL.md","sha256":"sha256:…","size":N}]}
//! ```
//!
//! `bundle_digest = "sha256:" + hex(SHA-256("peerharness-bundle-v0\0" || JCS(manifest)))`,
//! so the digest covers paths, sizes and content hashes. `sha256` of a file is the plain
//! SHA-256 of its bytes (no domain separation).
//!
//! Path policy (exactly `SKILL.md`, no traversal, ...) is enforced by `ph-skills`; this
//! module only computes.

use ph_core::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtocolError;
use crate::jcs;
use crate::signing::domain_separated;

/// Manifest `schema` value.
pub const BUNDLE_SCHEMA: &str = "peerharness.bundle/0.1";
/// Domain-separation context of [`bundle_digest`].
pub const BUNDLE_CONTEXT: &str = "peerharness-bundle-v0";

/// One file entry of a manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    /// Relative path inside the bundle.
    pub path: String,
    /// Plain SHA-256 of the content.
    pub sha256: Digest,
    /// Content size in bytes.
    pub size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRepr {
    schema: String,
    files: Vec<BundleFile>,
}

/// A bundle manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ManifestRepr", into = "ManifestRepr")]
pub struct BundleManifest {
    /// File entries, in manifest order.
    pub files: Vec<BundleFile>,
}

impl From<BundleManifest> for ManifestRepr {
    fn from(m: BundleManifest) -> Self {
        ManifestRepr {
            schema: BUNDLE_SCHEMA.to_owned(),
            files: m.files,
        }
    }
}

impl TryFrom<ManifestRepr> for BundleManifest {
    type Error = ProtocolError;
    fn try_from(r: ManifestRepr) -> Result<Self, ProtocolError> {
        if r.schema != BUNDLE_SCHEMA {
            return Err(ProtocolError::UnsupportedSchema {
                object: "bundle manifest",
            });
        }
        Ok(BundleManifest { files: r.files })
    }
}

impl BundleManifest {
    /// The manifest JSON value.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        jcs::to_value(self)
    }

    /// `JCS(manifest)`.
    pub fn to_canonical_json(&self) -> Result<String, ProtocolError> {
        jcs::to_canonical_string(self)
    }

    /// `"peerharness-bundle-v0\0" || JCS(manifest)`, the input hashed by
    /// [`bundle_digest`].
    pub fn digest_input(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok(domain_separated(
            BUNDLE_CONTEXT,
            self.to_canonical_json()?.as_bytes(),
        ))
    }

    /// The bundle digest.
    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        bundle_digest(self)
    }

    /// Sum of file sizes (saturating).
    pub fn total_size(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.size))
    }
}

/// Builds the manifest for `(path, content)` pairs. Entries are sorted by path (byte
/// order) so the manifest does not depend on input order.
pub fn manifest_for_files(files: &[(&str, &[u8])]) -> BundleManifest {
    let mut entries: Vec<BundleFile> = files
        .iter()
        .map(|(path, bytes)| BundleFile {
            path: (*path).to_owned(),
            sha256: Digest::sha256(bytes),
            size: bytes.len() as u64,
        })
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    BundleManifest { files: entries }
}

/// `"sha256:" + hex(SHA-256("peerharness-bundle-v0\0" || JCS(manifest)))`.
pub fn bundle_digest(manifest: &BundleManifest) -> Result<Digest, ProtocolError> {
    Ok(Digest::sha256(&manifest.digest_input()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_and_digest() {
        let content = b"---\nname: x\ndescription: y\n---\nbody\n";
        let m = manifest_for_files(&[("SKILL.md", content)]);
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].size, content.len() as u64);
        let canon = m.to_canonical_json().unwrap();
        assert_eq!(
            canon,
            format!(
                "{{\"files\":[{{\"path\":\"SKILL.md\",\"sha256\":\"{}\",\"size\":{}}}],\"schema\":\"peerharness.bundle/0.1\"}}",
                Digest::sha256(content),
                content.len()
            )
        );
        let mut input = b"peerharness-bundle-v0\0".to_vec();
        input.extend_from_slice(canon.as_bytes());
        assert_eq!(bundle_digest(&m).unwrap(), Digest::sha256(&input));

        // any change changes the digest
        let m2 = manifest_for_files(&[("SKILL.md", b"other")]);
        assert_ne!(m.digest().unwrap(), m2.digest().unwrap());
        let m3 = manifest_for_files(&[("skill.md", content)]);
        assert_ne!(m.digest().unwrap(), m3.digest().unwrap());

        // order independent
        let a = manifest_for_files(&[("a", b"1"), ("b", b"2")]);
        let b = manifest_for_files(&[("b", b"2"), ("a", b"1")]);
        assert_eq!(a, b);
        assert_eq!(a.total_size(), 2);

        let back: BundleManifest = serde_json::from_str(&canon).unwrap();
        assert_eq!(back, m);
        assert!(
            serde_json::from_str::<BundleManifest>(&canon.replace("bundle/0.1", "bundle/0.2"))
                .is_err()
        );
    }
}
