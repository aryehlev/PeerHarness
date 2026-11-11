//! Content-addressed, instruction-only skill bundles (architecture section 11).
//!
//! A v0 bundle is exactly one file, `SKILL.md` (at most 256 KiB, UTF-8, no NUL). Its
//! manifest is `{"schema":"peerharness.bundle/0.1","files":[{"path":"SKILL.md",
//! "sha256":…,"size":N}]}` and its digest is
//! `sha256(JCS-domain("peerharness-bundle-v0", manifest))`, computed by
//! [`ph_protocol::bundle_digest`]. The digest covers the path, size and content hash.
//!
//! A [`Bundle`] value can only be obtained through [`build_bundle`],
//! [`validate_received`] or [`from_wire_files`] (and [`crate::BundleStore::get`]), so a
//! `Bundle` always holds content that parses, validates and matches its digest.

use ph_core::Digest;
use ph_protocol::limits::{MAX_BUNDLE_FILES, MAX_BUNDLE_PATH_BYTES};
use ph_protocol::wire::WireFile;
use ph_protocol::{bundle_digest, manifest_for_files, BundleManifest};

use crate::error::{BundleError, PathRejection, ValidationError};
use crate::frontmatter::{parse_skill_md, SkillDoc};
use crate::scanner::{scan, RiskFinding};
use crate::validate::{check_skill_bytes, validate_skill, MAX_SKILL_FILE_BYTES};

/// The only file name a v0 bundle may contain.
pub const SKILL_FILE_NAME: &str = "SKILL.md";

/// A validated, content-addressed skill bundle.
///
/// Fields are private so the invariants hold: `skill_md` parses to `doc`, `doc`
/// validates (with `name` as the directory name), and `digest` is the bundle digest of
/// `manifest`, which describes exactly `skill_md`.
///
/// `Debug` prints the digest, name length and size only.
#[derive(Clone, PartialEq, Eq)]
pub struct Bundle {
    manifest: BundleManifest,
    digest: Digest,
    skill_md: String,
    doc: SkillDoc,
}

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bundle")
            .field("digest", &self.digest.to_string())
            .field("name_len", &self.doc.frontmatter.name.len())
            .field("size", &self.skill_md.len())
            .finish()
    }
}

impl Bundle {
    /// The manifest.
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }
    /// The bundle digest (`sha256:…`), the value carried in PROPOSAL/VOTE/RELEASE bodies.
    pub fn digest(&self) -> Digest {
        self.digest
    }
    /// The exact SKILL.md text (byte-for-byte what is hashed).
    pub fn skill_md(&self) -> &str {
        &self.skill_md
    }
    /// The SKILL.md bytes.
    pub fn skill_md_bytes(&self) -> &[u8] {
        self.skill_md.as_bytes()
    }
    /// The parsed document.
    pub fn doc(&self) -> &SkillDoc {
        &self.doc
    }
    /// The skill name (validated Agent Skills name, safe as a directory name).
    pub fn name(&self) -> &str {
        &self.doc.frontmatter.name
    }
    /// The description.
    pub fn description(&self) -> &str {
        &self.doc.frontmatter.description
    }
    /// Total size in bytes (the PROPOSAL `bundle_size`).
    pub fn size(&self) -> u64 {
        self.manifest.total_size()
    }
    /// Runs the advisory risk scanner over the SKILL.md text.
    pub fn scan(&self) -> Vec<RiskFinding> {
        scan(&self.skill_md)
    }
    /// The wire representation (see [`to_wire_files`]).
    pub fn to_wire_files(&self) -> Vec<WireFile> {
        to_wire_files(self)
    }
}

/// Computes the bundle digest of a single-`SKILL.md` bundle with this content, without
/// validating it.
pub fn digest_for_skill_md(content: &[u8]) -> Result<Digest, BundleError> {
    let manifest = manifest_for_files(&[(SKILL_FILE_NAME, content)]);
    bundle_digest(&manifest).map_err(BundleError::Protocol)
}

/// Builds a bundle from local SKILL.md text: checks size and NUL, parses, validates
/// (with `expected_name` as the directory name, when given), enforces
/// [`check_instruction_only`], and computes the manifest and digest. The bytes are
/// hashed exactly as given (no normalization).
pub fn build_bundle(skill_md: &str, expected_name: Option<&str>) -> Result<Bundle, BundleError> {
    let text = check_skill_bytes(skill_md.as_bytes()).map_err(file_error)?;
    let doc = parse_and_validate(text, expected_name)?;
    let manifest = manifest_for_files(&[(SKILL_FILE_NAME, text.as_bytes())]);
    let digest = bundle_digest(&manifest).map_err(BundleError::Protocol)?;
    Ok(Bundle {
        manifest,
        digest,
        skill_md: text.to_owned(),
        doc,
    })
}

fn parse_and_validate(text: &str, expected_name: Option<&str>) -> Result<SkillDoc, BundleError> {
    let doc = parse_skill_md(text)?;
    validate_skill(&doc, expected_name).map_err(BundleError::Invalid)?;
    check_instruction_only(&doc)?;
    // The body is clean. The same syntax in the frontmatter, or begun there and closed
    // in the body, is refused too: the file is what an agent's loader reads, and it
    // need not find the end of the frontmatter where this crate does.
    if has_shell_injection(text) {
        return Err(BundleError::ShellInjectionInFrontmatter);
    }
    Ok(doc)
}

/// Enforces "a bundle is instructions only" (architecture section 10.10: no vote runs
/// code). Applied to every bundle, whether built locally or received from a peer.
///
/// A single `SKILL.md` can still make an agent run things in two ways, and both are
/// refused outright rather than left to the advisory risk scanner:
///
/// * `allowed-tools` in the frontmatter pre-approves tools, so the agent uses them
///   without asking its user;
/// * Claude Code's dynamic-context syntax in the body runs a shell command when the
///   skill loads, before the model sees anything. See [`shell_injection_line`] for the
///   exact forms.
///
/// This looks at the parsed document. A bundle is also refused for the same syntax
/// anywhere else in its file, the frontmatter included ([`build_bundle`],
/// [`validate_received`]): a loader that splits the file differently from this crate
/// would read as body what this crate read as a value.
pub fn check_instruction_only(doc: &SkillDoc) -> Result<(), BundleError> {
    if doc.frontmatter.allowed_tools.is_some() {
        return Err(BundleError::ToolPreapproval);
    }
    match shell_injection_line(&doc.body) {
        Some(line) => Err(BundleError::ShellInjection { line }),
        None => Ok(()),
    }
}

/// Whether `text` contains syntax that Claude Code executes as a shell command when a
/// skill loads ([`shell_injection_line`]).
pub fn has_shell_injection(text: &str) -> bool {
    shell_injection_line(text).is_some()
}

/// The 1-based line of `text` on which syntax begins that Claude Code executes as a
/// shell command when a skill loads, or `None`.
///
/// Claude Code finds two forms, anywhere in the text and not only at the start of a
/// line, and both may span lines:
///
/// * block: three backticks directly followed by an exclamation mark, up to the next
///   three backticks;
/// * inline: an exclamation mark directly followed by a backtick, a command, and a
///   closing backtick.
///
/// This refuses a superset of both, so that it cannot fall behind the loader by a
/// detail:
///
/// * three backticks or three tildes directly followed by an exclamation mark,
///   anywhere: in the middle of a line, after a list or quote marker, or as the end of
///   a longer run of backticks;
/// * an exclamation mark directly followed by a backtick, with another backtick
///   anywhere after it in the text, on that line or a later one.
///
/// It errs on the side of refusing. "Use `!` and `x`" is refused although a human
/// reads two code spans, and so is a `!` that closes a code span when any backtick
/// follows further down. A lone `!` in a code span with no backtick after it is fine.
pub fn shell_injection_line(text: &str) -> Option<usize> {
    let fence = ["```!", "~~~!"].iter().filter_map(|m| text.find(m)).min();
    let inline = text.match_indices("!`").find_map(|(i, m)| {
        text.get(i + m.len()..)
            .is_some_and(|rest| rest.contains('`'))
            .then_some(i)
    });
    let at = match (fence, inline) {
        (Some(a), Some(b)) => a.min(b),
        (a, b) => a.or(b)?,
    };
    Some(
        text.get(..at)
            .map_or(0, |before| before.matches('\n').count())
            + 1,
    )
}

fn file_error(e: ValidationError) -> BundleError {
    match e {
        ValidationError::TooLarge { size, max } => BundleError::TooLarge { size, max },
        ValidationError::ContainsNul => BundleError::Nul,
        ValidationError::InvalidUtf8 => BundleError::InvalidUtf8,
        other => BundleError::Invalid(vec![other]),
    }
}

/// Checks one bundle path. Only the exact bytes `SKILL.md` are accepted; the rejection
/// reason is a best-effort classification for the error message.
pub fn check_bundle_path(path: &str) -> Result<(), PathRejection> {
    if path == SKILL_FILE_NAME {
        return Ok(());
    }
    if path.is_empty() {
        return Err(PathRejection::Empty);
    }
    if path.len() > MAX_BUNDLE_PATH_BYTES {
        return Err(PathRejection::TooLong);
    }
    if path.chars().any(char::is_control) {
        return Err(PathRejection::ControlCharacter);
    }
    let b = path.as_bytes();
    if path.starts_with('/')
        || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        || path.starts_with("\\\\")
    {
        return Err(PathRejection::Absolute);
    }
    if path.contains('\\') {
        return Err(PathRejection::Backslash);
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.contains(&"..") {
        return Err(PathRejection::Traversal);
    }
    if segments.iter().any(|s| s.is_empty() || *s == ".") {
        return Err(PathRejection::NotNormalized);
    }
    if segments.iter().any(|s| s.starts_with('.')) {
        return Err(PathRejection::Hidden);
    }
    if segments.len() > 1 {
        return Err(PathRejection::Nested);
    }
    if !path.is_ascii() {
        return Err(PathRejection::NonAscii);
    }
    if path.eq_ignore_ascii_case(SKILL_FILE_NAME) {
        return Err(PathRejection::CaseMismatch);
    }
    Err(PathRejection::UnexpectedFile)
}

/// Validates a bundle received from a peer (or read from disk) and returns it.
///
/// Rejects, in order: an empty file list; more than
/// [`ph_protocol::limits::MAX_BUNDLE_FILES`] files; any path that is not exactly
/// `SKILL.md` ([`check_bundle_path`]: `./SKILL.md`, `../x`, `/abs`, `C:\x`, backslashes,
/// case variants, fullwidth/homoglyph/NFD lookalikes, hidden or nested files, any other
/// name); duplicates; content over [`MAX_SKILL_FILE_BYTES`]; a digest that differs from
/// `expected_digest`; NUL bytes; invalid UTF-8; then SKILL.md that does not parse or
/// validate (with `expected_name` as directory name when given).
pub fn validate_received(
    files: Vec<(String, Vec<u8>)>,
    expected_digest: &Digest,
    expected_name: Option<&str>,
) -> Result<Bundle, BundleError> {
    if files.is_empty() {
        return Err(BundleError::Empty);
    }
    if files.len() > MAX_BUNDLE_FILES {
        return Err(BundleError::TooManyFiles { count: files.len() });
    }
    for (index, (path, _)) in files.iter().enumerate() {
        check_bundle_path(path).map_err(|reason| BundleError::Path { index, reason })?;
    }
    if files.len() > 1 {
        return Err(BundleError::Duplicate);
    }
    let total: usize = files
        .iter()
        .map(|(_, c)| c.len())
        .fold(0, usize::saturating_add);
    if total > MAX_SKILL_FILE_BYTES {
        return Err(BundleError::TooLarge {
            size: total,
            max: MAX_SKILL_FILE_BYTES,
        });
    }
    let Some((_, content)) = files.into_iter().next() else {
        return Err(BundleError::Empty);
    };

    let manifest = manifest_for_files(&[(SKILL_FILE_NAME, content.as_slice())]);
    let digest = bundle_digest(&manifest).map_err(BundleError::Protocol)?;
    if digest != *expected_digest {
        return Err(BundleError::DigestMismatch);
    }
    if content.contains(&0) {
        return Err(BundleError::Nul);
    }
    let text = String::from_utf8(content).map_err(|_| BundleError::InvalidUtf8)?;
    let doc = parse_and_validate(&text, expected_name)?;
    Ok(Bundle {
        manifest,
        digest,
        skill_md: text,
        doc,
    })
}

/// Encodes a bundle for a `Response::Bundle { digest, files }` wire message.
pub fn to_wire_files(bundle: &Bundle) -> Vec<WireFile> {
    vec![WireFile::new(SKILL_FILE_NAME, bundle.skill_md.as_bytes())]
}

/// Decodes and validates the files of a `Response::Bundle` (see [`validate_received`]).
/// Sizes are bounded before any base64 decoding.
pub fn from_wire_files(
    files: &[WireFile],
    expected_digest: &Digest,
    expected_name: Option<&str>,
) -> Result<Bundle, BundleError> {
    if files.is_empty() {
        return Err(BundleError::Empty);
    }
    if files.len() > MAX_BUNDLE_FILES {
        return Err(BundleError::TooManyFiles { count: files.len() });
    }
    let mut total = 0usize;
    for (index, f) in files.iter().enumerate() {
        check_bundle_path(&f.path).map_err(|reason| BundleError::Path { index, reason })?;
        total = total.saturating_add(f.decoded_len());
    }
    if total > MAX_SKILL_FILE_BYTES {
        return Err(BundleError::TooLarge {
            size: total,
            max: MAX_SKILL_FILE_BYTES,
        });
    }
    let mut decoded = Vec::with_capacity(files.len());
    for f in files {
        let bytes = f.decode().map_err(|_| BundleError::Encoding)?;
        decoded.push((f.path.clone(), bytes));
    }
    validate_received(decoded, expected_digest, expected_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "---\nname: demo\ndescription: d\n---\n\nbody\n";

    #[test]
    fn build_and_receive() {
        let b = build_bundle(OK, Some("demo")).unwrap();
        assert_eq!(b.name(), "demo");
        assert_eq!(b.size(), OK.len() as u64);
        assert_eq!(b.digest(), digest_for_skill_md(OK.as_bytes()).unwrap());
        let r = validate_received(
            vec![("SKILL.md".into(), OK.as_bytes().to_vec())],
            &b.digest(),
            Some("demo"),
        )
        .unwrap();
        assert_eq!(r, b);
        let w = from_wire_files(&b.to_wire_files(), &b.digest(), None).unwrap();
        assert_eq!(w, b);
        assert!(!format!("{b:?}").contains("body"));
    }

    #[test]
    fn paths() {
        use PathRejection::*;
        let cases: &[(&str, PathRejection)] = &[
            ("", Empty),
            ("./SKILL.md", NotNormalized),
            ("../x", Traversal),
            ("a/../SKILL.md", Traversal),
            ("/abs", Absolute),
            ("/SKILL.md", Absolute),
            ("C:\\x", Absolute),
            ("C:SKILL.md", Absolute),
            ("\\\\server\\share", Absolute),
            ("dir\\SKILL.md", Backslash),
            ("skill.md", CaseMismatch),
            ("Skill.md", CaseMismatch),
            ("SKILL.MD", CaseMismatch),
            ("\u{ff33}KILL.md", NonAscii),
            ("\u{0405}KILL.md", NonAscii),
            ("SKILL.md\u{0301}", NonAscii),
            ("SKI\u{200b}LL.md", NonAscii),
            ("SKILL.md\0", ControlCharacter),
            ("SKILL.md\n", ControlCharacter),
            (".hidden", Hidden),
            (".SKILL.md", Hidden),
            ("scripts/run.sh", Nested),
            ("SKILL.md/", NotNormalized),
            ("a//b", NotNormalized),
            ("README.md", UnexpectedFile),
            ("SKILL.md ", UnexpectedFile),
        ];
        for (p, want) in cases {
            assert_eq!(check_bundle_path(p), Err(*want), "{p:?}");
        }
        assert_eq!(check_bundle_path(&"a".repeat(300)), Err(TooLong));
        assert_eq!(check_bundle_path("SKILL.md"), Ok(()));
    }
}
