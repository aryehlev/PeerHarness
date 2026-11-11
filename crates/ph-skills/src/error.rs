//! Error types.
//!
//! Every `Display` implementation is built from static strings, numbers and field
//! names only. No error ever echoes SKILL.md content, paths received from peers,
//! frontmatter values or other untrusted payload text.

use std::io;

/// Why a frontmatter line was rejected by the strict YAML-subset parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyntaxError {
    /// An anchor (`&name`).
    Anchor,
    /// An alias (`*name`).
    Alias,
    /// A tag (`!tag`, `!!str`).
    Tag,
    /// A flow collection (`{...}` or `[...]`) used as a value.
    FlowCollection,
    /// A block sequence (`- item`).
    Sequence,
    /// A document marker (`---` variants or `...`) inside the frontmatter, i.e. a
    /// multi-document stream.
    DocumentMarker,
    /// A `%` directive.
    Directive,
    /// A tab character (anywhere in the frontmatter; tabs are never needed).
    Tab,
    /// A control, bidi, BOM or Unicode line-separator character in the raw frontmatter.
    ControlCharacter,
    /// The same key appears twice (top level or inside `metadata`).
    DuplicateKey,
    /// A top-level key outside the Agent Skills set.
    UnknownKey,
    /// A key that is quoted, complex (`? `), contains spaces or other characters.
    InvalidKey,
    /// A line is indented where no indentation is allowed.
    UnexpectedIndentation,
    /// A key has no value (YAML null).
    EmptyValue,
    /// A plain scalar that YAML would resolve to a non-string (`true`, `null`, `1.0`,
    /// `2026-01-01`, ...). Quote it.
    NonStringScalar,
    /// A value starts with a reserved or ambiguous indicator (`%`, `@`, `` ` ``, `?`,
    /// `:`, `,`, `]`, `}`).
    ReservedIndicator,
    /// A plain scalar contains `": "` or ends with `:`.
    AmbiguousColon,
    /// A quoted scalar is not closed on the same line (multi-line quoted scalars are
    /// not supported).
    UnterminatedQuote,
    /// Characters after a closing quote or block-scalar indicator.
    TrailingContent,
    /// An unknown or invalid escape in a double-quoted scalar.
    InvalidEscape,
    /// A block scalar (`|` or `>`) for a key other than `description`.
    BlockScalarNotAllowed,
    /// A block scalar header with an indentation indicator or other unsupported form.
    InvalidBlockScalarHeader,
    /// Inconsistent indentation inside a block scalar.
    BlockIndentation,
    /// A more-indented line inside a folded (`>`) block scalar, whose folding rules
    /// this parser does not implement.
    UnsupportedFolding,
    /// `metadata` is not a one-level map of `key: value` lines indented by exactly two
    /// spaces.
    MetadataIndentation,
    /// `metadata` has a scalar value instead of a map.
    ExpectedMap,
}

impl SyntaxError {
    /// A short static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            SyntaxError::Anchor => "anchors are not allowed",
            SyntaxError::Alias => "aliases are not allowed",
            SyntaxError::Tag => "tags are not allowed",
            SyntaxError::FlowCollection => "flow collections are not allowed",
            SyntaxError::Sequence => "sequences are not allowed",
            SyntaxError::DocumentMarker => "document markers are not allowed in frontmatter",
            SyntaxError::Directive => "directives are not allowed",
            SyntaxError::Tab => "tab characters are not allowed in frontmatter",
            SyntaxError::ControlCharacter => "control or invisible character in frontmatter",
            SyntaxError::DuplicateKey => "duplicate key",
            SyntaxError::UnknownKey => "unknown key",
            SyntaxError::InvalidKey => "invalid key",
            SyntaxError::UnexpectedIndentation => "unexpected indentation",
            SyntaxError::EmptyValue => "missing value",
            SyntaxError::NonStringScalar => "value would not be a string in YAML; quote it",
            SyntaxError::ReservedIndicator => "value starts with a reserved indicator; quote it",
            SyntaxError::AmbiguousColon => "plain value contains ': ' or ends with ':'; quote it",
            SyntaxError::UnterminatedQuote => "unterminated quoted value",
            SyntaxError::TrailingContent => "unexpected characters after value",
            SyntaxError::InvalidEscape => "invalid escape sequence",
            SyntaxError::BlockScalarNotAllowed => "block scalars are only allowed for description",
            SyntaxError::InvalidBlockScalarHeader => "unsupported block scalar header",
            SyntaxError::BlockIndentation => "inconsistent block scalar indentation",
            SyntaxError::UnsupportedFolding => "more-indented lines in a folded block scalar",
            SyntaxError::MetadataIndentation => {
                "metadata entries must be 'key: value' indented by two spaces"
            }
            SyntaxError::ExpectedMap => "metadata must be a map",
        }
    }
}

impl std::fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A SKILL.md file could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SkillError {
    /// The file does not start with a line that is exactly `---`.
    #[error("SKILL.md must start with a '---' frontmatter line")]
    MissingFrontmatter,
    /// No closing `---` line was found.
    #[error("SKILL.md frontmatter is not terminated by a '---' line")]
    UnterminatedFrontmatter,
    /// The frontmatter exceeds [`crate::MAX_FRONTMATTER_BYTES`].
    #[error("SKILL.md frontmatter exceeds {max} bytes")]
    FrontmatterTooLarge {
        /// The limit.
        max: usize,
    },
    /// A frontmatter line violates the strict YAML subset.
    #[error("SKILL.md frontmatter line {line}: {kind}")]
    Syntax {
        /// 1-based line number in the whole file.
        line: usize,
        /// What is wrong.
        kind: SyntaxError,
    },
    /// A required key is missing.
    #[error("SKILL.md frontmatter is missing required key '{key}'")]
    MissingKey {
        /// `name` or `description`.
        key: &'static str,
    },
}

/// One violated validation rule. Several can be reported at once.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// `name` is not 1-64 chars of `[a-z0-9-]` without leading, trailing or
    /// consecutive hyphens.
    #[error(
        "skill name is invalid (1-64 of a-z, 0-9 and '-', no leading, trailing or double '-')"
    )]
    InvalidName,
    /// `name` differs from the directory name.
    #[error("skill name does not match its directory name")]
    NameMismatch,
    /// A field is out of its length bounds (code points).
    #[error("{field} must be {min}-{max} characters (got {actual})")]
    FieldLength {
        /// The field.
        field: &'static str,
        /// Minimum characters.
        min: usize,
        /// Maximum characters.
        max: usize,
        /// Actual characters.
        actual: usize,
    },
    /// A field is empty or whitespace only.
    #[error("{field} must not be blank")]
    Blank {
        /// The field.
        field: &'static str,
    },
    /// A field contains a control, bidi or otherwise forbidden character.
    #[error("{field} contains a forbidden control character")]
    ForbiddenCharacter {
        /// The field.
        field: &'static str,
    },
    /// A `metadata` key has invalid characters or length.
    #[error("metadata key is invalid (1-64 of A-Z, a-z, 0-9, '.', '_' and '-')")]
    InvalidMetadataKey,
    /// Too many `metadata` entries.
    #[error("metadata has {actual} entries (max {max})")]
    TooManyMetadataEntries {
        /// Limit.
        max: usize,
        /// Actual.
        actual: usize,
    },
    /// The whole file is larger than [`crate::MAX_SKILL_FILE_BYTES`].
    #[error("SKILL.md is {size} bytes (max {max})")]
    TooLarge {
        /// Actual size.
        size: usize,
        /// Limit.
        max: usize,
    },
    /// The file contains a NUL byte.
    #[error("SKILL.md contains a NUL byte")]
    ContainsNul,
    /// The file is not valid UTF-8.
    #[error("SKILL.md is not valid UTF-8")]
    InvalidUtf8,
}

/// Why a bundle file path was rejected. Only `SKILL.md`, byte for byte, is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathRejection {
    /// Empty path.
    Empty,
    /// Over [`ph_protocol::limits::MAX_BUNDLE_PATH_BYTES`].
    TooLong,
    /// Contains NUL or another control character.
    ControlCharacter,
    /// Absolute path (`/x`) or Windows drive / UNC path (`C:\x`, `C:x`).
    Absolute,
    /// Contains a backslash.
    Backslash,
    /// Contains a `..` segment.
    Traversal,
    /// Contains a `.` segment, an empty segment or a trailing slash (`./SKILL.md`, `a//b`).
    NotNormalized,
    /// A hidden file or directory (segment starting with `.`).
    Hidden,
    /// A path inside a subdirectory.
    Nested,
    /// Non-ASCII characters (Unicode lookalikes, fullwidth forms, NFC/NFD variants).
    NonAscii,
    /// A case variant of `SKILL.md`.
    CaseMismatch,
    /// Any other file name: v0 bundles contain only `SKILL.md`.
    UnexpectedFile,
}

impl PathRejection {
    /// A short static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            PathRejection::Empty => "empty path",
            PathRejection::TooLong => "path too long",
            PathRejection::ControlCharacter => "control character in path",
            PathRejection::Absolute => "absolute path",
            PathRejection::Backslash => "backslash in path",
            PathRejection::Traversal => "path traversal",
            PathRejection::NotNormalized => "non-normalized path",
            PathRejection::Hidden => "hidden file",
            PathRejection::Nested => "nested path",
            PathRejection::NonAscii => "non-ASCII path",
            PathRejection::CaseMismatch => "wrong case for SKILL.md",
            PathRejection::UnexpectedFile => "unexpected file",
        }
    }
}

impl std::fmt::Display for PathRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A bundle could not be built or a received bundle was rejected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// No files.
    #[error("bundle has no files")]
    Empty,
    /// More files than a bundle may ever have.
    #[error("bundle has {count} files (v0 bundles contain exactly one)")]
    TooManyFiles {
        /// Number of files received.
        count: usize,
    },
    /// A file path is not exactly `SKILL.md`.
    #[error("bundle file #{index} rejected: {reason}")]
    Path {
        /// 0-based index of the offending file in the received list.
        index: usize,
        /// Why.
        reason: PathRejection,
    },
    /// `SKILL.md` appears more than once.
    #[error("bundle contains SKILL.md more than once")]
    Duplicate,
    /// Total or per-file size over [`crate::MAX_SKILL_FILE_BYTES`].
    #[error("bundle is {size} bytes (max {max})")]
    TooLarge {
        /// Size.
        size: usize,
        /// Limit.
        max: usize,
    },
    /// The content contains NUL.
    #[error("bundle content contains a NUL byte")]
    Nul,
    /// The content is not UTF-8.
    #[error("bundle content is not valid UTF-8")]
    InvalidUtf8,
    /// The computed digest differs from the expected one.
    #[error("bundle digest does not match the expected digest")]
    DigestMismatch,
    /// A wire file's base64 could not be decoded.
    #[error("bundle file encoding is invalid")]
    Encoding,
    /// The skill declares `allowed-tools`, which pre-approves tool use for the agent.
    /// A bundle is instructions only (architecture section 10.10).
    #[error("bundle declares allowed-tools; a shared skill may not pre-approve tools")]
    ToolPreapproval,
    /// The body contains shell-injection syntax that Claude Code would execute when
    /// the skill loads, before the model sees it: an exclamation mark directly followed
    /// by a backtick, or a fenced block opened with three backticks and an exclamation
    /// mark. A bundle is instructions only (architecture section 10.10).
    #[error("bundle body line {line} contains shell-injection syntax; a shared skill may not run commands")]
    ShellInjection {
        /// 1-based line number in the SKILL.md body.
        line: usize,
    },
    /// The same syntax outside the body: in a frontmatter value, or begun there and
    /// closed in the body.
    #[error(
        "bundle frontmatter contains shell-injection syntax; a shared skill may not run commands"
    )]
    ShellInjectionInFrontmatter,
    /// SKILL.md failed to parse.
    #[error(transparent)]
    Parse(#[from] SkillError),
    /// SKILL.md parsed but violates validation rules.
    #[error("SKILL.md is invalid: {}", join_validation(.0))]
    Invalid(Vec<ValidationError>),
    /// Digest computation failed (canonicalization).
    #[error("bundle digest computation failed")]
    Protocol(#[source] ph_protocol::ProtocolError),
}

/// Formats a list of validation errors as `a; b; c`.
pub(crate) fn join_validation(errs: &[ValidationError]) -> String {
    errs.iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// [`crate::render_skill_md`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenderError {
    /// The inputs violate validation rules.
    #[error("cannot render SKILL.md: {}", join_validation(.0))]
    Invalid(Vec<ValidationError>),
    /// The body is empty or whitespace only.
    #[error("cannot render SKILL.md: body must not be blank")]
    BlankBody,
    /// Internal consistency check failed: the rendered text did not re-parse.
    #[error("rendered SKILL.md failed to re-parse")]
    Reparse(#[source] SkillError),
    /// Internal consistency check failed: the rendered text re-parsed to other values.
    #[error("rendered SKILL.md did not re-parse to the same values")]
    Mismatch,
}

/// A [`crate::BundleStore`] operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// No bundle with this digest is stored.
    #[error("bundle not found in the local store")]
    NotFound,
    /// A symlink was found where a directory or file was expected.
    #[error("bundle store entry is a symlink; refusing")]
    Symlink,
    /// The bundle directory contains files other than `SKILL.md`.
    #[error("bundle store entry contains unexpected files; refusing")]
    UnexpectedEntry,
    /// The entry is not a directory / regular file as expected.
    #[error("bundle store entry has an unexpected file type")]
    NotRegular,
    /// The stored content does not verify (digest mismatch or invalid SKILL.md).
    #[error("stored bundle failed verification")]
    Corrupt(#[source] BundleError),
    /// The OS RNG failed while naming a staging directory.
    #[error("randomness unavailable")]
    Randomness,
    /// An I/O operation failed.
    #[error("bundle store I/O error during {op}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The OS error.
        #[source]
        source: io::Error,
    },
}

/// An [`crate::Installer`] operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InstallError {
    /// The skill name is not a valid Agent Skills name (also blocks path traversal).
    #[error("invalid skill name")]
    InvalidName,
    /// The target directory exists but is not managed by PeerHarness.
    #[error("target skill directory is not managed by PeerHarness; use --force-overwrite-unmanaged to replace it")]
    Unmanaged,
    /// The managed SKILL.md was changed since PeerHarness installed it.
    #[error("installed SKILL.md was modified since PeerHarness installed it; refusing without explicit permission")]
    Modified,
    /// A symlink was found at the target directory or one of its managed files.
    #[error("target skill directory or file is a symlink; refusing")]
    Symlink,
    /// The target exists but is not a directory (or a managed file is not a regular file).
    #[error("target skill path has an unexpected file type")]
    NotRegular,
    /// The target root escapes the confinement base or has a symlinked (or non-directory)
    /// path component below it (see [`crate::Installer::confine_to`]).
    #[error("skills directory is a symlink or outside the project; refusing")]
    UnsafeRoot,
    /// `uninstall` was asked for a skill that is not installed.
    #[error("skill is not installed")]
    NotInstalled,
    /// Neither the override nor `$HOME` is available.
    #[error("cannot determine the home directory (HOME is not set)")]
    HomeNotSet,
    /// The OS RNG failed while naming a staging directory.
    #[error("randomness unavailable")]
    Randomness,
    /// An injected test fault (see [`crate::install::FaultPoint`]).
    #[error("injected fault")]
    InjectedFault,
    /// Marker serialization failed.
    #[error("install marker serialization failed")]
    Marker,
    /// An I/O operation failed.
    #[error("install I/O error during {op}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The OS error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_are_static() {
        let e = BundleError::Invalid(vec![
            ValidationError::InvalidName,
            ValidationError::FieldLength {
                field: "description",
                min: 1,
                max: 1024,
                actual: 2000,
            },
        ]);
        let s = e.to_string();
        assert!(s.contains("skill name is invalid"));
        assert!(s.contains("description must be 1-1024 characters (got 2000)"));
        let e = SkillError::Syntax {
            line: 3,
            kind: SyntaxError::Anchor,
        };
        assert_eq!(
            e.to_string(),
            "SKILL.md frontmatter line 3: anchors are not allowed"
        );
        assert_eq!(
            BundleError::Path {
                index: 1,
                reason: PathRejection::Traversal
            }
            .to_string(),
            "bundle file #1 rejected: path traversal"
        );
    }
}
