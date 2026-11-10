//! Agent Skills field rules plus PeerHarness limits.
//!
//! Agent Skills specification (<https://agentskills.io/specification>):
//!
//! | field | rule |
//! |---|---|
//! | `name` | required, 1-64 chars of `a-z`, `0-9`, `-`; no leading/trailing/consecutive `-`; equals the parent directory name |
//! | `description` | required, 1-1024 chars, non-empty |
//! | `license` | optional, short license name or file reference |
//! | `compatibility` | optional, 1-500 chars if present |
//! | `metadata` | optional, string-to-string map |
//! | `allowed-tools` | optional, space-separated tool list (experimental) |
//!
//! PeerHarness adds (documented, stricter-than-spec):
//!
//! * the whole file is at most [`MAX_SKILL_FILE_BYTES`] (256 KiB), valid UTF-8, no NUL
//!   (checked on bytes by [`check_skill_bytes`]);
//! * the body is not blank;
//! * every frontmatter value rejects the control and bidi characters of
//!   [`ph_protocol::text::is_forbidden_char`] plus invisible characters (zero-width
//!   spaces and joiners, BOM, soft hyphen, tag characters, Unicode line/paragraph
//!   separators; see [`is_forbidden_field_char`]), which a double-quoted escape could
//!   otherwise smuggle past the raw-text checks; `description` may span lines, the other
//!   fields are single-line;
//! * `description` is not whitespace-only;
//! * `license` is 1-[`MAX_LICENSE_CHARS`] chars, `allowed-tools` 1-[`MAX_ALLOWED_TOOLS_CHARS`];
//! * at most [`MAX_METADATA_ENTRIES`] metadata entries, keys 1-64 chars of
//!   `[A-Za-z0-9._-]` that YAML reads as strings (not `1`, `true`, `null`, ...), values
//!   0-[`MAX_METADATA_VALUE_CHARS`] chars, single-line.

use ph_core::is_valid_skill_name;
use ph_protocol::text::{is_forbidden_char, Lines};

use crate::error::ValidationError;
use crate::frontmatter::{looks_non_string, SkillDoc};
use crate::scanner::is_hidden_char;

/// Maximum size of a whole SKILL.md file (= `ph_protocol::limits::MAX_BUNDLE_BYTES`).
pub const MAX_SKILL_FILE_BYTES: usize = ph_protocol::limits::MAX_BUNDLE_BYTES;
/// Maximum `description` length in characters (Agent Skills spec).
pub const MAX_DESCRIPTION_CHARS: usize = 1024;
/// Maximum `compatibility` length in characters (Agent Skills spec).
pub const MAX_COMPATIBILITY_CHARS: usize = 500;
/// Maximum `license` length in characters (PeerHarness limit).
pub const MAX_LICENSE_CHARS: usize = 500;
/// Maximum `allowed-tools` length in characters (PeerHarness limit).
pub const MAX_ALLOWED_TOOLS_CHARS: usize = 1024;
/// Maximum number of `metadata` entries (PeerHarness limit).
pub const MAX_METADATA_ENTRIES: usize = 64;
/// Maximum `metadata` key length in bytes (PeerHarness limit).
pub const MAX_METADATA_KEY_BYTES: usize = 64;
/// Maximum `metadata` value length in characters (PeerHarness limit).
pub const MAX_METADATA_VALUE_CHARS: usize = 1024;

/// Checks the file-level rules on raw bytes: size, no NUL, valid UTF-8. Returns the text.
pub fn check_skill_bytes(bytes: &[u8]) -> Result<&str, ValidationError> {
    if bytes.len() > MAX_SKILL_FILE_BYTES {
        return Err(ValidationError::TooLarge {
            size: bytes.len(),
            max: MAX_SKILL_FILE_BYTES,
        });
    }
    if bytes.contains(&0) {
        return Err(ValidationError::ContainsNul);
    }
    std::str::from_utf8(bytes).map_err(|_| ValidationError::InvalidUtf8)
}

/// Validates a parsed document against the Agent Skills rules and PeerHarness limits.
///
/// `expected_dir_name` is the directory the skill lives (or will be installed) in; when
/// given, `name` must equal it. All violations are returned, not only the first. The
/// whole-file byte rules are in [`check_skill_bytes`]; this function additionally
/// rejects a body larger than [`MAX_SKILL_FILE_BYTES`] or containing NUL.
pub fn validate_skill(
    doc: &SkillDoc,
    expected_dir_name: Option<&str>,
) -> Result<(), Vec<ValidationError>> {
    let mut errs = Vec::new();
    let fm = &doc.frontmatter;

    if !is_valid_skill_name(&fm.name) {
        errs.push(ValidationError::InvalidName);
    } else if let Some(dir) = expected_dir_name {
        if dir != fm.name {
            errs.push(ValidationError::NameMismatch);
        }
    }

    text_rule(
        &mut errs,
        "description",
        &fm.description,
        MAX_DESCRIPTION_CHARS,
        Lines::Multi,
        true,
    );
    if let Some(c) = &fm.compatibility {
        text_rule(
            &mut errs,
            "compatibility",
            c,
            MAX_COMPATIBILITY_CHARS,
            Lines::Single,
            true,
        );
    }
    if let Some(l) = &fm.license {
        text_rule(
            &mut errs,
            "license",
            l,
            MAX_LICENSE_CHARS,
            Lines::Single,
            true,
        );
    }
    if let Some(t) = &fm.allowed_tools {
        text_rule(
            &mut errs,
            "allowed-tools",
            t,
            MAX_ALLOWED_TOOLS_CHARS,
            Lines::Single,
            true,
        );
    }

    if fm.metadata.len() > MAX_METADATA_ENTRIES {
        errs.push(ValidationError::TooManyMetadataEntries {
            max: MAX_METADATA_ENTRIES,
            actual: fm.metadata.len(),
        });
    }
    let mut bad_key = false;
    for (k, v) in &fm.metadata {
        if !is_valid_metadata_key(k) {
            bad_key = true;
        }
        text_rule(
            &mut errs,
            "metadata value",
            v,
            MAX_METADATA_VALUE_CHARS,
            Lines::Single,
            false,
        );
    }
    if bad_key {
        errs.push(ValidationError::InvalidMetadataKey);
    }

    if doc.body.len() > MAX_SKILL_FILE_BYTES {
        errs.push(ValidationError::TooLarge {
            size: doc.body.len(),
            max: MAX_SKILL_FILE_BYTES,
        });
    } else if doc.body.contains('\0') {
        errs.push(ValidationError::ContainsNul);
    } else if doc.body.trim().is_empty() {
        errs.push(ValidationError::Blank { field: "body" });
    }

    errs.dedup();
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Whether `k` is an acceptable `metadata` key: 1-64 bytes of `[A-Za-z0-9._-]`, and not
/// a plain scalar that YAML would resolve to a non-string (`1`, `true`, `null`, `y`,
/// `1.0`, ...), so every YAML parser reads the same string key.
pub fn is_valid_metadata_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= MAX_METADATA_KEY_BYTES
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !looks_non_string(k)
        && k != "-"
}

/// Whether `c` is forbidden in a frontmatter value: everything
/// [`ph_protocol::text::is_forbidden_char`] forbids (controls, bidi characters and the
/// zero-width / invisible format characters U+200B-U+200D, U+2060, U+FEFF, U+180E and
/// the tag characters; `lines` decides whether `\n`, `\r`, `\t` are allowed) plus the
/// wider set of hidden characters the risk scanner knows (soft hyphen, combining
/// grapheme joiner, invisible operators U+2061-U+2064, deprecated format characters
/// U+206A-U+206F, Mongolian free variation selectors, Khmer inherent vowels, Hangul
/// fillers, variation selectors supplement and, in every field, U+2028/U+2029).
/// Emoji variation selectors (U+FE00-U+FE0F) are allowed.
pub fn is_forbidden_field_char(c: char, lines: Lines) -> bool {
    is_forbidden_char(c, lines) || (is_hidden_char(c) && !matches!(c, '\u{fe00}'..='\u{fe0f}'))
}

fn text_rule(
    errs: &mut Vec<ValidationError>,
    field: &'static str,
    s: &str,
    max: usize,
    lines: Lines,
    required_nonblank: bool,
) {
    let mut n = 0usize;
    let mut forbidden = false;
    for c in s.chars() {
        n += 1;
        if is_forbidden_field_char(c, lines) {
            forbidden = true;
        }
    }
    if forbidden {
        errs.push(ValidationError::ForbiddenCharacter { field });
    }
    let min = usize::from(required_nonblank);
    if n < min || n > max {
        errs.push(ValidationError::FieldLength {
            field,
            min,
            max,
            actual: n,
        });
    } else if required_nonblank && s.trim().is_empty() {
        errs.push(ValidationError::Blank { field });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontmatter::{Frontmatter, SkillDoc};

    fn doc(name: &str, description: &str) -> SkillDoc {
        SkillDoc {
            frontmatter: Frontmatter {
                name: name.into(),
                description: description.into(),
                ..Default::default()
            },
            body: "Body.\n".into(),
        }
    }

    #[test]
    fn ok_and_dir_match() {
        assert!(validate_skill(&doc("pnpm-x", "d"), Some("pnpm-x")).is_ok());
        assert_eq!(
            validate_skill(&doc("pnpm-x", "d"), Some("other")),
            Err(vec![ValidationError::NameMismatch])
        );
    }

    #[test]
    fn names() {
        for bad in ["", "A", "-a", "a-", "a--b", "a_b", "../x", &"a".repeat(65)] {
            assert_eq!(
                validate_skill(&doc(bad, "d"), None),
                Err(vec![ValidationError::InvalidName]),
                "{bad}"
            );
        }
    }

    #[test]
    fn lengths_and_chars() {
        assert!(validate_skill(&doc("a", &"é".repeat(1024)), None).is_ok());
        assert!(matches!(
            validate_skill(&doc("a", &"é".repeat(1025)), None).unwrap_err()[0],
            ValidationError::FieldLength { actual: 1025, .. }
        ));
        assert!(matches!(
            validate_skill(&doc("a", ""), None).unwrap_err()[0],
            ValidationError::FieldLength { actual: 0, .. }
        ));
        assert_eq!(
            validate_skill(&doc("a", "   "), None),
            Err(vec![ValidationError::Blank {
                field: "description"
            }])
        );
        assert_eq!(
            validate_skill(&doc("a", "x\u{1b}[31m"), None),
            Err(vec![ValidationError::ForbiddenCharacter {
                field: "description"
            }])
        );
        assert!(validate_skill(&doc("a", "multi\nline"), None).is_ok());

        let mut d = doc("a", "d");
        d.frontmatter.compatibility = Some("x".repeat(501));
        d.frontmatter.license = Some("MIT\nX".into());
        d.frontmatter.allowed_tools = Some(String::new());
        d.frontmatter.metadata.insert("bad key".into(), "v".into());
        d.frontmatter
            .metadata
            .insert("ok".into(), "\u{202e}".into());
        d.body = " \n".into();
        let errs = validate_skill(&d, None).unwrap_err();
        assert!(errs.contains(&ValidationError::FieldLength {
            field: "compatibility",
            min: 1,
            max: 500,
            actual: 501
        }));
        assert!(errs.contains(&ValidationError::ForbiddenCharacter { field: "license" }));
        assert!(errs.contains(&ValidationError::FieldLength {
            field: "allowed-tools",
            min: 1,
            max: 1024,
            actual: 0
        }));
        assert!(errs.contains(&ValidationError::InvalidMetadataKey));
        assert!(errs.contains(&ValidationError::ForbiddenCharacter {
            field: "metadata value"
        }));
        assert!(errs.contains(&ValidationError::Blank { field: "body" }));
    }

    #[test]
    fn invisible_characters_and_yaml_keys() {
        for c in [
            '\u{200b}',
            '\u{200d}',
            '\u{2060}',
            '\u{feff}',
            '\u{00ad}',
            '\u{e0041}',
            '\u{2028}',
        ] {
            assert_eq!(
                validate_skill(&doc("a", &format!("x{c}y")), None),
                Err(vec![ValidationError::ForbiddenCharacter {
                    field: "description"
                }]),
                "{:04X}",
                c as u32
            );
        }
        // Emoji with a variation selector stays valid.
        assert!(validate_skill(&doc("a", "Ship it \u{2764}\u{fe0f}"), None).is_ok());
        for k in ["1", "true", "NULL", "y", "~", "-", "1.0", ""] {
            assert!(!is_valid_metadata_key(k), "{k:?}");
        }
        for k in ["author", "v1", "x.y_z-w", "Version"] {
            assert!(is_valid_metadata_key(k), "{k:?}");
        }
    }

    #[test]
    fn bytes() {
        assert_eq!(check_skill_bytes(b"ok"), Ok("ok"));
        assert_eq!(
            check_skill_bytes(b"a\0b"),
            Err(ValidationError::ContainsNul)
        );
        assert_eq!(
            check_skill_bytes(&[0xff, 0xfe]),
            Err(ValidationError::InvalidUtf8)
        );
        assert_eq!(
            check_skill_bytes(&vec![b'a'; MAX_SKILL_FILE_BYTES + 1]),
            Err(ValidationError::TooLarge {
                size: MAX_SKILL_FILE_BYTES + 1,
                max: MAX_SKILL_FILE_BYTES
            })
        );
        assert!(check_skill_bytes(&vec![b'a'; MAX_SKILL_FILE_BYTES]).is_ok());
    }
}
