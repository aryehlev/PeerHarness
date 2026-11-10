//! Strict YAML-subset frontmatter parser for `SKILL.md` (ADR-005).
//!
//! # Accepted grammar
//!
//! ```text
//! ---                                   first line, exactly
//! name: <scalar>                        required
//! description: <scalar> | <block>       required
//! license: <scalar>                     optional
//! compatibility: <scalar>               optional
//! allowed-tools: <scalar>               optional (experimental in the Agent Skills spec)
//! metadata:                             optional, one level, exactly two spaces indent
//!   <key>: <scalar>
//! ---                                   next line that is exactly ---
//! <markdown body>
//! ```
//!
//! * `<scalar>` is a single-line plain scalar, a single-quoted string (`''` escapes a
//!   quote) or a double-quoted string with the YAML escapes `\0 \a \b \t \n \v \f \r \e
//!   \  \" \/ \\ \N \_ \L \P \xHH \uHHHH \UHHHHHHHH`. A `#` comment preceded by a space
//!   may follow. Plain scalars that YAML would not resolve to a string (`true`, `no`,
//!   `null`, `~`, numbers, dates, ...) are rejected so that our reading never differs from
//!   a real YAML parser's; quote them.
//! * `<block>` is `|` or `>` with an optional `-` / `+` chomping indicator (no explicit
//!   indentation indicator) followed by lines indented by at least one space. Folded
//!   blocks with more-indented lines are rejected.
//! * Blank lines and full-line `#` comments are allowed between entries.
//! * CRLF line endings are normalized to LF before parsing.
//!
//! Everything else is rejected: anchors, aliases, tags, flow collections, sequences,
//! directives, document markers, multi-line plain or quoted scalars, tabs, control and
//! invisible characters, duplicate keys, unknown top-level keys and frontmatter over
//! [`MAX_FRONTMATTER_BYTES`]. The Markdown body is free-form; a `---` line in the body is
//! an ordinary Markdown rule.
//!
//! The parser never panics: it works on `&str` slices split at ASCII boundaries only.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ph_protocol::text::{is_forbidden_char, Lines};

use crate::error::{SkillError, SyntaxError};

/// Maximum frontmatter size in bytes (between the two `---` lines, after CRLF
/// normalization).
pub const MAX_FRONTMATTER_BYTES: usize = 8 * 1024;

/// The top-level keys the Agent Skills specification defines.
pub const ALLOWED_KEYS: [&str; 6] = [
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
];

/// Parsed frontmatter. Values are exactly what a YAML parser would produce.
///
/// `Debug` prints lengths only, because the values are untrusted text.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Frontmatter {
    /// `name` (not yet validated; see [`crate::validate_skill`]).
    pub name: String,
    /// `description`.
    pub description: String,
    /// `license`, when present.
    pub license: Option<String>,
    /// `compatibility`, when present.
    pub compatibility: Option<String>,
    /// `metadata` entries (empty when the key is absent).
    pub metadata: BTreeMap<String, String>,
    /// `allowed-tools`, when present. The risk scanner flags it as a warning.
    pub allowed_tools: Option<String>,
}

impl fmt::Debug for Frontmatter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frontmatter")
            .field("name_len", &self.name.len())
            .field("description_len", &self.description.len())
            .field("license_len", &self.license.as_ref().map(String::len))
            .field(
                "compatibility_len",
                &self.compatibility.as_ref().map(String::len),
            )
            .field("metadata_entries", &self.metadata.len())
            .field(
                "allowed_tools_len",
                &self.allowed_tools.as_ref().map(String::len),
            )
            .finish()
    }
}

/// A parsed `SKILL.md`.
///
/// `body` is the Markdown after the closing `---` line with CRLF normalized to LF and
/// leading empty lines removed (see [`crate::normalize_body`]).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SkillDoc {
    /// The frontmatter.
    pub frontmatter: Frontmatter,
    /// The Markdown body.
    pub body: String,
}

impl fmt::Debug for SkillDoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkillDoc")
            .field("frontmatter", &self.frontmatter)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Parses a `SKILL.md` file (see the module docs for the accepted subset).
///
/// This only parses; [`crate::validate_skill`] enforces the Agent Skills field rules.
pub fn parse_skill_md(input: &str) -> Result<SkillDoc, SkillError> {
    let text: Cow<'_, str> = if input.contains("\r\n") {
        Cow::Owned(input.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(input)
    };
    let rest = text
        .strip_prefix("---\n")
        .ok_or(SkillError::MissingFrontmatter)?;

    // Find the closing line, bounded by the frontmatter limit.
    let mut offset = 0usize;
    let (fm, body_raw) = loop {
        if offset > MAX_FRONTMATTER_BYTES {
            return Err(SkillError::FrontmatterTooLarge {
                max: MAX_FRONTMATTER_BYTES,
            });
        }
        let remaining = rest.get(offset..).unwrap_or("");
        if remaining.is_empty() {
            return Err(SkillError::UnterminatedFrontmatter);
        }
        let (line, next) = match remaining.find('\n') {
            Some(i) => (&remaining[..i], offset + i + 1),
            None => (remaining, rest.len()),
        };
        if line == "---" {
            break (&rest[..offset], rest.get(next..).unwrap_or(""));
        }
        offset = next;
    };
    if fm.len() > MAX_FRONTMATTER_BYTES {
        return Err(SkillError::FrontmatterTooLarge {
            max: MAX_FRONTMATTER_BYTES,
        });
    }

    let frontmatter = parse_frontmatter(fm)?;
    let body = body_raw.trim_start_matches('\n').to_owned();
    Ok(SkillDoc { frontmatter, body })
}

/// File line number of frontmatter line `idx` (0-based): line 1 is the opening `---`.
const fn file_line(idx: usize) -> usize {
    idx + 2
}

fn syntax(idx: usize, kind: SyntaxError) -> SkillError {
    SkillError::Syntax {
        line: file_line(idx),
        kind,
    }
}

/// Characters never allowed raw in the frontmatter.
pub(crate) fn forbidden_raw(c: char) -> Option<SyntaxError> {
    match c {
        '\n' => None,
        '\t' => Some(SyntaxError::Tab),
        // `is_forbidden_char` also covers U+FEFF and the other zero-width characters.
        '\r' | '\u{2028}' | '\u{2029}' => Some(SyntaxError::ControlCharacter),
        c if is_forbidden_char(c, Lines::Multi) => Some(SyntaxError::ControlCharacter),
        _ => None,
    }
}

fn is_blank(line: &str) -> bool {
    line.bytes().all(|b| b == b' ')
}

fn leading_spaces(line: &str) -> usize {
    line.bytes().take_while(|&b| b == b' ').count()
}

fn is_comment_line(line: &str) -> bool {
    line.trim_start_matches(' ').starts_with('#')
}

fn parse_frontmatter(fm: &str) -> Result<Frontmatter, SkillError> {
    let lines: Vec<&str> = fm.split_terminator('\n').collect();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(kind) = line.chars().find_map(forbidden_raw) {
            return Err(syntax(idx, kind));
        }
    }

    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut out = Frontmatter::default();
    let mut name = None;
    let mut description = None;
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        if is_blank(line) || is_comment_line(line) {
            i += 1;
            continue;
        }
        if line.starts_with(' ') {
            return Err(syntax(i, SyntaxError::UnexpectedIndentation));
        }
        if line.starts_with("---") || line.starts_with("...") {
            return Err(syntax(i, SyntaxError::DocumentMarker));
        }
        if line.starts_with('%') {
            return Err(syntax(i, SyntaxError::Directive));
        }
        if line == "-" || line.starts_with("- ") {
            return Err(syntax(i, SyntaxError::Sequence));
        }
        let (key, value) = split_key(line).map_err(|k| syntax(i, k))?;
        let key: &'static str = ALLOWED_KEYS
            .iter()
            .copied()
            .find(|k| *k == key)
            .ok_or_else(|| syntax(i, SyntaxError::UnknownKey))?;
        if !seen.insert(key) {
            return Err(syntax(i, SyntaxError::DuplicateKey));
        }
        match key {
            "metadata" => {
                if !is_empty_value(value) {
                    return Err(syntax(i, value_shape_error(value)));
                }
                let (map, next) = parse_metadata(&lines, i + 1)?;
                if map.is_empty() {
                    return Err(syntax(i, SyntaxError::EmptyValue));
                }
                out.metadata = map;
                i = next;
                continue;
            }
            "description" if value.starts_with('|') || value.starts_with('>') => {
                let (text, next) = parse_block_scalar(&lines, i, value)?;
                description = Some(text);
                i = next;
                continue;
            }
            _ => {}
        }
        let v = parse_inline_scalar(value).map_err(|k| syntax(i, k))?;
        match key {
            "name" => name = Some(v),
            "description" => description = Some(v),
            "license" => out.license = Some(v),
            "compatibility" => out.compatibility = Some(v),
            "allowed-tools" => out.allowed_tools = Some(v),
            _ => return Err(syntax(i, SyntaxError::UnknownKey)),
        }
        i += 1;
    }
    out.name = name.ok_or(SkillError::MissingKey { key: "name" })?;
    out.description = description.ok_or(SkillError::MissingKey { key: "description" })?;
    Ok(out)
}

/// Splits `key: value` (or `key:`). Returns the key and the value with leading spaces
/// removed.
fn split_key(line: &str) -> Result<(&str, &str), SyntaxError> {
    let first = line.chars().next().unwrap_or(' ');
    match first {
        '&' => return Err(SyntaxError::Anchor),
        '*' => return Err(SyntaxError::Alias),
        '!' => return Err(SyntaxError::Tag),
        '{' | '[' => return Err(SyntaxError::FlowCollection),
        _ => {}
    }
    let colon = line.find(':').ok_or(SyntaxError::InvalidKey)?;
    let key = &line[..colon];
    let after = &line[colon + 1..];
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(SyntaxError::InvalidKey);
    }
    if !(after.is_empty() || after.starts_with(' ')) {
        return Err(SyntaxError::InvalidKey);
    }
    Ok((key, after.trim_start_matches(' ')))
}

/// A value that is empty or only a comment.
fn is_empty_value(v: &str) -> bool {
    v.is_empty() || v.starts_with('#')
}

/// The error for a non-empty value where a map was expected.
fn value_shape_error(v: &str) -> SyntaxError {
    match v.chars().next() {
        Some('&') => SyntaxError::Anchor,
        Some('*') => SyntaxError::Alias,
        Some('!') => SyntaxError::Tag,
        Some('{') | Some('[') => SyntaxError::FlowCollection,
        _ => SyntaxError::ExpectedMap,
    }
}

/// Parses the indented `metadata` entries starting at `start`. Returns the map and the
/// index of the first line after the block.
fn parse_metadata(
    lines: &[&str],
    start: usize,
) -> Result<(BTreeMap<String, String>, usize), SkillError> {
    let mut map = BTreeMap::new();
    let mut i = start;
    while i < lines.len() {
        let line = lines[i];
        if is_blank(line) {
            i += 1;
            continue;
        }
        if !line.starts_with(' ') {
            break;
        }
        if is_comment_line(line) {
            i += 1;
            continue;
        }
        if leading_spaces(line) != 2 {
            return Err(syntax(i, SyntaxError::MetadataIndentation));
        }
        let entry = &line[2..];
        if entry == "-" || entry.starts_with("- ") {
            return Err(syntax(i, SyntaxError::Sequence));
        }
        let (key, value) = split_key(entry).map_err(|k| syntax(i, k))?;
        if key == "-" {
            return Err(syntax(i, SyntaxError::InvalidKey));
        }
        if looks_non_string(key) {
            // `1:`, `true:`, `null:` ... are non-string keys in YAML.
            return Err(syntax(i, SyntaxError::NonStringScalar));
        }
        if value.starts_with('|') || value.starts_with('>') {
            return Err(syntax(i, SyntaxError::BlockScalarNotAllowed));
        }
        let v = parse_inline_scalar(value).map_err(|k| syntax(i, k))?;
        if map.insert(key.to_owned(), v).is_some() {
            return Err(syntax(i, SyntaxError::DuplicateKey));
        }
        i += 1;
    }
    Ok((map, i))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Chomp {
    Clip,
    Strip,
    Keep,
}

/// Parses a `|` / `>` block scalar whose header is `header` on line `idx`.
fn parse_block_scalar(
    lines: &[&str],
    idx: usize,
    header: &str,
) -> Result<(String, usize), SkillError> {
    let bytes = header.as_bytes();
    let folded = bytes.first() == Some(&b'>');
    let mut pos = 1;
    let chomp = match bytes.get(1) {
        Some(b'-') => {
            pos = 2;
            Chomp::Strip
        }
        Some(b'+') => {
            pos = 2;
            Chomp::Keep
        }
        _ => Chomp::Clip,
    };
    let tail = &header[pos..];
    if tail.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return Err(syntax(idx, SyntaxError::InvalidBlockScalarHeader));
    }
    let trimmed = tail.trim_start_matches(' ');
    let comment_after_space = trimmed.starts_with('#') && trimmed.len() < tail.len();
    if !trimmed.is_empty() && !comment_after_space {
        return Err(syntax(idx, SyntaxError::InvalidBlockScalarHeader));
    }

    // Collect candidate lines: blank or indented.
    let mut end = idx + 1;
    while end < lines.len() && (is_blank(lines[end]) || lines[end].starts_with(' ')) {
        end += 1;
    }
    let block = &lines[idx + 1..end];
    let indent = block
        .iter()
        .find(|l| !is_blank(l))
        .map(|l| leading_spaces(l));

    let mut content: Vec<&str> = Vec::with_capacity(block.len());
    match indent {
        // Only blank lines: all of them are empty content lines.
        None => content.resize(block.len(), ""),
        Some(n) => {
            let mut seen_text = false;
            for (off, l) in block.iter().enumerate() {
                let li = idx + 1 + off;
                if is_blank(l) {
                    if l.len() > n {
                        if !seen_text {
                            // YAML: leading empty lines may not be more indented.
                            return Err(syntax(li, SyntaxError::BlockIndentation));
                        }
                        if folded {
                            return Err(syntax(li, SyntaxError::UnsupportedFolding));
                        }
                        content.push(&l[n..]);
                    } else {
                        content.push("");
                    }
                    continue;
                }
                if leading_spaces(l) < n {
                    return Err(syntax(li, SyntaxError::BlockIndentation));
                }
                let c = &l[n..];
                if folded && c.starts_with(' ') {
                    return Err(syntax(li, SyntaxError::UnsupportedFolding));
                }
                seen_text = true;
                content.push(c);
            }
        }
    }

    let last_text = content.iter().rposition(|c| !c.is_empty());
    let value = match last_text {
        None => match chomp {
            Chomp::Keep => "\n".repeat(content.len()),
            _ => String::new(),
        },
        Some(last) => {
            let text_lines = &content[..=last];
            let trailing = content.len() - last - 1;
            let mut s = if folded {
                fold(text_lines)
            } else {
                text_lines.join("\n")
            };
            match chomp {
                Chomp::Strip => {}
                Chomp::Clip => s.push('\n'),
                Chomp::Keep => {
                    s.push('\n');
                    s.push_str(&"\n".repeat(trailing));
                }
            }
            s
        }
    };
    Ok((value, end))
}

/// YAML line folding for blocks without more-indented lines: a single line break
/// between text lines becomes a space, `k` empty lines become `k` newlines, and leading
/// empty lines are kept as newlines.
fn fold(lines: &[&str]) -> String {
    let mut out = String::new();
    let mut started = false;
    let mut pending_empty = 0usize;
    for l in lines {
        if l.is_empty() {
            pending_empty += 1;
            continue;
        }
        if started && pending_empty == 0 {
            out.push(' ');
        } else {
            out.push_str(&"\n".repeat(pending_empty));
        }
        out.push_str(l);
        started = true;
        pending_empty = 0;
    }
    out
}

/// Parses a single-line scalar value (leading spaces already removed).
pub(crate) fn parse_inline_scalar(v: &str) -> Result<String, SyntaxError> {
    let mut chars = v.chars();
    let first = match chars.next() {
        None | Some('#') => return Err(SyntaxError::EmptyValue),
        Some(c) => c,
    };
    let second = chars.next();
    match first {
        '&' => Err(SyntaxError::Anchor),
        '*' => Err(SyntaxError::Alias),
        '!' => Err(SyntaxError::Tag),
        '{' | '[' => Err(SyntaxError::FlowCollection),
        '|' | '>' => Err(SyntaxError::BlockScalarNotAllowed),
        '}' | ']' | ',' | '%' | '@' | '`' | '?' | ':' => Err(SyntaxError::ReservedIndicator),
        '-' if second.is_none() || second == Some(' ') => Err(SyntaxError::Sequence),
        '"' => parse_double_quoted(&v[1..]),
        '\'' => parse_single_quoted(&v[1..]),
        _ => parse_plain(v),
    }
}

fn parse_plain(v: &str) -> Result<String, SyntaxError> {
    let s = match v.find(" #") {
        Some(i) => &v[..i],
        None => v,
    };
    let s = s.trim_end_matches(' ');
    if s.contains(": ") || s.ends_with(':') {
        return Err(SyntaxError::AmbiguousColon);
    }
    if looks_non_string(s) {
        return Err(SyntaxError::NonStringScalar);
    }
    Ok(s.to_owned())
}

/// After a closing quote: only spaces, optionally followed by a ` #` comment.
fn check_after_quote(rest: &str) -> Result<(), SyntaxError> {
    let t = rest.trim_start_matches(' ');
    if t.is_empty() || (t.starts_with('#') && t.len() < rest.len()) {
        Ok(())
    } else {
        Err(SyntaxError::TrailingContent)
    }
}

fn parse_single_quoted(s: &str) -> Result<String, SyntaxError> {
    let mut out = String::new();
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if c == '\'' {
            if let Some(&(_, '\'')) = it.peek() {
                it.next();
                out.push('\'');
                continue;
            }
            check_after_quote(&s[i + 1..])?;
            return Ok(out);
        }
        out.push(c);
    }
    Err(SyntaxError::UnterminatedQuote)
}

fn parse_double_quoted(s: &str) -> Result<String, SyntaxError> {
    let mut out = String::new();
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => {
                check_after_quote(&s[i + 1..])?;
                return Ok(out);
            }
            '\\' => {
                let (_, e) = it.next().ok_or(SyntaxError::UnterminatedQuote)?;
                let decoded = match e {
                    '0' => '\0',
                    'a' => '\u{7}',
                    'b' => '\u{8}',
                    't' => '\t',
                    'n' => '\n',
                    'v' => '\u{b}',
                    'f' => '\u{c}',
                    'r' => '\r',
                    'e' => '\u{1b}',
                    ' ' => ' ',
                    '"' => '"',
                    '/' => '/',
                    '\\' => '\\',
                    'N' => '\u{85}',
                    '_' => '\u{a0}',
                    'L' => '\u{2028}',
                    'P' => '\u{2029}',
                    'x' => hex_escape(&mut it, 2)?,
                    'u' => hex_escape(&mut it, 4)?,
                    'U' => hex_escape(&mut it, 8)?,
                    _ => return Err(SyntaxError::InvalidEscape),
                };
                out.push(decoded);
            }
            c => out.push(c),
        }
    }
    Err(SyntaxError::UnterminatedQuote)
}

fn hex_escape(it: &mut std::str::CharIndices<'_>, n: usize) -> Result<char, SyntaxError> {
    let mut v: u32 = 0;
    for _ in 0..n {
        let (_, c) = it.next().ok_or(SyntaxError::InvalidEscape)?;
        let d = c.to_digit(16).ok_or(SyntaxError::InvalidEscape)?;
        v = v.checked_mul(16).ok_or(SyntaxError::InvalidEscape)? | d;
    }
    char::from_u32(v).ok_or(SyntaxError::InvalidEscape)
}

/// Whether a plain scalar would resolve to something other than a string under the
/// YAML 1.1 or 1.2 core schemas (null, booleans including `yes`/`no`/`on`/`off`,
/// integers in any base, floats, `.inf`/`.nan`, sexagesimal numbers and timestamps).
/// Conservative: some strings (`1.0.0`) are rejected too; they must be quoted.
pub(crate) fn looks_non_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "" | "~" | "null" | "true" | "false" | "yes" | "no" | "on" | "off" | "y" | "n" | "="
    ) {
        return true;
    }
    let t = lower
        .strip_prefix('+')
        .or_else(|| lower.strip_prefix('-'))
        .unwrap_or(&lower);
    if matches!(t, ".inf" | ".nan") {
        return true;
    }
    let tb = t.as_bytes();
    let numeric_start = match tb {
        [d, ..] if d.is_ascii_digit() => true,
        [b'.', d, ..] if d.is_ascii_digit() => true,
        _ => false,
    };
    if numeric_start
        && tb
            .iter()
            .all(|b| b.is_ascii_hexdigit() || b"xo_.:+-".contains(b))
    {
        return true;
    }
    // YAML 1.1 timestamps: YYYY-M-D...
    let b = s.as_bytes();
    if b.len() >= 8
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5].is_ascii_digit()
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fm(s: &str) -> Result<Frontmatter, SkillError> {
        parse_skill_md(&format!("---\n{s}---\nbody\n")).map(|d| d.frontmatter)
    }

    fn kind(s: &str) -> SyntaxError {
        match fm(s) {
            Err(SkillError::Syntax { kind, .. }) => kind,
            other => panic!("expected syntax error, got {other:?}"),
        }
    }

    #[test]
    fn minimal() {
        let d = parse_skill_md("---\nname: a\ndescription: b c\n---\n\nHello\n").unwrap();
        assert_eq!(d.frontmatter.name, "a");
        assert_eq!(d.frontmatter.description, "b c");
        assert_eq!(d.body, "Hello\n");
        assert!(d.frontmatter.metadata.is_empty());
    }

    #[test]
    fn crlf() {
        let d = parse_skill_md("---\r\nname: a\r\ndescription: b\r\n---\r\nx\r\n").unwrap();
        assert_eq!(d.frontmatter.name, "a");
        assert_eq!(d.body, "x\n");
    }

    #[test]
    fn closing_at_eof() {
        let d = parse_skill_md("---\nname: a\ndescription: b\n---").unwrap();
        assert_eq!(d.body, "");
    }

    #[test]
    fn missing_and_unterminated() {
        assert_eq!(
            parse_skill_md("name: a\n"),
            Err(SkillError::MissingFrontmatter)
        );
        assert_eq!(
            parse_skill_md("\u{feff}---\nname: a\n---\n"),
            Err(SkillError::MissingFrontmatter)
        );
        assert_eq!(
            parse_skill_md(" ---\nname: a\n---\n"),
            Err(SkillError::MissingFrontmatter)
        );
        assert_eq!(
            parse_skill_md("---\nname: a\n"),
            Err(SkillError::UnterminatedFrontmatter)
        );
        assert_eq!(parse_skill_md("---"), Err(SkillError::MissingFrontmatter));
        assert_eq!(
            fm("name: a\n"),
            Err(SkillError::MissingKey { key: "description" })
        );
        assert_eq!(
            fm("description: a\n"),
            Err(SkillError::MissingKey { key: "name" })
        );
    }

    #[test]
    fn quoting() {
        let f = fm("name: 'a'\ndescription: \"x\\ty \\\"q\\\" \\u00e9 \\x41\"  # c\n").unwrap();
        assert_eq!(f.name, "a");
        assert_eq!(f.description, "x\ty \"q\" é A");
        let f = fm("name: a\ndescription: 'it''s # not a comment'\n").unwrap();
        assert_eq!(f.description, "it's # not a comment");
        let f = fm("name: a # comment\ndescription: C# is fine, issue#1\n").unwrap();
        assert_eq!(f.name, "a");
        assert_eq!(f.description, "C# is fine, issue#1");
        assert_eq!(
            kind("name: 'a\ndescription: b\n"),
            SyntaxError::UnterminatedQuote
        );
        assert_eq!(
            kind("name: \"a\ndescription: b\n"),
            SyntaxError::UnterminatedQuote
        );
        assert_eq!(
            kind("name: \"a\"x\ndescription: b\n"),
            SyntaxError::TrailingContent
        );
        assert_eq!(
            kind("name: \"a\"#x\ndescription: b\n"),
            SyntaxError::TrailingContent
        );
        assert_eq!(
            kind("name: \"\\q\"\ndescription: b\n"),
            SyntaxError::InvalidEscape
        );
        assert_eq!(
            kind("name: \"\\ud800\"\ndescription: b\n"),
            SyntaxError::InvalidEscape
        );
        assert_eq!(
            kind("name: \"\\x4\"\ndescription: b\n"),
            SyntaxError::InvalidEscape
        );
        assert_eq!(
            kind("name: \"\\UFFFFFFFF\"\ndescription: b\n"),
            SyntaxError::InvalidEscape
        );
    }

    #[test]
    fn plain_scalar_rules() {
        for v in [
            "true",
            "No",
            "null",
            "~",
            "1",
            "1.0",
            "0x1F",
            "-3",
            ".5",
            ".inf",
            "-.NaN",
            "2026-01-01",
            "12:30",
            "1_000",
            "y",
            "on",
        ] {
            assert_eq!(
                kind(&format!("name: {v}\ndescription: b\n")),
                SyntaxError::NonStringScalar,
                "{v}"
            );
        }
        for v in ["a1", "x-1.0", "v1", "3D models", "1 apple"] {
            assert!(fm(&format!("name: {v}\ndescription: b\n")).is_ok(), "{v}");
        }
        assert_eq!(
            kind("name: a\ndescription: a: b\n"),
            SyntaxError::AmbiguousColon
        );
        assert_eq!(
            kind("name: a\ndescription: ab:\n"),
            SyntaxError::AmbiguousColon
        );
        assert!(fm("name: a\ndescription: see http://x.y/z\n").is_ok());
        assert_eq!(kind("name:\ndescription: b\n"), SyntaxError::EmptyValue);
        assert_eq!(kind("name: # c\ndescription: b\n"), SyntaxError::EmptyValue);
        assert_eq!(
            kind("name: a\ndescription: @x\n"),
            SyntaxError::ReservedIndicator
        );
        assert_eq!(
            kind("name: a\ndescription: `x`\n"),
            SyntaxError::ReservedIndicator
        );
        assert_eq!(kind("name: a\ndescription: - x\n"), SyntaxError::Sequence);
        assert!(fm("name: a\ndescription: -x\n").is_ok());
    }

    #[test]
    fn yaml_attacks() {
        assert_eq!(kind("name: &a x\ndescription: b\n"), SyntaxError::Anchor);
        assert_eq!(kind("name: a\ndescription: *a\n"), SyntaxError::Alias);
        assert_eq!(kind("name: !!str a\ndescription: b\n"), SyntaxError::Tag);
        assert_eq!(
            kind("name: a\ndescription: {a: b}\n"),
            SyntaxError::FlowCollection
        );
        assert_eq!(
            kind("name: a\ndescription: [a]\n"),
            SyntaxError::FlowCollection
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata: {a: b}\n"),
            SyntaxError::FlowCollection
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata: &m\n"),
            SyntaxError::Anchor
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata: x\n"),
            SyntaxError::ExpectedMap
        );
        assert_eq!(
            kind("name: a\ndescription: b\n...\n"),
            SyntaxError::DocumentMarker
        );
        assert_eq!(
            kind("name: a\ndescription: b\n--- \n"),
            SyntaxError::DocumentMarker
        );
        assert_eq!(
            kind("%YAML 1.2\nname: a\ndescription: b\n"),
            SyntaxError::Directive
        );
        assert_eq!(
            kind("name: a\ndescription: b\nname: c\n"),
            SyntaxError::DuplicateKey
        );
        assert_eq!(
            kind("name: a\ndescription: b\nfoo: c\n"),
            SyntaxError::UnknownKey
        );
        assert_eq!(
            kind("name: a\ndescription: b\nName: c\n"),
            SyntaxError::UnknownKey
        );
        assert_eq!(
            kind("\"name\": a\ndescription: b\n"),
            SyntaxError::InvalidKey
        );
        assert_eq!(kind("name : a\ndescription: b\n"), SyntaxError::InvalidKey);
        assert_eq!(kind("name:a\ndescription: b\n"), SyntaxError::InvalidKey);
        assert_eq!(
            kind("? name\n: a\ndescription: b\n"),
            SyntaxError::InvalidKey
        );
        assert_eq!(kind("<<: *x\nname: a\n"), SyntaxError::InvalidKey);
        assert_eq!(kind("&a name: a\n"), SyntaxError::Anchor);
        assert_eq!(kind("- a\n"), SyntaxError::Sequence);
        assert_eq!(
            kind("name: a\ndescription: b\n\tlicense: x\n"),
            SyntaxError::Tab
        );
        assert_eq!(kind("name:\ta\ndescription: b\n"), SyntaxError::Tab);
        assert_eq!(
            kind("name: a\ndescription: b\n  license: x\n"),
            SyntaxError::UnexpectedIndentation
        );
        assert_eq!(
            kind("name: a\ndescription: b\n  continued\n"),
            SyntaxError::UnexpectedIndentation
        );
        assert_eq!(
            kind("name: a\rb\ndescription: b\n"),
            SyntaxError::ControlCharacter
        );
        assert_eq!(
            kind("name: a\u{202e}\ndescription: b\n"),
            SyntaxError::ControlCharacter
        );
        assert_eq!(
            kind("name: a\u{feff}\ndescription: b\n"),
            SyntaxError::ControlCharacter
        );
        for zw in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{e0041}'] {
            assert_eq!(
                kind(&format!("name: a\ndescription: b{zw}c\n")),
                SyntaxError::ControlCharacter,
                "{zw:?}"
            );
        }
        assert_eq!(
            kind("name: a\u{85}\ndescription: b\n"),
            SyntaxError::ControlCharacter
        );
        assert_eq!(
            kind("name: a\u{2028}\ndescription: b\n"),
            SyntaxError::ControlCharacter
        );
        assert_eq!(
            kind("name: a\0\ndescription: b\n"),
            SyntaxError::ControlCharacter
        );
        assert_eq!(
            kind("name: a\ndescription: b\nlicense: |\n  x\n"),
            SyntaxError::BlockScalarNotAllowed
        );
    }

    #[test]
    fn too_large() {
        let big = format!("name: a\ndescription: b\n{}", "# pad\n".repeat(2000));
        assert_eq!(
            fm(&big),
            Err(SkillError::FrontmatterTooLarge {
                max: MAX_FRONTMATTER_BYTES
            })
        );
        // Unterminated huge input fails fast with TooLarge.
        let huge = format!("---\n{}", "a".repeat(1 << 20));
        assert_eq!(
            parse_skill_md(&huge),
            Err(SkillError::FrontmatterTooLarge {
                max: MAX_FRONTMATTER_BYTES
            })
        );
    }

    #[test]
    fn metadata() {
        let f = fm("name: a\ndescription: b\nmetadata:\n  author: example-org\n  # c\n\n  version: \"1.0\"\nlicense: MIT\n").unwrap();
        assert_eq!(f.metadata.len(), 2);
        assert_eq!(f.metadata["author"], "example-org");
        assert_eq!(f.metadata["version"], "1.0");
        assert_eq!(f.license.as_deref(), Some("MIT"));
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n"),
            SyntaxError::EmptyValue
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n    a: b\n"),
            SyntaxError::MetadataIndentation
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n a: b\n"),
            SyntaxError::MetadataIndentation
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  a: b\n  a: c\n"),
            SyntaxError::DuplicateKey
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  a:\n    b: c\n"),
            SyntaxError::EmptyValue
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  a: b\n    c\n"),
            SyntaxError::MetadataIndentation
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  - a\n"),
            SyntaxError::Sequence
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  a: |\n    x\n"),
            SyntaxError::BlockScalarNotAllowed
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  a: *x\n"),
            SyntaxError::Alias
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  'a': x\n"),
            SyntaxError::InvalidKey
        );
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  a: 1\n"),
            SyntaxError::NonStringScalar
        );
        for k in ["1", "true", "null", "y", "1.0", "0x1f", "2026-01-01"] {
            assert_eq!(
                kind(&format!("name: a\ndescription: b\nmetadata:\n  {k}: x\n")),
                SyntaxError::NonStringScalar,
                "{k}"
            );
        }
        assert_eq!(
            kind("name: a\ndescription: b\nmetadata:\n  -: x\n"),
            SyntaxError::InvalidKey
        );
        assert!(fm("name: a\ndescription: b\nmetadata:\n  v1: x\n  x.y_z-w: x\n").is_ok());
    }

    #[test]
    fn block_scalars() {
        let f = fm("name: a\ndescription: |\n  line one\n  line two\n\n  para\n\nlicense: MIT\n")
            .unwrap();
        assert_eq!(f.description, "line one\nline two\n\npara\n");
        let f = fm("name: a\ndescription: |-\n  x\n   y\n").unwrap();
        assert_eq!(f.description, "x\n y");
        let f = fm("name: a\ndescription: |+\n  x\n\n\n").unwrap();
        assert_eq!(f.description, "x\n\n\n");
        let f = fm("name: a\ndescription: >\n  folded\n  text\n\n  next\n").unwrap();
        assert_eq!(f.description, "folded text\nnext\n");
        let f = fm("name: a\ndescription: >-\n\n  a\n  b\n").unwrap();
        assert_eq!(f.description, "\na b");
        let f = fm("name: a\ndescription: | # comment\n  # not a comment\n").unwrap();
        assert_eq!(f.description, "# not a comment\n");
        let f = fm("name: a\ndescription: |\n").unwrap();
        assert_eq!(f.description, "");
        assert_eq!(
            kind("name: a\ndescription: |2\n  x\n"),
            SyntaxError::InvalidBlockScalarHeader
        );
        assert_eq!(
            kind("name: a\ndescription: | x\n  x\n"),
            SyntaxError::InvalidBlockScalarHeader
        );
        assert_eq!(
            kind("name: a\ndescription: |# x\n  x\n"),
            SyntaxError::InvalidBlockScalarHeader
        );
        assert_eq!(
            kind("name: a\ndescription: |\n    x\n  y\n"),
            SyntaxError::BlockIndentation
        );
        assert_eq!(
            kind("name: a\ndescription: |\n     \n  y\n"),
            SyntaxError::BlockIndentation
        );
        assert_eq!(
            kind("name: a\ndescription: >\n  x\n    y\n"),
            SyntaxError::UnsupportedFolding
        );
    }

    #[test]
    fn body_may_contain_rules() {
        let d =
            parse_skill_md("---\nname: a\ndescription: b\n---\n\n# T\n\n---\n\nmore\n").unwrap();
        assert_eq!(d.body, "# T\n\n---\n\nmore\n");
    }

    #[test]
    fn debug_hides_content() {
        let d = parse_skill_md("---\nname: secretname\ndescription: secretdesc\n---\nsecretbody\n")
            .unwrap();
        let s = format!("{d:?}");
        assert!(!s.contains("secret"), "{s}");
    }
}
