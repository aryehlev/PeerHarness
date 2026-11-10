//! Deterministic SKILL.md rendering.

use std::collections::BTreeMap;

use crate::error::RenderError;
use crate::frontmatter::{
    forbidden_raw, parse_inline_scalar, parse_skill_md, Frontmatter, SkillDoc,
};
use crate::validate::{check_skill_bytes, validate_skill};

/// Normalizes a Markdown body the way [`parse_skill_md`] reports it: CRLF and lone CR
/// become LF, leading empty lines are removed and a final newline is ensured.
pub fn normalize_body(body: &str) -> String {
    let mut s = body.replace("\r\n", "\n").replace('\r', "\n");
    let lead = s.len() - s.trim_start_matches('\n').len();
    s.drain(..lead);
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Renders a SKILL.md with `name`, `description`, optional `metadata` and `body`.
///
/// * Deterministic: keys are emitted in the order `name`, `description`, `metadata`
///   (entries sorted by key), followed by `---`, one empty line and the
///   [`normalize_body`]-normalized body.
/// * A value is written as a plain scalar when that re-parses to exactly the same
///   string, and as a double-quoted scalar with escapes otherwise.
/// * The inputs are validated first ([`validate_skill`] without a directory name, plus
///   the whole-file size limit), and the output is re-parsed and compared before it is
///   returned, so `parse_skill_md(&render_skill_md(..)?)` always yields the same values
///   (with the body normalized).
///
/// An empty `metadata` map is the same as `None`.
pub fn render_skill_md(
    name: &str,
    description: &str,
    body: &str,
    metadata: Option<&BTreeMap<String, String>>,
) -> Result<String, RenderError> {
    let body = normalize_body(body);
    if body.trim().is_empty() {
        return Err(RenderError::BlankBody);
    }
    let expected = SkillDoc {
        frontmatter: Frontmatter {
            name: name.to_owned(),
            description: description.to_owned(),
            metadata: metadata.cloned().unwrap_or_default(),
            ..Default::default()
        },
        body,
    };
    validate_skill(&expected, None).map_err(RenderError::Invalid)?;

    let mut out = String::with_capacity(expected.body.len() + 256);
    out.push_str("---\nname: ");
    out.push_str(&scalar(name));
    out.push_str("\ndescription: ");
    out.push_str(&scalar(description));
    out.push('\n');
    if !expected.frontmatter.metadata.is_empty() {
        out.push_str("metadata:\n");
        for (k, v) in &expected.frontmatter.metadata {
            out.push_str("  ");
            out.push_str(k);
            out.push_str(": ");
            out.push_str(&scalar(v));
            out.push('\n');
        }
    }
    out.push_str("---\n\n");
    out.push_str(&expected.body);

    check_skill_bytes(out.as_bytes()).map_err(|e| RenderError::Invalid(vec![e]))?;
    let reparsed = parse_skill_md(&out).map_err(RenderError::Reparse)?;
    if reparsed != expected {
        // Unreachable by construction; never return text that reads back differently.
        return Err(RenderError::Mismatch);
    }
    Ok(out)
}

/// The YAML scalar for `s`: plain when that round-trips, otherwise double-quoted.
pub(crate) fn scalar(s: &str) -> String {
    if is_safe_plain(s) {
        s.to_owned()
    } else {
        double_quote(s)
    }
}

fn is_safe_plain(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(' ')
        && s.chars().all(|c| c != '\n' && forbidden_raw(c).is_none())
        && parse_inline_scalar(s).as_deref() == Ok(s)
}

fn double_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c if forbidden_raw(c).is_some() => {
                let v = c as u32;
                if v <= 0xff {
                    out.push_str(&format!("\\x{v:02X}"));
                } else if v <= 0xffff {
                    out.push_str(&format!("\\u{v:04X}"));
                } else {
                    out.push_str(&format!("\\U{v:08X}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_quoted() {
        assert_eq!(scalar("pnpm"), "pnpm");
        assert_eq!(scalar("Use pnpm, not npm."), "Use pnpm, not npm.");
        assert_eq!(scalar("true"), "\"true\"");
        assert_eq!(scalar("1.0"), "\"1.0\"");
        assert_eq!(scalar("a: b"), "\"a: b\"");
        assert_eq!(scalar("x #y"), "\"x #y\"");
        assert_eq!(scalar("'q'"), "\"'q'\"");
        assert_eq!(
            scalar("line\nbreak\t\"q\"\\"),
            "\"line\\nbreak\\t\\\"q\\\"\\\\\""
        );
        assert_eq!(scalar(" lead"), "\" lead\"");
        assert_eq!(scalar("trail "), "\"trail \"");
        assert_eq!(scalar("&x"), "\"&x\"");
        assert_eq!(scalar(""), "\"\"");
        assert_eq!(scalar("\u{2028}"), "\"\\u2028\"");
    }

    #[test]
    fn render_example() {
        let s = render_skill_md(
            "pnpm-repository-convention",
            "Use pnpm when installing packages or running package scripts in the specified repository.",
            "When working in this repository, use pnpm.\n",
            None,
        )
        .unwrap();
        assert_eq!(
            s,
            "---\nname: pnpm-repository-convention\ndescription: Use pnpm when installing packages or running package scripts in the specified repository.\n---\n\nWhen working in this repository, use pnpm.\n"
        );
        let mut m = BTreeMap::new();
        m.insert("version".to_owned(), "1.0".to_owned());
        m.insert("author".to_owned(), "me".to_owned());
        let s = render_skill_md("a", "d: x", "\r\n\r\nbody", Some(&m)).unwrap();
        assert_eq!(
            s,
            "---\nname: a\ndescription: \"d: x\"\nmetadata:\n  author: me\n  version: \"1.0\"\n---\n\nbody\n"
        );
    }

    #[test]
    fn render_rejects_invalid() {
        assert!(matches!(
            render_skill_md("Bad", "d", "b", None),
            Err(RenderError::Invalid(_))
        ));
        assert!(matches!(
            render_skill_md("a", "", "b", None),
            Err(RenderError::Invalid(_))
        ));
        assert!(matches!(
            render_skill_md("a", "d", " \n\n", None),
            Err(RenderError::BlankBody)
        ));
        assert!(matches!(
            render_skill_md("a", "d", &"x".repeat(300 * 1024), None),
            Err(RenderError::Invalid(_))
        ));
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_body("\n\na\r\nb\rc"), "a\nb\nc\n");
        assert_eq!(normalize_body("x\n"), "x\n");
    }
}
