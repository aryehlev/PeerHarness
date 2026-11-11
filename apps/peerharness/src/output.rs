//! Human and `--json` output.
//!
//! Every command returns a [`Report`]: a JSON value (printed with `--json`) and concise
//! human text (printed otherwise). Progress notes, previews and prompts go through
//! [`Output::note`]: to stdout in human mode, to stderr in `--json` mode so stdout stays
//! a single JSON document.

use std::fmt::Write as _;
use std::io::Write as _;

use serde_json::Value;

/// How to print.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub json: bool,
}

/// A warning on standard error, for code that has no [`Output`] at hand. `--json` does
/// not hide it: it is not part of the report.
pub fn warn(text: impl AsRef<str>) {
    let mut e = std::io::stderr().lock();
    let _ = writeln!(e, "warning: {}", text.as_ref());
}

impl Output {
    /// A human-facing note, preview or progress line.
    pub fn note(&self, text: impl AsRef<str>) {
        let text = text.as_ref();
        if self.json {
            let mut e = std::io::stderr().lock();
            let _ = writeln!(e, "{text}");
        } else {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{text}");
            let _ = o.flush();
        }
    }

    /// A warning, always on stderr.
    pub fn warn(&self, text: impl AsRef<str>) {
        warn(text);
    }

    /// Prints the final report.
    pub fn print_report(&self, report: &Report) {
        let mut o = std::io::stdout().lock();
        if self.json {
            let s = serde_json::to_string_pretty(&report.json).unwrap_or_else(|_| "{}".into());
            let _ = writeln!(o, "{s}");
        } else if !report.text.is_empty() {
            let t = report.text.trim_end_matches('\n');
            let _ = writeln!(o, "{t}");
        }
        let _ = o.flush();
    }

    /// Prints an error (JSON object on stdout with `--json`, text on stderr otherwise).
    pub fn print_error(&self, kind: &str, code: i32, message: &str) {
        if self.json {
            let v = serde_json::json!({
                "error": { "kind": kind, "exit_code": code, "message": message }
            });
            let mut o = std::io::stdout().lock();
            let _ = writeln!(
                o,
                "{}",
                serde_json::to_string_pretty(&v).unwrap_or_default()
            );
        } else {
            let mut e = std::io::stderr().lock();
            let _ = writeln!(e, "error: {message}");
        }
    }
}

/// A command result.
#[derive(Debug, Default)]
pub struct Report {
    pub json: Value,
    pub text: String,
    /// A non-zero exit after printing the report (for example `doctor` failures).
    pub exit: Option<crate::error::ExitKind>,
}

impl Report {
    pub fn new(json: Value, text: impl Into<String>) -> Self {
        Self {
            json,
            text: text.into(),
            exit: None,
        }
    }
}

/// A small builder for multi-line human text.
#[derive(Default)]
pub struct Text(String);

impl Text {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn line(&mut self, s: impl AsRef<str>) -> &mut Self {
        let _ = writeln!(self.0, "{}", s.as_ref());
        self
    }

    pub fn kv(&mut self, k: &str, v: impl std::fmt::Display) -> &mut Self {
        let _ = writeln!(self.0, "  {k:<18} {v}");
        self
    }

    pub fn finish(self) -> String {
        self.0
    }
}

/// Shortens a `sha256:<hex>` id for display (`sha256:0123abcd…`).
pub fn short_id(id: &impl std::fmt::Display) -> String {
    let s = id.to_string();
    match s.strip_prefix("sha256:") {
        Some(hex) if hex.len() > 12 => format!("sha256:{}", &hex[..12]),
        _ => s,
    }
}

/// Untrusted or local text made safe for a terminal (control, bidi and invisible
/// characters removed).
pub fn safe(s: &str) -> String {
    ph_skills::sanitize_for_display(s)
}

/// Text a member wrote, for showing among PeerHarness's own lines: made safe for a
/// terminal ([`safe`]), and every line of it begins with `prefix`. A reason, a summary
/// or a rule's text can hold several lines, and without the mark one of them could pass
/// for a heading, a scanner line or a ballot's last sentence.
pub fn quoted(text: &str, prefix: &str) -> String {
    safe(text)
        .trim_end()
        .split('\n')
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The mark in front of a line that a member wrote, in a listing.
pub const MEMBERS_WORDS: &str = "        | ";

/// Text a member wrote, placed inside one of PeerHarness's own lines: a question in a
/// listing, a reason after a name. It is made safe for a terminal ([`safe`]), and every
/// line after the first begins with `prefix`. The first line stands where the caller
/// puts it. Without the mark, a second line of the text could pass for the next row of
/// the listing: another question, another member's answer, a proposal that waits
/// (ADR-051).
pub fn continued(text: &str, prefix: &str) -> String {
    safe(text)
        .trim_end()
        .split('\n')
        .collect::<Vec<_>>()
        .join(&format!("\n{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_of_a_members_text_carries_the_mark() {
        assert_eq!(quoted("too strict", "    | "), "    | too strict");
        // Lines that imitate what `proposal show` and a ballot's preview print.
        let forged = "ok\n\n  rule text (12 bytes, 0 scanner finding(s)):\r\n---\nname: harmless\n\
                      ---\n  scanner, line 3: nothing found\nAn approval cannot be withdrawn.\n\n";
        let shown = quoted(forged, "      | ");
        assert_eq!(shown.lines().count(), 8);
        assert!(shown.lines().all(|l| l.starts_with("      | ")), "{shown}");
        assert!(shown.contains("      | An approval cannot be withdrawn."));
        // Characters that break a line or move the cursor without being a line feed do
        // not start an unmarked line: they are shown as what they are.
        let shown = quoted("a\rb\u{2028}c\u{2029}d\u{1b}[2Ke\u{85}f\u{b}g\u{c}h", "| ");
        assert_eq!(shown.lines().count(), 1, "{shown:?}");
        assert!(shown.starts_with("| a<U+000D>b<U+2028>c<U+2029>d<U+001B>[2Ke<U+0085>f"));
        assert!(!shown.contains(['\r', '\u{1b}', '\u{2028}', '\u{2029}', '\u{85}']));
    }
}
