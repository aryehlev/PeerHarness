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
        let mut e = std::io::stderr().lock();
        let _ = writeln!(e, "warning: {}", text.as_ref());
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
