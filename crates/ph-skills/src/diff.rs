//! Unified diffs and terminal-safe display of untrusted skill text.

use std::time::Duration;

use similar::TextDiff;

use crate::scanner::is_hidden_char;

/// Makes untrusted text safe to print in a terminal: CRLF becomes LF; `\n` and `\t` are
/// kept; every other control character (C0, DEL, C1 including ESC and lone CR) and every
/// invisible or bidi-control character is replaced by a visible `<U+XXXX>` marker, so it
/// can neither rewrite the terminal nor hide content.
pub fn sanitize_for_display(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let control = c.is_control() && c != '\n' && c != '\t';
        if control || is_hidden_char(c) {
            out.push_str(&format!("<U+{:04X}>", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// A unified diff (3 lines of context, `---`/`+++` headers with the given labels) between
/// `old` and `new`, for showing a human what an install or update changes. Both texts
/// and labels pass through [`sanitize_for_display`] first. Returns an empty string when
/// the texts are identical. Diff computation is bounded by a 2 second deadline, after
/// which `similar` falls back to a coarser (still correct) diff.
pub fn unified_diff(old: &str, new: &str, old_label: &str, new_label: &str) -> String {
    let old = sanitize_for_display(old);
    let new = sanitize_for_display(new);
    let old_label = sanitize_for_display(old_label).replace('\n', " ");
    let new_label = sanitize_for_display(new_label).replace('\n', " ");
    let diff = TextDiff::configure()
        .timeout(Duration::from_secs(2))
        .diff_lines(old.as_str(), new.as_str());
    diff.unified_diff()
        .context_radius(3)
        .header(&old_label, &new_label)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_basic() {
        let d = unified_diff("a\nb\nc\n", "a\nB\nc\n", "installed", "proposed");
        assert_eq!(
            d,
            "--- installed\n+++ proposed\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
        );
        assert_eq!(unified_diff("same\n", "same\n", "x", "y"), "");
        let d = unified_diff("", "new\n", "/dev/null", "SKILL.md");
        assert!(d.contains("+new"));
    }

    #[test]
    fn sanitizes() {
        assert_eq!(
            sanitize_for_display("a\u{1b}[31mb\r\nc\rd\u{202e}e\tf"),
            "a<U+001B>[31mb\nc<U+000D>d<U+202E>e\tf"
        );
        let d = unified_diff("x\n", "\u{1b}]0;pwned\u{7}\n", "a\u{1b}", "b\nc");
        assert!(!d.contains('\u{1b}'));
        assert!(d.starts_with("--- a<U+001B>\n+++ b c\n"));
    }
}
