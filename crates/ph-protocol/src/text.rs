//! Bounds and character rules for free-text fields received from peers.
//!
//! Lengths are counted in Unicode scalar values (code points). Besides length, every
//! text field rejects characters that can manipulate a terminal or hide content when
//! the text is shown to a human:
//!
//! * C0 controls (U+0000-U+001F) except, in multi-line fields, `\t`, `\n` and `\r`
//! * DEL (U+007F) and C1 controls (U+0080-U+009F)
//! * every Unicode bidirectional formatting character: the overrides and embeddings
//!   (U+202A-U+202E), the isolates (U+2066-U+2069) and the implicit marks (U+061C,
//!   U+200E, U+200F)
//! * in single-line fields also the line and paragraph separators U+2028 / U+2029, which
//!   many renderers display as line breaks

use crate::error::ProtocolError;

/// Whether a field may span lines.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lines {
    /// No `\t`, `\n`, `\r`, U+2028 or U+2029.
    Single,
    /// `\t`, `\n` and `\r` allowed.
    Multi,
}

/// Whether `c` is forbidden in a text field.
pub fn is_forbidden_char(c: char, lines: Lines) -> bool {
    match c {
        '\t' | '\n' | '\r' | '\u{2028}' | '\u{2029}' => lines == Lines::Single,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => true,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => true,
        '\u{061c}' | '\u{200e}' | '\u{200f}' => true,
        _ => false,
    }
}

/// Checks a text field: `min_chars..=max_chars` code points and no forbidden
/// characters. The error names only `field`.
pub fn check_text(
    field: &'static str,
    s: &str,
    min_chars: usize,
    max_chars: usize,
    lines: Lines,
) -> Result<(), ProtocolError> {
    // Cheap byte bound first: a code point is at most 4 bytes.
    if s.len() > max_chars.saturating_mul(4) {
        return Err(ProtocolError::field(field, "too long"));
    }
    let mut n = 0usize;
    for c in s.chars() {
        n += 1;
        if is_forbidden_char(c, lines) {
            return Err(ProtocolError::field(field, "forbidden control character"));
        }
    }
    if n > max_chars {
        return Err(ProtocolError::field(field, "too long"));
    }
    if n < min_chars {
        return Err(ProtocolError::field(field, "too short"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(check_text("f", "hello", 1, 5, Lines::Single).is_ok());
        assert!(check_text("f", "hello!", 1, 5, Lines::Single).is_err());
        assert!(check_text("f", "", 1, 5, Lines::Single).is_err());
        assert!(check_text("f", "", 0, 5, Lines::Single).is_ok());
        assert!(check_text("f", "€€€€€", 1, 5, Lines::Single).is_ok());
        assert!(check_text("f", "a\nb", 1, 5, Lines::Single).is_err());
        assert!(check_text("f", "a\nb\tc", 1, 9, Lines::Multi).is_ok());
        for bad in [
            "\u{1b}[31m",
            "a\u{0}",
            "\u{7f}",
            "\u{85}",
            "\u{202e}abc",
            "\u{2066}",
            "\u{2069}",
            "a\u{200e}b",
            "a\u{200f}b",
            "a\u{61c}b",
        ] {
            assert!(
                check_text("f", bad, 0, 50, Lines::Multi).is_err(),
                "{bad:?}"
            );
        }
        for sep in ["a\u{2028}b", "a\u{2029}b"] {
            assert!(check_text("f", sep, 0, 50, Lines::Single).is_err());
            assert!(check_text("f", sep, 0, 50, Lines::Multi).is_ok());
        }
        // ordinary non-ASCII text, emoji with ZWJ, and RTL letters are fine
        assert!(check_text("f", "שלום world 👩\u{200d}💻 café", 1, 50, Lines::Single).is_ok());
        let e = check_text("question", "\u{1b}SECRET", 0, 50, Lines::Multi).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }
}
