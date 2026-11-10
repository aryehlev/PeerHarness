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
//! * invisible format characters that can hide or split text: the zero-width space,
//!   non-joiner and joiner (U+200B-U+200D), the word joiner (U+2060), the zero-width
//!   no-break space / byte order mark (U+FEFF), the Mongolian vowel separator (U+180E)
//!   and the tag characters (U+E0000-U+E007F). This also rejects emoji ZWJ sequences
//!   such as `👩\u{200D}💻`; the individual emoji are fine.
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
        '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}' | '\u{180e}' => true,
        '\u{e0000}'..='\u{e007f}' => true,
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
            "a\u{200b}b",
            "a\u{200c}b",
            "a\u{200d}b",
            "a\u{2060}b",
            "\u{feff}abc",
            "a\u{180e}b",
            "a\u{e0001}b",
            "a\u{e0041}b",
            "a\u{e007f}b",
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
        // ordinary non-ASCII text, emoji (including variation selectors) and RTL letters
        // are fine; emoji ZWJ sequences are not (U+200D is a zero-width joiner)
        assert!(check_text("f", "שלום world 👩 💻 ❤\u{fe0f} café", 1, 50, Lines::Single).is_ok());
        assert!(check_text("f", "👩\u{200d}💻", 1, 50, Lines::Single).is_err());
        // neighbours of the forbidden ranges stay allowed
        for ok in [
            "\u{180d}",
            "\u{180f}",
            "\u{2061}",
            "\u{dffff}",
            "\u{e0080}",
            "\u{e0100}",
        ] {
            assert!(check_text("f", ok, 0, 50, Lines::Multi).is_ok(), "{ok:?}");
        }
        let e = check_text("question", "\u{1b}SECRET", 0, 50, Lines::Multi).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }
}
