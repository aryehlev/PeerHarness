//! POSIX shell quoting and a deliberately strict word splitter used only to recognise
//! hook commands that PeerHarness generated.

/// Quotes `s` as a single POSIX shell word: `'...'`, with each `'` written as `'\''`.
///
/// Inside single quotes the shell interprets nothing, so this is correct for every
/// string that contains no NUL byte.
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Splits a command line into words, honouring single quotes, double quotes and
/// backslash escapes.
///
/// Returns `None` for anything that is not a plain sequence of literal words: an
/// unterminated quote, or any unquoted shell metacharacter (operators, redirections,
/// expansions, globs, comments, `~`, braces, newlines) or `$`/backtick inside double
/// quotes. Commands we generate never contain those, so a `None` simply means "not ours"
/// and the entry is left untouched.
pub(crate) fn split_words(s: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        ch => cur.push(ch),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            n @ ('$' | '`' | '"' | '\\') => cur.push(n),
                            '\n' => {}
                            other => {
                                cur.push('\\');
                                cur.push(other);
                            }
                        },
                        '$' | '`' => return None,
                        ch => cur.push(ch),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next()? {
                    '\n' => {}
                    n => cur.push(n),
                }
            }
            ';' | '&' | '|' | '<' | '>' | '(' | ')' | '$' | '`' | '\n' | '\r' | '*' | '?' | '['
            | ']' | '#' | '~' | '{' | '}' | '!' => return None,
            ch => {
                in_word = true;
                cur.push(ch);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_round_trips_through_split() {
        for s in [
            "",
            "plain",
            "with space",
            "it's",
            "'''",
            "a'b\"c\\d$e`f",
            "/tmp/we ird/'x'/pe$erharness",
            "tab\there",
            "new\nline",
            "ünïcödé 😀",
        ] {
            let q = quote(s);
            assert_eq!(split_words(&q), Some(vec![s.to_owned()]), "{s:?}");
        }
    }

    #[test]
    fn split_basic() {
        assert_eq!(
            split_words("a  'b c'\td\"e f\"g"),
            Some(vec!["a".into(), "b c".into(), "de fg".into()])
        );
        assert_eq!(split_words(r"a\ b"), Some(vec!["a b".into()]));
        assert_eq!(split_words(""), Some(vec![]));
        assert_eq!(split_words("   "), Some(vec![]));
        assert_eq!(split_words("x=''"), Some(vec!["x=".into()]));
    }

    #[test]
    fn split_rejects_metacharacters_and_unterminated() {
        for s in [
            "a; b",
            "a && b",
            "a | b",
            "a > f",
            "$(x)",
            "`x`",
            "\"$HOME\"",
            "'unterminated",
            "\"unterminated",
            "trailing\\",
            "~/bin/x",
            "a # comment",
            "a\nb",
            "*",
            "{a,b}",
        ] {
            assert_eq!(split_words(s), None, "{s:?}");
        }
    }
}
