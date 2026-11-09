//! Name validation shared across crates.

/// Maximum length of an Agent Skills `name`.
pub const MAX_SKILL_NAME_LEN: usize = 64;

/// Whether `name` is a valid Agent Skills skill name (architecture section 11):
/// 1-64 characters of `[a-z0-9-]`, with no leading, trailing or consecutive hyphens.
pub fn is_valid_skill_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_SKILL_NAME_LEN
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
        && !name.contains("--")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_names() {
        for ok in [
            "a",
            "pnpm",
            "pnpm-repository-convention",
            "x1-2y",
            &"a".repeat(64),
        ] {
            assert!(is_valid_skill_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "a--b",
            "A",
            "a_b",
            "a.b",
            "a b",
            "../x",
            "ä",
            &"a".repeat(65),
        ] {
            assert!(!is_valid_skill_name(bad), "{bad}");
        }
    }
}
