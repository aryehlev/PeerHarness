//! Heuristic secret and home-path redaction (architecture section 13).
//!
//! [`redact`] runs on every observation before storage and on every human-approved text
//! before the sharing preview. It replaces likely secrets with [`REDACTED`] and rewrites
//! absolute home-directory prefixes to `~/`.
//!
//! Detected secret shapes:
//!
//! * PEM / PGP private key blocks (also a truncated block with no `END` line)
//! * Anthropic (`sk-ant-...`) and OpenAI-style (`sk-...`, `sk-proj-...`) API keys
//! * AWS access key ids (`AKIA...`, `ASIA...` and related prefixes)
//! * GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
//! * GitLab (`glpat-`), Hugging Face (`hf_`), npm (`npm_`), Google API (`AIza...`) and
//!   Stripe (`sk_live_`, `rk_test_`, ...) tokens
//! * Slack tokens (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-`, `xoxe-`)
//! * JWTs (`eyJ....eyJ....sig`)
//! * `Bearer <token>` and `Authorization: Basic <credentials>` (the scheme is kept)
//! * passwords in URLs (`scheme://user:<password>@host`, the user and host are kept)
//! * generic assignments such as `api_key=...`, `token: ...`, `password = "..."`,
//!   `GITHUB_TOKEN=...`, `AWS_SECRET_ACCESS_KEY=...` (the key is kept, the value replaced)
//! * long high-entropy runs: hex of at least 32 chars mixing digits and letters (this
//!   includes git commit SHAs), or base64/base64url of at least 32 chars mixing upper
//!   case, lower case and digits whose character classes change often (random-looking).
//!   CamelCase identifiers and paths with ordinary lowercase directory names are kept.
//!
//! Redaction is heuristic. It can miss secrets and can redact harmless text; it is a
//! safety net under the exact human preview, not a guarantee.

use std::sync::LazyLock;

use regex::{Captures, Regex};

/// The replacement marker for redacted secrets.
pub const REDACTED: &str = "[REDACTED]";

/// Result of [`redact`].
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted {
    /// The redacted text.
    pub text: String,
    /// Number of secret findings that were replaced.
    pub findings_count: usize,
    /// Number of absolute home-directory prefixes rewritten to `~`.
    pub paths_stripped: usize,
}

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redacted")
            .field("text_len", &self.text.len())
            .field("findings_count", &self.findings_count)
            .field("paths_stripped", &self.paths_stripped)
            .finish()
    }
}

#[derive(Clone, Copy)]
enum Action {
    /// Replace the whole match.
    Whole,
    /// Keep capture group 1 (and group 3 if present), replace group 2 (skipped if
    /// already redacted).
    KeepPrefix,
    /// Replace the whole match only if it looks high-entropy.
    HighEntropy,
}

struct Rule {
    re: Regex,
    action: Action,
}

const SECRET_PATTERNS: &[(&str, Action)] = &[
    (
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
        Action::Whole,
    ),
    (
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*",
        Action::Whole,
    ),
    (r"\bsk-ant-[A-Za-z0-9_\-]{8,}", Action::Whole),
    (r"\bsk-[A-Za-z0-9_\-]{16,}", Action::Whole),
    (
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b",
        Action::Whole,
    ),
    (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}", Action::Whole),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}", Action::Whole),
    (r"\bglpat-[A-Za-z0-9_\-]{20,}", Action::Whole),
    (r"\bhf_[A-Za-z0-9]{30,}", Action::Whole),
    (r"\bnpm_[A-Za-z0-9]{36,}", Action::Whole),
    (r"\bAIza[0-9A-Za-z_\-]{35}", Action::Whole),
    (r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{10,}", Action::Whole),
    (r"\bxox[abprse]-[A-Za-z0-9\-]{10,}", Action::Whole),
    (
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*",
        Action::Whole,
    ),
    (
        r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=\-]{8,})",
        Action::KeepPrefix,
    ),
    (
        r"(?i)(\bauthorization\s*:\s*basic\s+)([A-Za-z0-9+/=]{4,})",
        Action::KeepPrefix,
    ),
    (
        r"(?i)(\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:)([^\s/@]+)(@)",
        Action::KeepPrefix,
    ),
    (
        r#"(?i)(\b(?:[a-z0-9]+[_\-])*(?:api[_\-]?key|apikey|secret|access[_\-]?key|private[_\-]?key|token|password|passwd|passphrase|pwd|credentials?)(?:[_\-][a-z0-9]+)*["']?\s*[:=]\s*["']?)([^\s"'`,;]{3,})"#,
        Action::KeepPrefix,
    ),
    (r"[A-Za-z0-9+/_\-]{32,}={0,2}", Action::HighEntropy),
];

/// Minimum share of adjacent character pairs that switch class (lower / upper / digit /
/// other) for a mixed-case run to count as random. Random base64 of 32+ chars sits
/// around 0.6 (below 0.35 in fewer than 0.3% of cases); camelCase identifiers such as
/// `getUserById2FactorAuthenticationHandler` sit around 0.3.
const MIN_CLASS_TRANSITION_RATE: f64 = 0.35;

static SECRET_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    SECRET_PATTERNS
        .iter()
        .filter_map(|(p, action)| {
            Regex::new(p).ok().map(|re| Rule {
                re,
                action: *action,
            })
        })
        .collect()
});

static UNIX_HOME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(^|[\s"'=(\[{<,;:])(?:/Users|/home)/[A-Za-z0-9._\-]+(/|\b)"#).ok()
});

static WINDOWS_HOME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)(^|[\s"'=(\[{<,;])[a-z]:\\Users\\[^\\\s"'<>|]+(\\|\b)"#).ok()
});

fn char_class(b: u8) -> u8 {
    if b.is_ascii_lowercase() {
        0
    } else if b.is_ascii_uppercase() {
        1
    } else if b.is_ascii_digit() {
        2
    } else {
        3
    }
}

/// Share of adjacent byte pairs whose character class differs.
fn class_transition_rate(s: &str) -> f64 {
    let b = s.as_bytes();
    if b.len() < 2 {
        return 0.0;
    }
    let changes = b
        .windows(2)
        .filter(|w| matches!(w, [x, y] if char_class(*x) != char_class(*y)))
        .count();
    changes as f64 / (b.len() - 1) as f64
}

fn looks_high_entropy(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    let is_hex = body.bytes().all(|b| b.is_ascii_hexdigit());
    let has_digit = body.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = body.bytes().any(|b| b.is_ascii_alphabetic());
    if is_hex {
        return has_digit && has_alpha;
    }
    let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
    if !(has_upper && has_lower && has_digit) {
        return false;
    }
    // A filesystem path has ordinary lowercase directory names ("src", "components");
    // a random base64 string almost never contains a 3+ letter all-lowercase segment.
    if body.contains('/')
        && body
            .split('/')
            .any(|seg| seg.len() >= 3 && seg.bytes().all(|b| b.is_ascii_lowercase()))
    {
        return false;
    }
    class_transition_rate(body) >= MIN_CLASS_TRANSITION_RATE
}

/// Redacts likely secrets and strips absolute home-directory prefixes.
///
/// Never panics, and never logs its input.
pub fn redact(text: &str) -> Redacted {
    let mut out = text.to_owned();
    let mut findings = 0usize;

    for rule in SECRET_RULES.iter() {
        let replaced = rule.re.replace_all(&out, |c: &Captures<'_>| {
            let whole = c.get(0).map(|m| m.as_str()).unwrap_or_default();
            match rule.action {
                Action::Whole => {
                    findings += 1;
                    REDACTED.to_owned()
                }
                Action::KeepPrefix => {
                    let prefix = c.get(1).map(|m| m.as_str()).unwrap_or_default();
                    let value = c.get(2).map(|m| m.as_str()).unwrap_or_default();
                    let suffix = c.get(3).map(|m| m.as_str()).unwrap_or_default();
                    if value.starts_with("[REDACTED") {
                        whole.to_owned()
                    } else {
                        findings += 1;
                        format!("{prefix}{REDACTED}{suffix}")
                    }
                }
                Action::HighEntropy => {
                    if looks_high_entropy(whole) {
                        findings += 1;
                        REDACTED.to_owned()
                    } else {
                        whole.to_owned()
                    }
                }
            }
        });
        if let std::borrow::Cow::Owned(s) = replaced {
            out = s;
        }
    }

    let mut paths = 0usize;
    for re in [&*UNIX_HOME, &*WINDOWS_HOME].into_iter().flatten() {
        let replaced = re.replace_all(&out, |c: &Captures<'_>| {
            paths += 1;
            let lead = c.get(1).map(|m| m.as_str()).unwrap_or_default();
            let sep = c.get(2).map(|m| m.as_str()).unwrap_or_default();
            if sep.is_empty() {
                format!("{lead}~")
            } else {
                format!("{lead}~/")
            }
        });
        if let std::borrow::Cow::Owned(s) = replaced {
            out = s;
        }
    }

    Redacted {
        text: out,
        findings_count: findings,
        paths_stripped: paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> String {
        redact(s).text
    }

    #[test]
    fn all_patterns_compile() {
        assert_eq!(SECRET_RULES.len(), SECRET_PATTERNS.len());
        assert!(UNIX_HOME.is_some());
        assert!(WINDOWS_HOME.is_some());
    }

    #[test]
    fn provider_tokens() {
        let cases = [
            "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE-FAKE_FAKE",
            "sk-proj-FAKEfake1234FAKEfake5678",
            "sk-FAKEfake1234FAKEfake5678abcd",
            "AKIAFAKEFAKEFAKEFAKE",
            "ASIAABCDEFGHIJKLMNOP",
            "ghp_FAKEfakeFAKEfakeFAKEfake1234",
            "gho_FAKEfakeFAKEfakeFAKEfake1234",
            "github_pat_11FAKEFAKE0_fakefakefakefakefake",
            "xoxb-1234567890-FAKEFAKEFAKE",
            "xoxp-1234567890-fakefake",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.FAKEsignatureFAKE",
        ];
        for tok in cases {
            let text = format!("please use {tok} for this");
            let out = redact(&text);
            assert!(!out.text.contains(tok), "leaked {tok}: {}", out.text);
            assert!(out.text.contains(REDACTED));
            assert!(out.text.starts_with("please use "));
            assert!(out.text.ends_with(" for this"));
            assert!(out.findings_count >= 1);
        }
    }

    #[test]
    fn more_token_families() {
        let cases = [
            "sk_live_51HFAKEfakeFAKEfake1234567890",
            "rk_test_FAKEfake1234FAKEfake",
            "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKE12345",
            "glpat-FAKEfakeFAKEfake1234",
            "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake1234",
            "hf_FAKEfakeFAKEfakeFAKEfakeFAKEfake",
        ];
        for tok in cases {
            let out = redact(&format!("token {tok} here"));
            assert!(!out.text.contains(tok), "leaked {tok}");
            assert_eq!(out.text, "token [REDACTED] here");
        }
        assert_eq!(
            r("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "AWS_SECRET_ACCESS_KEY=[REDACTED]"
        );
        assert_eq!(
            r("aws_secret_access_key: \"abcDEF123/xyz\""),
            "aws_secret_access_key: \"[REDACTED]\""
        );
        assert_eq!(
            r("Authorization: Basic dXNlcjpwYXNzd29yZA=="),
            "Authorization: Basic [REDACTED]"
        );
        assert_eq!(
            r("git clone https://alice:hunter2pass@example.com/repo.git"),
            "git clone https://alice:[REDACTED]@example.com/repo.git"
        );
        assert_eq!(
            r("postgres://admin:s3cretPW@db.internal:5432/app"),
            "postgres://admin:[REDACTED]@db.internal:5432/app"
        );
        let pgp =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----";
        assert_eq!(r(pgp), "[REDACTED]");
    }

    #[test]
    fn ordinary_developer_prose_is_kept() {
        for keep in [
            "The tokenizer splits text into tokens; max_tokens is 1000.",
            "Please use React18ComponentFactory and the useEffect hook.",
            "Use the getUserById2FactorAuthenticationHandler function.",
            "see src/components/AuthenticationProviderWrapper2/index.tsx",
            "Run pnpm install, then pnpm test --filter @acme/web-app2024.",
            "The password policy requires 12 characters.",
            "Bearer tokens must be validated by the gateway.",
            "sk-learn is a python library",
            "task-management-dashboard-component",
            "Open http://localhost:3000/login and sign in.",
            "XMLHttpRequest2ResponseHandlerFactory is deprecated.",
            "IPv6AddressResolverConfig2025Builder",
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            let out = redact(keep);
            assert_eq!(out.text, keep);
            assert_eq!(out.findings_count, 0, "{keep}");
        }
    }

    /// Random base64 / base64url / alphanumeric secrets of realistic lengths are caught
    /// by the high-entropy fallback with overwhelming probability. Deterministic PRNG so
    /// the test is not flaky.
    #[test]
    fn random_secrets_caught_by_entropy_rule() {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut missed = 0;
        let total = 2000;
        for i in 0..total {
            let len = 32 + (i % 33);
            let tok: String = (0..len)
                .map(|_| char::from(B64[(next() % 64) as usize]))
                .collect();
            let out = redact(&format!("key {tok} end"));
            if out.text.contains(&tok) {
                missed += 1;
            }
        }
        // Expected miss rate is well under 1% (mostly tokens without a digit).
        assert!(missed * 100 < total, "missed {missed} of {total}");
    }

    #[test]
    fn anthropic_key_counted_once() {
        let out = redact("key sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE end");
        assert_eq!(out.text, "key [REDACTED] end");
        assert_eq!(out.findings_count, 1);
    }

    #[test]
    fn assignments_keep_key() {
        assert_eq!(r("api_key=abcd1234"), "api_key=[REDACTED]");
        assert_eq!(r("API-KEY: hunter22"), "API-KEY: [REDACTED]");
        assert_eq!(r("token: s3cr3tvalue"), "token: [REDACTED]");
        assert_eq!(r("password = \"hunter2\""), "password = \"[REDACTED]\"");
        assert_eq!(
            r("export GITHUB_TOKEN=abc123xyz"),
            "export GITHUB_TOKEN=[REDACTED]"
        );
        assert_eq!(
            r(r#"{"client_secret": "zzz999"}"#),
            r#"{"client_secret": "[REDACTED]"}"#
        );
        assert_eq!(r("passwd=x1y2z3"), "passwd=[REDACTED]");
        // nested: token value already caught by a provider rule is not double counted
        let out = redact("api_key=sk-ant-api03-FAKEFAKEFAKEFAKE");
        assert_eq!(out.text, "api_key=[REDACTED]");
        assert_eq!(out.findings_count, 1);
    }

    #[test]
    fn bearer() {
        assert_eq!(
            r("Authorization: Bearer abc.def-ghi_jkl"),
            "Authorization: Bearer [REDACTED]"
        );
        assert_eq!(r("bearer   ZZZZZZZZZZZZ"), "bearer   [REDACTED]");
    }

    #[test]
    fn pem_blocks() {
        let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEFAKE\nFAKE==\n-----END RSA PRIVATE KEY-----\nafter";
        assert_eq!(r(pem), "before\n[REDACTED]\nafter");
        let open = "x -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk";
        assert_eq!(r(open), "x [REDACTED]");
        let pk = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----";
        assert_eq!(r(pk), "[REDACTED]");
    }

    #[test]
    fn high_entropy() {
        let hex = "deadbeef0123456789abcdef0123456789abcdef";
        assert_eq!(r(&format!("sha {hex} x")), "sha [REDACTED] x");
        let b64 = "Zm9vYmFyYmF6cXV4UXV1eDEyMzQ1Njc4OTBhYmNkZWY=";
        assert_eq!(r(&format!("blob {b64}")), "blob [REDACTED]");
        // not secrets
        for keep in [
            "abcdefghijklmnopqrstuvwxyzabcdefghij",
            "SomeVeryLongJavaClassNameFactoryBean",
            "src/components/Button2/IndexFileList/More",
            "0000000000000000000000000000000000000000",
            "We use pnpm, not npm, for this repo.",
        ] {
            assert_eq!(r(keep), keep);
        }
    }

    #[test]
    fn home_paths() {
        assert_eq!(r("/Users/alice/proj/x.rs"), "~/proj/x.rs");
        assert_eq!(r("see /home/bob/src now"), "see ~/src now");
        assert_eq!(r("cd /home/bob"), "cd ~");
        assert_eq!(r(r"C:\Users\carol\repo"), r"~/repo");
        assert_eq!(r("PATH=/Users/a/bin:/home/b/bin"), "PATH=~/bin:~/bin");
        assert_eq!(
            r("https://example.com/home/page/"),
            "https://example.com/home/page/"
        );
        let out = redact("/Users/alice/x and /home/bob/y");
        assert_eq!(out.paths_stripped, 2);
        assert_eq!(out.findings_count, 0);
    }

    #[test]
    fn clean_text_untouched_and_debug_hides_text() {
        let s = "This repository uses pnpm, not npm. Run pnpm install.";
        let out = redact(s);
        assert_eq!(out.text, s);
        assert_eq!(out.findings_count, 0);
        assert!(!format!("{out:?}").contains("pnpm"));
    }

    #[test]
    fn unicode_safe() {
        let s = "héllo wörld € 😀 sk-ant-api03-FAKEFAKEFAKEFAKE ✓";
        assert_eq!(r(s), "héllo wörld € 😀 [REDACTED] ✓");
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,300}") {
            let _ = redact(&s);
        }

        #[test]
        fn embedded_anthropic_key_always_removed(prefix in "[a-z ]{0,20}", body in "[A-Za-z0-9]{20,40}") {
            let tok = format!("sk-ant-api03-{body}");
            let out = redact(&format!("{prefix} {tok} tail"));
            proptest::prop_assert!(!out.text.contains(&tok));
        }
    }
}
