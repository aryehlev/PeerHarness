//! Heuristic secret and home-path redaction (architecture section 13).
//!
//! [`redact`] runs on every observation before storage and on every human-approved text
//! before the sharing preview. It replaces likely secrets with [`REDACTED`], email
//! addresses with [`REDACTED_EMAIL`], and rewrites absolute home-directory prefixes to
//! `~/`.
//!
//! Detected secret shapes:
//!
//! * PEM / PGP private key blocks (also a truncated block with no `END` line)
//! * Anthropic (`sk-ant-...`) and OpenAI-style (`sk-...`, `sk-proj-...`) API keys
//! * AWS access key ids (`AKIA...`, `ASIA...` and related prefixes)
//! * GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
//! * GitLab (`glpat-`), Hugging Face (`hf_`), npm (`npm_`), Google API (`AIza...`) and
//!   Stripe (`sk_live_`, `rk_test_`, ...) tokens
//! * Slack tokens (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-`, `xoxe-`) and Slack webhook
//!   URLs (`https://hooks.slack.com/services/...`: the host is kept, the path, which is
//!   the credential, is replaced)
//! * JWTs (`eyJ....eyJ....sig`)
//! * `Bearer <token>` and `Authorization: Basic <credentials>` (the scheme is kept), and
//!   `Authorization: <other scheme> <value>` or `Authorization: <value>` when the value
//!   looks like a literal (the same test as in [Sentences](#sentences))
//! * passwords in URLs (`scheme://user:<password>@host`, the user and host are kept)
//! * the password of `curl -u user:<password>` (also `--user`, `--proxy-user`, `-U` and
//!   combined short flags such as `-su`; only on a line that runs `curl`, because
//!   `-u name:name` means user and group for other tools; the user is kept)
//! * generic assignments such as `api_key=...`, `token: ...`, `password = "..."`,
//!   `GITHUB_TOKEN=...`, `AWS_SECRET_ACCESS_KEY=...`, `ENCRYPTION_KEY=...` (the key is
//!   kept, the value replaced; a quoted value is replaced up to its closing quote).
//!   Besides the listed names (`api_key`, `secret`, `token`, `password`, ...), an
//!   all-capitals name that ends in `_KEY` or `_PASS` and is assigned with `=` counts
//!   (`STRIPE_KEY=...`, `DB_PASS=...`), except names such as `PRIMARY_KEY` or `SORT_KEY`
//!   that say what the key is for.
//! * secret command-line flags with a separate value: `--password hunter2`,
//!   `--token ...`, `--api-key ...`, `--client-secret ...` (the flag is kept). See
//!   [Flags](#flags) for what is left alone.
//! * a secret stated in a sentence: `the password is hunter2`. See
//!   [Sentences](#sentences) for where the line is drawn.
//! * email addresses (`local@domain.tld`, replaced by [`REDACTED_EMAIL`] so the preview
//!   says what was removed), including internationalized ones. The domain needs a final
//!   label of 2-63 letters.
//!   npm package specs are kept: `@scope/pkg` has no local part, and `pkg@1.2.3`,
//!   `pkg@1.2.3-beta.rc` or `@scope/pkg@^2` have a numeric version where the domain would
//!   be (a "domain" whose first two labels are all digits is treated as a version).
//!   The user part of `scheme://user:password@host` is kept by the URL rule above, which
//!   runs first. Note that SSH remotes such as `git@github.com:org/repo` are redacted
//!   too.
//! * long high-entropy runs: hex of at least 32 chars mixing digits and letters (this
//!   includes git commit SHAs), or base64/base64url of at least 32 chars mixing upper
//!   case, lower case and digits whose character classes change often (random-looking).
//!   CamelCase identifiers and paths with ordinary lowercase directory names are kept.
//!
//! Token prefixes are anchored with an ASCII word boundary, so a token is also found when
//! it follows text in another script without a space (`...令牌ghp_...`): to the default
//! Unicode-aware `\b`, a CJK character is a word character like any letter.
//!
//! # Flags
//!
//! `--password hunter2` is redacted, `--verbose` and `--password` alone are not. Three
//! kinds of value are deliberately left alone:
//!
//! * a reference rather than a literal: `--token $CI_TOKEN`, `--password <password>`;
//! * a flag whose name says that the value points at the secret instead of being it:
//!   `--password-file /run/secrets/db`, `--token-url ...`, `--secret-name ...`,
//!   `--password-stdin` (the last part of the name decides, see `REFERENCE_SUFFIXES`).
//!   The path of a secrets file is not the secret, and it is often the useful part of a
//!   rule ("read the password from --password-file");
//! * a word that follows a flag in prose: `use --password to log in`, `the --token flag`
//!   (see `FLAG_PROSE_WORDS`), and anything shorter than three characters.
//!
//! `--pwd` followed by a path (`--pwd /srv/app`) is taken for a working directory.
//!
//! Short flags (`-p hunter2`, `-phunter2`) and `--key` are not handled: `-p` is a port
//! or a path as often as a password, and `--key` usually names something.
//!
//! # Sentences
//!
//! "the password is hunter2" must go, "the password is required" and "the password is
//! wrong" should stay. After `password`/`passphrase`/`secret`/`token`/`api key`/...
//! followed by `is` or `was`, the next word is redacted only when it looks like a
//! literal rather than a word:
//!
//! * it is quoted (`the password is "swordfish"`), or
//! * it is at least four characters long and contains both a digit and a letter
//!   (`hunter2`), at least six digits, or one of `!@#$%^&*~`, and it is not a quantity
//!   (`2048-bit`), a well-known technical term (`base64`, `sha256-hashed`) or a
//!   reference (`$TOKEN`).
//!
//! So a password that is an ordinary word and is written without quotes ("the password
//! is swordfish") is **not** redacted: it cannot be told apart from "the password is
//! required". `password: swordfish` and `password=swordfish` are redacted by the
//! assignment rule.
//!
//! # Home directories
//!
//! `/Users/<name>/` and `/home/<name>/` become `~/`, and `C:\Users\<name>\` (also written
//! with `/`) becomes `~/`, where a path can start: at the start of the text, after white
//! space, a quote, a backtick, a bracket, `=`, `,`, `;`, `:`, `|`, `>`, `@` (an editor
//! mention such as `@/Users/alice/x.rs`) or a non-ASCII character, and inside `file://`
//! URLs (`file:///Users/alice/x` becomes `file://~/x`). A path that continues a longer
//! one (`https://example.com/home/page/`) is kept.
//!
//! Redaction is heuristic. It can miss secrets and can redact harmless text; it is a
//! safety net under the exact human preview, not a guarantee.

use std::sync::LazyLock;

use regex::{Captures, Regex};

/// The replacement marker for redacted secrets.
pub const REDACTED: &str = "[REDACTED]";

/// The replacement marker for redacted email addresses.
pub const REDACTED_EMAIL: &str = "[REDACTED-EMAIL]";

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
    /// Like [`Action::KeepPrefix`], but only when the predicate accepts
    /// `(group 1, group 2)`.
    KeepPrefixIf(fn(&str, &str) -> bool),
    /// The match is the rest of a line that runs `curl`: replace the password of every
    /// `-u user:password` on it (see [`CURL_USER_RULES`]).
    CurlUser,
    /// Replace the whole match only if it looks high-entropy.
    HighEntropy,
    /// Replace the whole match with [`REDACTED_EMAIL`] unless it is a package version
    /// spec (see [`looks_like_version_spec`]).
    Email,
}

struct Rule {
    re: Regex,
    action: Action,
}

/// An ASCII word boundary. The default `\b` is Unicode-aware: it sees no boundary
/// between a CJK (or any other non-ASCII) letter and a token that follows it without a
/// space, so `\bghp_...` would miss the token in `令牌ghp_...`.
macro_rules! b {
    () => {
        r"(?-u:\b)"
    };
}

/// A name whose value is a secret, in an assignment (`name=value`, `name: value`) or as
/// a command-line flag (`--name value`).
macro_rules! secret_name {
    () => {
        r"(?:api[_\-]?key|apikey|secret|access[_\-]?key|private[_\-]?key|(?:encryption|decryption|signing|master|license|licence|session|hmac|jwt|auth|deploy|app)[_\-]?key|token|password|passwd|passphrase|pwd|credentials?)"
    };
}

/// The left side of a generic assignment, up to and including `=` or `:`.
macro_rules! assignment {
    () => {
        concat!(
            b!(),
            r"(?:[a-z0-9]+[_\-])*",
            secret_name!(),
            r#"(?:[_\-][a-z0-9]+)*["']?\s*[:=]\s*"#
        )
    };
}

/// The left side of an environment-style assignment: an all-capitals name ending in
/// `_KEY` or `_PASS`, and `=`. Case-sensitive.
macro_rules! env_assignment {
    () => {
        concat!(b!(), r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:KEY|PASS)\s*=\s*")
    };
}

/// A secret flag and the blanks after it: `--password `, `--api-key `, `-token `. It
/// must start where an argument can start, so `re-token x` is not a flag.
macro_rules! flag {
    () => {
        concat!(
            r#"(?:^|[\s"'`(\[{=;|&])--?(?:[a-z0-9]+[_\-])*"#,
            secret_name!(),
            r"(?:[_\-][a-z0-9]+)*[ \t]+"
        )
    };
}

/// "the password is ", "the api key for staging was ", "the token is now ".
macro_rules! stated {
    () => {
        concat!(
            b!(),
            r"(?:pass(?:word|wd|phrase|code)|pwd|secret|token|apikey|(?:api|access|secret|private|encryption|signing|master|license)[ _\-]?key|credentials?)",
            r"(?:[ \t]+(?:for|to|on|of)(?:[ \t]+[^\s.,;:!?]+){1,4}?)?",
            r"[ \t]+(?:is|was)(?:[ \t]+(?:now|currently|still|just|set[ \t]+to))?[ \t]*:?[ \t]+"
        )
    };
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
    (concat!(b!(), r"sk-ant-[A-Za-z0-9_\-]{8,}"), Action::Whole),
    (concat!(b!(), r"sk-[A-Za-z0-9_\-]{16,}"), Action::Whole),
    (
        concat!(
            b!(),
            r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}",
            b!()
        ),
        Action::Whole,
    ),
    (
        concat!(b!(), r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
        Action::Whole,
    ),
    (
        concat!(b!(), r"github_pat_[A-Za-z0-9_]{20,}"),
        Action::Whole,
    ),
    (concat!(b!(), r"glpat-[A-Za-z0-9_\-]{20,}"), Action::Whole),
    (concat!(b!(), r"hf_[A-Za-z0-9]{30,}"), Action::Whole),
    (concat!(b!(), r"npm_[A-Za-z0-9]{36,}"), Action::Whole),
    (concat!(b!(), r"AIza[0-9A-Za-z_\-]{35}"), Action::Whole),
    (
        concat!(b!(), r"[rsp]k_(?:live|test)_[A-Za-z0-9]{10,}"),
        Action::Whole,
    ),
    (
        concat!(b!(), r"xox[abprse]-[A-Za-z0-9\-]{10,}"),
        Action::Whole,
    ),
    // A Slack webhook URL: whoever has the path can post, so the path is the secret.
    (
        r"(?i)(https://hooks\.slack(?:-gov)?\.com/(?:services|workflows|triggers)/)([A-Za-z0-9_/\-]+)",
        Action::KeepPrefix,
    ),
    (
        concat!(
            b!(),
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"
        ),
        Action::Whole,
    ),
    (
        concat!("(?i)(", b!(), r"bearer\s+)([A-Za-z0-9._~+/=\-]{8,})"),
        Action::KeepPrefix,
    ),
    (
        concat!(
            "(?i)(",
            b!(),
            r"authorization\s*:\s*basic\s+)([A-Za-z0-9+/=]{4,})"
        ),
        Action::KeepPrefix,
    ),
    // Any other scheme, or none: `Authorization: token abc123`, `Authorization: abc123`.
    // Only a value that looks like a literal, so "Authorization: required" is kept.
    (
        concat!(
            "(?i)(",
            b!(),
            r#"authorization["']?\s*:\s*["']?(?:[a-z][a-z0-9_\-]*[ \t]+)?)([^\s"'`,;]{8,})"#
        ),
        Action::KeepPrefixIf(stated_value_is_literal),
    ),
    (
        concat!(
            "(?i)(",
            b!(),
            r"[a-z][a-z0-9+.\-]*://[^\s/:@]+:)([^\s/@]+)(@)"
        ),
        Action::KeepPrefix,
    ),
    (concat!(b!(), "curl", b!(), r"[^\n]*"), Action::CurlUser),
    // Assignments. A quoted value goes up to its closing quote, so a passphrase with
    // spaces is replaced whole; an unquoted one goes up to white space.
    (
        concat!("(?i)(", assignment!(), r#"")([^"\n]+)(")"#),
        Action::KeepPrefix,
    ),
    (
        concat!("(?i)(", assignment!(), r"')([^'\n]+)(')"),
        Action::KeepPrefix,
    ),
    (
        concat!("(?i)(", assignment!(), r#"["']?)([^\s"'`,;]{3,})"#),
        Action::KeepPrefix,
    ),
    (
        concat!("(", env_assignment!(), r#"")([^"\n]+)(")"#),
        Action::KeepPrefixIf(env_name_is_secret),
    ),
    (
        concat!("(", env_assignment!(), r"')([^'\n]+)(')"),
        Action::KeepPrefixIf(env_name_is_secret),
    ),
    (
        concat!("(", env_assignment!(), r#")([^\s"'`,;]{3,})"#),
        Action::KeepPrefixIf(env_name_is_secret),
    ),
    // Flags with a separate value: `--password hunter2`, `--token "a b"`.
    (
        concat!("(?i)(", flag!(), r#"")([^"\n]+)(")"#),
        Action::KeepPrefixIf(quoted_flag_value_is_secret),
    ),
    (
        concat!("(?i)(", flag!(), r"')([^'\n]+)(')"),
        Action::KeepPrefixIf(quoted_flag_value_is_secret),
    ),
    (
        concat!("(?i)(", flag!(), r#")([^\s"'`\-][^\s"'`]*)"#),
        Action::KeepPrefixIf(flag_value_is_secret),
    ),
    // A secret stated in a sentence: `the password is hunter2`.
    (
        concat!("(?i)(", stated!(), r#"["'`])([^"'`\n]+)(["'`])"#),
        Action::KeepPrefix,
    ),
    (
        concat!("(?i)(", stated!(), r#")([^\s"'`,;]{4,})"#),
        Action::KeepPrefixIf(stated_value_is_literal),
    ),
    (
        r"\b[\p{L}\p{N}][\p{L}\p{N}._%+\-]*@[\p{L}\p{N}](?:[\p{L}\p{N}\-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}\-]*[\p{L}\p{N}])?)*\.\p{L}{2,63}\b",
        Action::Email,
    ),
    (r"[A-Za-z0-9+/_\-]{32,}={0,2}", Action::HighEntropy),
];

/// `-u user:password` on a `curl` line, quoted or not: `-u`, combined short flags
/// ending in `u` or `U` (`-su`, `-fsSLu`), `--user` and `--proxy-user`.
const CURL_USER_PATTERNS: &[&str] = &[
    r#"(\s(?:-[A-Za-z]*[uU][ \t]*|--(?:proxy-)?user(?:[ \t]+|=))"[^\s:"]+:)([^"\n]+)(")"#,
    r"(\s(?:-[A-Za-z]*[uU][ \t]*|--(?:proxy-)?user(?:[ \t]+|=))'[^\s:']+:)([^'\n]+)(')",
    r#"(\s(?:-[A-Za-z]*[uU][ \t]*|--(?:proxy-)?user(?:[ \t]+|=))[^\s:"'\-][^\s:"']*:)([^\s"']+)"#,
];

/// Last part of a flag name that says the value points at the secret instead of being
/// it: `--password-file`, `--token-url`, `--secret-name`, `--password-stdin`.
const REFERENCE_SUFFIXES: &[&str] = &[
    "file", "path", "dir", "stdin", "env", "name", "id", "url", "uri", "endpoint", "type",
    "length", "header", "prompt", "command", "cmd", "helper", "ttl", "expiry", "count", "size",
    "field", "var", "format", "prefix", "location", "ref", "policy",
];

/// Words that follow a flag when it is mentioned in a sentence rather than used in a
/// command: "use --password to log in", "the --token flag is required".
const FLAG_PROSE_WORDS: &[&str] = &[
    "to",
    "is",
    "and",
    "or",
    "the",
    "a",
    "an",
    "for",
    "in",
    "on",
    "with",
    "flag",
    "flags",
    "option",
    "options",
    "argument",
    "arguments",
    "arg",
    "args",
    "parameter",
    "parameters",
    "param",
    "value",
    "values",
    "from",
    "if",
    "when",
    "as",
    "was",
    "should",
    "must",
    "can",
    "will",
    "not",
    "are",
    "instead",
    "here",
    "there",
    "it",
    "that",
    "this",
    "which",
    "so",
    "but",
    "then",
    "by",
    "of",
    "switch",
    "at",
    "via",
    "because",
    "does",
    "has",
    "required",
    "optional",
    "prompt",
    "prompts",
    "twice",
    "again",
    "directly",
    "explicitly",
    "inline",
    "works",
    "handling",
    "support",
    "every",
    "each",
    "off",
    "true",
    "false",
];

/// The part of an all-capitals `..._KEY` name before `_KEY` that says the key is a
/// lookup key, not a secret: `PRIMARY_KEY=id`, `SORT_KEY=created_at`.
const LOOKUP_KEY_QUALIFIERS: &[&str] = &[
    "PRIMARY",
    "FOREIGN",
    "PARTITION",
    "SORT",
    "RANGE",
    "HASH",
    "CACHE",
    "PUBLIC",
    "ROW",
    "GROUP",
    "UNIQUE",
    "OBJECT",
    "INDEX",
    "LOOKUP",
    "MAP",
    "DICT",
];

/// Technical terms with digits that follow "the token is" in ordinary prose
/// ("the token is base64-encoded"). A value that starts with one of them, followed by
/// nothing or by a non-alphanumeric character, is not a literal secret.
const TECH_TERMS: &[&str] = &[
    "base64", "base32", "base58", "sha1", "sha256", "sha384", "sha512", "sha-1", "sha-256",
    "sha-384", "sha-512", "md5", "utf8", "utf-8", "utf16", "utf-16", "hs256", "hs384", "hs512",
    "rs256", "rs384", "rs512", "es256", "es384", "es512", "oauth2", "x509", "argon2", "argon2i",
    "argon2d", "argon2id", "pbkdf2", "aes128", "aes256", "aes-128", "aes-256", "ed25519", "http2",
    "ipv4", "ipv6", "2fa", "v1", "v2", "v3", "v4",
];

/// Punctuation that ends a sentence or a clause rather than a value.
const TRAILING_PUNCTUATION: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}'];

/// A reference to a value rather than the value: `$TOKEN`, `${TOKEN}`, `<token>`,
/// `{{ token }}`, `%TOKEN%`, `[token]`.
fn is_reference(value: &str) -> bool {
    value.starts_with(['$', '<', '{', '%', '['])
}

/// The flag name at the end of a matched prefix such as ` --db-password ` or
/// ` --db-password "`.
fn flag_name(prefix: &str) -> &str {
    prefix
        .trim_end_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .next()
        .unwrap_or_default()
}

/// Whether a quoted value after a secret flag is the secret: not when the flag names a
/// file, URL or similar (`--password-file "..."`), and not when it is a reference.
fn quoted_flag_value_is_secret(prefix: &str, value: &str) -> bool {
    let name = flag_name(prefix).to_ascii_lowercase();
    let last = name.rsplit(['-', '_']).next().unwrap_or_default();
    // `--pwd` is a password for some tools and a working directory for others.
    let directory = last == "pwd" && value.starts_with(['/', '.', '~']);
    !REFERENCE_SUFFIXES.contains(&last) && !is_reference(value) && !directory
}

/// [`quoted_flag_value_is_secret`] for an unquoted value, which may also be the next
/// word of a sentence that only mentions the flag.
fn flag_value_is_secret(prefix: &str, value: &str) -> bool {
    let word = value
        .trim_end_matches(TRAILING_PUNCTUATION)
        .to_ascii_lowercase();
    word.len() >= 3
        && !FLAG_PROSE_WORDS.contains(&word.as_str())
        && quoted_flag_value_is_secret(prefix, value)
}

/// Whether an all-capitals `NAME_KEY=` / `NAME_PASS=` assignment holds a secret.
fn env_name_is_secret(prefix: &str, value: &str) -> bool {
    let name = prefix.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
    let qualifier = name
        .strip_suffix("_KEY")
        .and_then(|n| n.rsplit('_').next())
        .unwrap_or_default();
    !LOOKUP_KEY_QUALIFIERS.contains(&qualifier) && !is_reference(value)
}

/// `2048-bit`, `32-byte`: digits, a hyphen, letters.
fn is_quantity(value: &str) -> bool {
    value.split_once('-').is_some_and(|(n, unit)| {
        !n.is_empty()
            && !unit.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
            && unit.bytes().all(|b| b.is_ascii_alphabetic())
    })
}

fn is_tech_term(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    TECH_TERMS.iter().any(|t| {
        lower
            .strip_prefix(t)
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric()))
    })
}

/// Whether the word after "the password is" looks like a literal secret rather than
/// the rest of a sentence (see the module docs, "Sentences"). Letters alone are prose:
/// "required", "wrong", "hashed". A digit next to letters, six or more digits, or one
/// of `!@#$%^&*~` make a literal, unless the value is a quantity, a technical term or
/// a reference.
fn stated_value_is_literal(_prefix: &str, value: &str) -> bool {
    if is_reference(value) {
        return false;
    }
    let v = value.trim_end_matches(TRAILING_PUNCTUATION);
    if v.contains(['!', '@', '#', '$', '%', '^', '&', '*', '~']) {
        return true;
    }
    let digits = v.chars().filter(char::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    if !v.chars().any(char::is_alphabetic) {
        return digits >= 6;
    }
    !is_quantity(v) && !is_tech_term(v)
}

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

static CURL_USER_RULES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    CURL_USER_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

/// Where a home-directory path can start (kept as `lead`): the start of the text, white
/// space, a quote or backtick, a bracket, `=`, `,`, `;`, `:`, `|`, `>`, `@`, any
/// non-ASCII character, or the `file` host of an editor URL (`vscode://file/Users/...`).
/// The other way in is a `file://` URL (kept as `url`; a `localhost` host is dropped).
/// A path that continues a longer one (`example.com/home/page`) does not match.
macro_rules! path_start {
    ($extra:literal) => {
        concat!(
            r#"(?:(?P<lead>^|[\s"'`=(\[{<>,;:@|]|[^\x00-\x7F]|://file)|(?P<url>file://)(?:localhost)?"#,
            $extra,
            ")"
        )
    };
}

static UNIX_HOME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        path_start!(""),
        r"(?:/Users|/home)/[A-Za-z0-9._\-]+(?P<sep>/|\b)"
    ))
    .ok()
});

/// `C:\Users\name\`, also written with forward slashes (`C:/Users/name/`, and
/// `file:///C:/Users/name/`).
static WINDOWS_HOME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        "(?i)",
        path_start!("/"),
        r#"[a-z]:[\\/]Users[\\/][^\\/\s"'`<>|]+(?P<sep>[\\/]|\b)"#
    ))
    .ok()
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

/// Whether an email-shaped match `local@domain` is really a package version spec such as
/// `pkg@1.2.3-beta.rc`: the first two labels of the domain are all digits. Real domains
/// with a numeric first label (`163.com`) are still emails.
fn looks_like_version_spec(email_match: &str) -> bool {
    let Some((_, domain)) = email_match.rsplit_once('@') else {
        return false;
    };
    let mut labels = domain.split('.');
    let numeric =
        |l: Option<&str>| l.is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
    numeric(labels.next()) && numeric(labels.next())
}

/// Replaces the password of every `-u user:password` in `line` (a line that runs
/// `curl`). Returns the line and the number of replacements. A password that is a
/// reference (`-u admin:$PASS`) or already redacted is kept.
fn redact_curl_user(line: &str) -> (String, usize) {
    let mut out = line.to_owned();
    let mut replaced = 0usize;
    for re in CURL_USER_RULES.iter() {
        let next = re.replace_all(&out, |c: &Captures<'_>| {
            let group = |i: usize| c.get(i).map(|m| m.as_str()).unwrap_or_default();
            let (prefix, value, suffix) = (group(1), group(2), group(3));
            if value.starts_with("[REDACTED") || is_reference(value) {
                group(0).to_owned()
            } else {
                replaced += 1;
                format!("{prefix}{REDACTED}{suffix}")
            }
        });
        if let std::borrow::Cow::Owned(s) = next {
            out = s;
        }
    }
    (out, replaced)
}

/// Redacts likely secrets and email addresses and strips absolute home-directory
/// prefixes.
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
                Action::KeepPrefix | Action::KeepPrefixIf(_) => {
                    let prefix = c.get(1).map(|m| m.as_str()).unwrap_or_default();
                    let value = c.get(2).map(|m| m.as_str()).unwrap_or_default();
                    let suffix = c.get(3).map(|m| m.as_str()).unwrap_or_default();
                    let wanted = match rule.action {
                        Action::KeepPrefixIf(accepts) => accepts(prefix, value),
                        _ => true,
                    };
                    if value.starts_with("[REDACTED") || !wanted {
                        whole.to_owned()
                    } else {
                        findings += 1;
                        format!("{prefix}{REDACTED}{suffix}")
                    }
                }
                Action::CurlUser => {
                    let (line, replaced) = redact_curl_user(whole);
                    findings += replaced;
                    line
                }
                Action::HighEntropy => {
                    if looks_high_entropy(whole) {
                        findings += 1;
                        REDACTED.to_owned()
                    } else {
                        whole.to_owned()
                    }
                }
                Action::Email => {
                    if looks_like_version_spec(whole) {
                        whole.to_owned()
                    } else {
                        findings += 1;
                        REDACTED_EMAIL.to_owned()
                    }
                }
            }
        });
        if let std::borrow::Cow::Owned(s) = replaced {
            out = s;
        }
    }

    let mut paths = 0usize;
    // Windows first: `C:/Users/name/` also contains what the Unix rule looks for.
    for re in [&*WINDOWS_HOME, &*UNIX_HOME].into_iter().flatten() {
        let replaced = re.replace_all(&out, |c: &Captures<'_>| {
            paths += 1;
            let lead = c
                .name("lead")
                .or_else(|| c.name("url"))
                .map(|m| m.as_str())
                .unwrap_or_default();
            let sep = c.name("sep").map(|m| m.as_str()).unwrap_or_default();
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
    fn emails() {
        assert_eq!(
            r("ping alice@example.com about it"),
            "ping [REDACTED-EMAIL] about it"
        );
        assert_eq!(
            r("use alice@corp.com, not bob@corp.com"),
            "use [REDACTED-EMAIL], not [REDACTED-EMAIL]"
        );
        assert_eq!(r("<x.y+tag@mail.example.co.uk>"), "<[REDACTED-EMAIL]>");
        assert_eq!(r("mailto:Carol_D@Example.ORG."), "mailto:[REDACTED-EMAIL].");
        assert_eq!(r("dev@163.com"), "[REDACTED-EMAIL]");
        assert_eq!(r("héllo bob@exämple.com"), "héllo [REDACTED-EMAIL]");
        assert_eq!(
            r("git@github.com:org/repo.git"),
            "[REDACTED-EMAIL]:org/repo.git"
        );
        let out = redact("a@b.io and c@d.dev");
        assert_eq!(out.text, "[REDACTED-EMAIL] and [REDACTED-EMAIL]");
        assert_eq!(out.findings_count, 2);
        // URL credentials: the password rule runs first and keeps user and host.
        assert_eq!(
            r("https://alice:hunter2pass@example.com/x"),
            "https://alice:[REDACTED]@example.com/x"
        );
    }

    #[test]
    fn package_specs_are_not_emails() {
        for keep in [
            "pnpm add @scope/pkg",
            "pnpm add @acme/web-app2024@latest",
            "npm i react@18.2.0",
            "npm i pkg@1.2.3",
            "npm i pkg@1.2.3-beta.rc",
            "npm i @types/node@20.11.5",
            "npm i @scope/pkg@^2.0.0 left-pad@~1.3",
            "npm WARN deprecated request@2.88.2: use got",
            "cargo add serde@1",
            "user@localhost",
            "foo@bar",
            "@alice mentioned it",
        ] {
            let out = redact(keep);
            assert_eq!(out.text, keep);
            assert_eq!(out.findings_count, 0, "{keep}");
        }
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

    /// Asserts that `input` is left exactly as it is, with nothing counted.
    fn kept(input: &str) {
        let out = redact(input);
        assert_eq!(out.text, input);
        assert_eq!(out.findings_count, 0, "{input}");
        assert_eq!(out.paths_stripped, 0, "{input}");
    }

    #[test]
    fn curl_patterns_compile() {
        assert_eq!(CURL_USER_RULES.len(), CURL_USER_PATTERNS.len());
    }

    #[test]
    fn slack_webhook_urls() {
        // Assembled here so that no webhook-shaped URL sits in the source.
        let path = format!("T00000000/B00000000/{}", "x1Y2".repeat(6));
        let url = format!("https://hooks.slack.com/services/{path}");
        let out = redact(&format!("post it to {url} when done"));
        assert_eq!(
            out.text,
            "post it to https://hooks.slack.com/services/[REDACTED] when done"
        );
        assert!(!out.text.contains("T00000000") && !out.text.contains("x1Y2"));
        assert_eq!(out.findings_count, 1);
        let md = r(&format!("[alerts]({url})."));
        assert_eq!(md, "[alerts](https://hooks.slack.com/services/[REDACTED]).");
        let wf = r(&format!(
            "https://hooks.slack.com/triggers/{path} and Slack docs"
        ));
        assert_eq!(
            wf,
            "https://hooks.slack.com/triggers/[REDACTED] and Slack docs"
        );
        kept("see https://api.slack.com/messaging/webhooks for the setup");
        kept("the hooks.slack.com host is allowed by the proxy");
    }

    #[test]
    fn secret_stated_in_a_sentence() {
        assert_eq!(r("the password is hunter2"), "the password is [REDACTED]");
        assert_eq!(
            r("The admin password is now hunter2."),
            "The admin password is now [REDACTED]"
        );
        assert_eq!(
            r("password is: Tr0ub4dor&3 for the vpn"),
            "password is: [REDACTED] for the vpn"
        );
        assert_eq!(
            r("the api key for the staging server is abc123def, use it"),
            "the api key for the staging server is [REDACTED], use it"
        );
        assert_eq!(
            r("the pin code changed and the passcode was 12345678"),
            "the pin code changed and the passcode was [REDACTED]"
        );
        assert_eq!(r("my token is p@ssword"), "my token is [REDACTED]");
        // Quoted: a literal, whatever it looks like, up to the closing quote.
        assert_eq!(
            r("the passphrase is \"correct horse battery staple\", ok?"),
            "the passphrase is \"[REDACTED]\", ok?"
        );
        assert_eq!(
            r("the password is 'swordfish'"),
            "the password is '[REDACTED]'"
        );
        assert_eq!(
            r("the secret is `opensesame`"),
            "the secret is `[REDACTED]`"
        );
        let out = redact("the password is hunter2 and the secret key is s3cr3t");
        assert_eq!(
            out.text,
            "the password is [REDACTED] and the secret key is [REDACTED]"
        );
        assert_eq!(out.findings_count, 2);
        assert!(!out.text.contains("hunter2") && !out.text.contains("s3cr3t"));
    }

    #[test]
    fn sentences_about_secrets_are_kept() {
        for keep in [
            "the password is required",
            "the password is wrong",
            "The password is wrong!",
            "the password is not what I expected",
            "the token is expired, log in again",
            "the token is base64-encoded",
            "the token is sha256-hashed before it is stored",
            "the secret is 32 bytes long",
            "the signing key is 2048-bit",
            "the api key is missing from the request",
            "the password is $DB_PASSWORD",
            "the token is <your token here>",
            "the password for the admin user is wrong",
            "explain what the token is used for",
            "if token is None:",
            "the secret is safe, the token is rotated nightly",
            "max_tokens is 100000 for this model",
        ] {
            kept(keep);
        }
        // The documented limit: an ordinary word without quotes is not told apart from
        // "required". With quotes or as an assignment it is redacted.
        kept("the password is swordfish");
        assert_eq!(r("password: swordfish"), "password: [REDACTED]");
    }

    #[test]
    fn secret_flags() {
        assert_eq!(
            r("mysql --password hunter2 -h db"),
            "mysql --password [REDACTED] -h db"
        );
        assert_eq!(
            r("mysql --password=hunter2 -h db"),
            "mysql --password=[REDACTED] -h db"
        );
        let out = redact("tool --token abc123def --api-key zzz999 --verbose");
        assert_eq!(
            out.text,
            "tool --token [REDACTED] --api-key [REDACTED] --verbose"
        );
        assert_eq!(out.findings_count, 2);
        assert_eq!(
            r("cli login --client-secret \"a b c\" --user bob"),
            "cli login --client-secret \"[REDACTED]\" --user bob"
        );
        assert_eq!(
            r("cli login --passphrase 'open sesame'"),
            "cli login --passphrase '[REDACTED]'"
        );
        // A flag value is a literal even when it is an ordinary word.
        assert_eq!(
            r("psql --db-password swordfish"),
            "psql --db-password [REDACTED]"
        );
        assert_eq!(r("deploy -token abc123"), "deploy -token [REDACTED]");
        assert_eq!(
            r("run `app --auth-token t0k3n` first"),
            "run `app --auth-token [REDACTED]` first"
        );
        assert_eq!(
            r("aws configure set --aws-secret-access-key abcDEF123/xyz"),
            "aws configure set --aws-secret-access-key [REDACTED]"
        );
        // A provider token after a flag is counted once.
        let out = redact("gh auth --token ghp_FAKEfakeFAKEfakeFAKEfake1234");
        assert_eq!(out.text, "gh auth --token [REDACTED]");
        assert_eq!(out.findings_count, 1);
    }

    #[test]
    fn ordinary_flags_are_kept() {
        for keep in [
            "cargo build --verbose --release",
            "git log --author bob --no-merges",
            "run it with --password --verbose",
            "mysql --password",
            // The value points at the secret, it is not the secret.
            "app --password-file /run/secrets/db_password",
            "docker login --password-stdin registry.example.com",
            "aws secretsmanager get-secret-value --secret-id prod/db",
            "vault write --token-ttl 30m auth/x",
            // References, not literals.
            "deploy --token $CI_TOKEN --env prod",
            "deploy --token \"${CI_TOKEN}\" --env prod",
            "usage: tool --api-key <key> [--verbose]",
            "gh auth login --with-token < token.txt",
            // A flag mentioned in a sentence.
            "use --password to log in",
            "the --token flag is required",
            "pass --api-key and --verbose",
            "never put --password on the command line",
            // A working directory, not a password.
            "tool --pwd /srv/app build",
        ] {
            kept(keep);
        }
        assert_eq!(r("tool --pwd hunter2"), "tool --pwd [REDACTED]");
    }

    #[test]
    fn authorization_header_with_another_scheme() {
        assert_eq!(
            r("curl -H 'Authorization: token abc123def456' https://api.example.com"),
            "curl -H 'Authorization: token [REDACTED]' https://api.example.com"
        );
        assert_eq!(
            r("Authorization: abc123def456"),
            "Authorization: [REDACTED]"
        );
        assert_eq!(
            r(r#"{"Authorization": "ApiKey k3y-0f-s0me-length"}"#),
            r#"{"Authorization": "ApiKey [REDACTED]"}"#
        );
        // The two schemes that were already handled are counted once.
        let out = redact("Authorization: Bearer abc.def-ghi_jkl123");
        assert_eq!(out.text, "Authorization: Bearer [REDACTED]");
        assert_eq!(out.findings_count, 1);
        for keep in [
            "Authorization: required for all endpoints",
            "Authorization: Bearer <token>",
            "Authorization: Bearer $GITHUB_TOKEN",
            "Authorization: handled by the gateway middleware",
        ] {
            kept(keep);
        }
    }

    #[test]
    fn curl_user_passwords() {
        assert_eq!(
            r("curl -u admin:hunter2 https://example.com/api"),
            "curl -u admin:[REDACTED] https://example.com/api"
        );
        assert_eq!(
            r("curl -sSu admin:hunter2 https://example.com"),
            "curl -sSu admin:[REDACTED] https://example.com"
        );
        assert_eq!(
            r("curl -uadmin:hunter2 https://example.com"),
            "curl -uadmin:[REDACTED] https://example.com"
        );
        let out = redact("curl --user \"admin:my pass\" -U proxy:pw2 https://example.com");
        assert_eq!(
            out.text,
            "curl --user \"admin:[REDACTED]\" -U proxy:[REDACTED] https://example.com"
        );
        assert_eq!(out.findings_count, 2);
        assert_eq!(
            r("first\n$ curl https://example.com --proxy-user=bob:s3cret\nlast"),
            "first\n$ curl https://example.com --proxy-user=bob:[REDACTED]\nlast"
        );
        // URL userinfo was already handled; it stays handled next to curl.
        assert_eq!(
            r("curl https://alice:hunter2pass@example.com/x"),
            "curl https://alice:[REDACTED]@example.com/x"
        );
        for keep in [
            // Other tools: user and group, not user and password.
            "docker run -u 1000:1000 alpine id",
            "docker run --user node:node app",
            // No password given, a reference, or no credentials at all.
            "curl -u admin https://example.com",
            "curl -u admin:$API_PASSWORD https://example.com",
            "curl -H \"Accept: application/json\" http://localhost:8080/users",
            "curl -X PUT -d @body.json http://localhost:8080/items/1",
            "use curl to check the endpoint",
        ] {
            kept(keep);
        }
    }

    #[test]
    fn short_and_quoted_assignments() {
        assert_eq!(r("ENCRYPTION_KEY=abc123"), "ENCRYPTION_KEY=[REDACTED]");
        assert_eq!(r("encryption_key: abc123"), "encryption_key: [REDACTED]");
        assert_eq!(r("signingKey = \"k1\";"), "signingKey = \"[REDACTED]\";");
        let out = redact("export STRIPE_KEY=abc123 DB_PASS=hunter2");
        assert_eq!(out.text, "export STRIPE_KEY=[REDACTED] DB_PASS=[REDACTED]");
        assert_eq!(out.findings_count, 2);
        // A quoted value is replaced up to the closing quote, spaces included.
        assert_eq!(
            r("password = \"my secret phrase\""),
            "password = \"[REDACTED]\""
        );
        assert_eq!(
            r("token: 'it is a long one', next: 1"),
            "token: '[REDACTED]', next: 1"
        );
        assert_eq!(r("DB_PASS='correct horse'"), "DB_PASS='[REDACTED]'");
        assert_eq!(r("MASTER_KEY=\"a b\""), "MASTER_KEY=\"[REDACTED]\"");
        for keep in [
            "PRIMARY_KEY=user_id",
            "SORT_KEY=created_at",
            "primary_key = id",
            "foreign_key: true",
            "STRIPE_KEY=$STRIPE_KEY_FROM_VAULT",
            "keyboard=us",
            "monkey: banana",
            "password = \"\"",
        ] {
            kept(keep);
        }
    }

    #[test]
    fn tokens_next_to_cjk_text() {
        let cases = [
            "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
            "sk-proj-FAKEfake1234FAKEfake5678",
            "AKIAFAKEFAKEFAKEFAKE",
            "ghp_FAKEfakeFAKEfakeFAKEfake1234",
            "github_pat_11FAKEFAKE0_fakefakefakefakefake",
            "glpat-FAKEfakeFAKEfake1234",
            "xoxb-1234567890-FAKEFAKEFAKE",
            "sk_live_51HFAKEfakeFAKEfake1234567890",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.FAKEsignatureFAKE",
        ];
        for tok in cases {
            // Chinese, Japanese and Korean text with no space on either side.
            for (before, after) in [
                ("请使用这个令牌", "来访问"),
                ("トークンは", "です"),
                ("토큰", "입니다"),
            ] {
                let out = redact(&format!("{before}{tok}{after}"));
                assert_eq!(out.text, format!("{before}[REDACTED]{after}"), "{tok}");
                assert_eq!(out.findings_count, 1, "{tok}");
            }
        }
        assert_eq!(r("密码password=hunter2"), "密码password=[REDACTED]");
        assert_eq!(r("令牌Bearer abcdef123456"), "令牌Bearer [REDACTED]");
        // Accented Latin letters are no boundary problem either.
        assert_eq!(r("cléghp_FAKEfakeFAKEfakeFAKEfake1234"), "clé[REDACTED]");
        kept("请使用 pnpm，不要使用 npm。");
    }

    #[test]
    fn home_paths_in_backticks_mentions_and_file_urls() {
        let cases = [
            (
                "see `/Users/alice/project/file.rs`",
                "see `~/project/file.rs`",
            ),
            ("`/home/alice`", "`~`"),
            (
                "look at @/Users/alice/project/file.rs please",
                "look at @~/project/file.rs please",
            ),
            ("@/home/alice/notes.md", "@~/notes.md"),
            (
                "open file:///Users/alice/project/file.rs",
                "open file://~/project/file.rs",
            ),
            (
                "file://localhost/home/alice/notes.txt",
                "file://~/notes.txt",
            ),
            ("(file:///home/alice)", "(file://~)"),
            (
                "vscode://file/Users/alice/project/a.rs:10",
                "vscode://file~/project/a.rs:10",
            ),
            ("`C:\\Users\\alice\\repo`", "`~/repo`"),
            ("@C:\\Users\\alice\\repo\\a.rs", "@~/repo\\a.rs"),
            ("file:///C:/Users/alice/repo/a.rs", "file://~/repo/a.rs"),
            ("C:/Users/alice/repo", "~/repo"),
            ("cat a.log >/home/alice/out.log", "cat a.log >~/out.log"),
            ("路径/Users/alice/x", "路径~/x"),
        ];
        for (input, expected) in cases {
            let out = redact(input);
            assert_eq!(out.text, expected, "{input}");
            assert!(!out.text.contains("alice"), "{input}");
            assert_eq!(out.paths_stripped, 1, "{input}");
        }
        for keep in [
            "https://example.com/home/page/",
            "https://example.com/Users/list",
            "GET /api/home/feed returns 200",
            "the `/home/` directory",
            "file:///etc/hosts",
            "regex:/users/(\\d+)/",
            "@scope/home/index.js",
        ] {
            kept(keep);
        }
    }

    /// Redaction runs more than once on the same text (on the way into the store, on
    /// drain, before a preview), so its output must be stable under a second pass.
    #[test]
    fn second_pass_changes_nothing() {
        for input in [
            "the password is hunter2",
            "the passphrase is \"correct horse battery staple\"",
            "mysql --password hunter2 -h db",
            "cli login --client-secret \"a b c\"",
            "curl -u admin:hunter2 https://example.com/api",
            "curl --user \"admin:my pass\" -U proxy:pw2 https://example.com",
            "export STRIPE_KEY=abc123 DB_PASS='correct horse'",
            "password = \"my secret phrase\"",
            "令牌ghp_FAKEfakeFAKEfakeFAKEfake1234。",
            "see `/Users/alice/project/file.rs` and @/home/alice/x",
            "file:///Users/alice/project/file.rs",
            "file:///C:/Users/alice/repo/a.rs",
            "https://hooks.slack.com/services/[REDACTED]",
        ] {
            let once = redact(input);
            let twice = redact(&once.text);
            assert_eq!(twice.text, once.text, "{input}");
            assert_eq!(twice.findings_count, 0, "{input}");
            assert_eq!(twice.paths_stripped, 0, "{input}");
        }
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,300}") {
            let _ = redact(&s);
        }

        #[test]
        fn embedded_email_always_removed(local in "[a-z][a-z0-9._+-]{0,15}", host in "[a-z][a-z0-9-]{0,10}[a-z0-9]", tld in "[a-z]{2,6}") {
            let email = format!("{local}@{host}.{tld}");
            let out = redact(&format!("contact {email} today"));
            proptest::prop_assert!(!out.text.contains(&email));
            proptest::prop_assert!(out.text.contains(REDACTED_EMAIL));
        }

        #[test]
        fn embedded_anthropic_key_always_removed(prefix in "[a-z ]{0,20}", body in "[A-Za-z0-9]{20,40}") {
            let tok = format!("sk-ant-api03-{body}");
            let out = redact(&format!("{prefix} {tok} tail"));
            proptest::prop_assert!(!out.text.contains(&tok));
        }
    }
}
