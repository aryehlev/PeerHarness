//! Claude Code hook input and output.
//!
//! The flow for `peerharness hook <event>` is:
//!
//! 1. [`read_bounded_stdin`] (at most [`MAX_HOOK_INPUT_BYTES`]),
//! 2. [`parse_hook_payload`] (lenient: unknown fields ignored, wrongly typed fields
//!    treated as absent, never panics),
//! 3. [`normalize`] into a redacted, bounded [`NormalizedObservation`],
//! 4. store it (SQLite, or [`crate::spool`] as a fallback; done by the caller),
//! 5. write [`HookOutput`] to stdout and exit with [`HookOutput::EXIT_CODE`] (always 0).
//!
//! [`observe_hook_input`] performs steps 1-3 in one call and swallows every error
//! (logging only an error code at debug level), which is what the hook binary wants.
//!
//! # Never reading transcripts
//!
//! [`normalize`] is a pure function of its arguments. It takes no filesystem handle,
//! does no I/O, and [`HookPayload`] does not even keep `transcript_path`,
//! `last_assistant_message`, `tool_input` or `error`: they are dropped at parse time. It
//! is therefore structurally impossible for this module to open a transcript.

use std::fmt;
use std::io::{self, Read, Write};
use std::str::FromStr;

use ph_core::{
    Digest, NormalizedObservation, ObservationId, ObservationKind, ObservationSource, ParseError,
    Timestamp,
};
use serde_json::Value;

use crate::notify::{should_notify, NotifyPolicy};

/// Maximum hook stdin size we accept (1 MiB). Larger input is discarded.
pub const MAX_HOOK_INPUT_BYTES: usize = 1024 * 1024;

/// After an oversized input, at most this many further bytes are read and discarded so
/// the writer does not see a broken pipe; then we stop reading.
const OVERSIZE_DRAIN_LIMIT: u64 = 64 * 1024 * 1024;

/// Domain-separation context for [`session_hash`].
pub const SESSION_HASH_CONTEXT: &str = "peerharness-session-v0";

/// Domain-separation context for [`repo_key`].
pub const REPO_KEY_CONTEXT: &str = "peerharness-repo-v0";

/// Repo key used when the payload has no usable `cwd`.
pub const UNKNOWN_REPO_KEY: &str = "repo:unknown";

/// Maximum length of a tool name kept in a `ToolFailure` observation.
pub const MAX_TOOL_NAME_CHARS: usize = 128;

/// Maximum length of [`repo_label`] output.
pub const MAX_REPO_LABEL_CHARS: usize = 64;

/// Maximum length (in characters) of a `systemMessage` we print.
pub const MAX_SYSTEM_MESSAGE_CHARS: usize = 300;

/// A Claude Code hook event PeerHarness understands.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum HookEvent {
    /// `UserPromptSubmit`: the user submitted a prompt.
    UserPromptSubmit,
    /// `Stop`: the main agent finished responding.
    Stop,
    /// `PostToolUseFailure`: a tool call failed. Parsed and normalized, but not installed
    /// by default.
    PostToolUseFailure,
}

impl HookEvent {
    /// Every event this crate can parse.
    pub const ALL: [HookEvent; 3] = [
        HookEvent::UserPromptSubmit,
        HookEvent::Stop,
        HookEvent::PostToolUseFailure,
    ];

    /// The events [`crate::settings::install_hooks`] installs.
    pub const INSTALLED: [HookEvent; 2] = [HookEvent::UserPromptSubmit, HookEvent::Stop];

    /// The Claude Code event name, as in `hook_event_name` and the `settings.json` key.
    pub const fn event_name(self) -> &'static str {
        match self {
            HookEvent::UserPromptSubmit => "UserPromptSubmit",
            HookEvent::Stop => "Stop",
            HookEvent::PostToolUseFailure => "PostToolUseFailure",
        }
    }

    /// The `peerharness hook <arg>` subcommand argument (kebab case).
    pub const fn cli_arg(self) -> &'static str {
        match self {
            HookEvent::UserPromptSubmit => "user-prompt-submit",
            HookEvent::Stop => "stop",
            HookEvent::PostToolUseFailure => "post-tool-use-failure",
        }
    }

    /// Parses a Claude Code event name (exact, case-sensitive).
    pub fn from_event_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.event_name() == s)
    }

    /// Parses a CLI argument (exact, case-sensitive).
    pub fn from_cli_arg(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.cli_arg() == s)
    }
}

impl fmt::Display for HookEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.event_name())
    }
}

impl FromStr for HookEvent {
    type Err = ParseError;
    /// Accepts either the CLI argument (`user-prompt-submit`) or the event name
    /// (`UserPromptSubmit`).
    fn from_str(s: &str) -> Result<Self, ParseError> {
        Self::from_cli_arg(s)
            .or_else(|| Self::from_event_name(s))
            .ok_or(ParseError::new("hook event", "unknown hook event"))
    }
}

/// Errors while reading or parsing hook input. `Display` never includes input contents.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HookInputError {
    /// The input exceeded the size limit and was discarded.
    #[error("hook input exceeds {max} bytes and was discarded")]
    Oversized {
        /// The limit that was exceeded.
        max: usize,
    },
    /// Reading stdin failed.
    #[error("failed to read hook input: {kind}")]
    Io {
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
    /// The input is not valid JSON.
    #[error("hook input is not valid JSON (line {line}, column {column})")]
    Malformed {
        /// 1-based line of the syntax error.
        line: usize,
        /// 1-based column of the syntax error.
        column: usize,
    },
    /// The input is JSON but not an object.
    #[error("hook input is not a JSON object")]
    NotAnObject,
}

impl HookInputError {
    /// A stable, content-free code for logs.
    pub const fn code(&self) -> &'static str {
        match self {
            HookInputError::Oversized { .. } => "oversized",
            HookInputError::Io { .. } => "io",
            HookInputError::Malformed { .. } => "malformed",
            HookInputError::NotAnObject => "not_an_object",
        }
    }
}

/// Reads at most `max` bytes from `reader` until EOF.
///
/// If the input is longer than `max`, everything read is discarded, up to 64 MiB more
/// is read and thrown away (so the writer does not get `EPIPE`), and
/// [`HookInputError::Oversized`] is returned.
pub fn read_bounded<R: Read>(mut reader: R, max: usize) -> Result<Vec<u8>, HookInputError> {
    let mut buf = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    (&mut reader)
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| HookInputError::Io { kind: e.kind() })?;
    if buf.len() > max {
        drop(buf);
        let _ = io::copy(&mut reader.take(OVERSIZE_DRAIN_LIMIT), &mut io::sink());
        return Err(HookInputError::Oversized { max });
    }
    Ok(buf)
}

/// [`read_bounded`] on the process's stdin with [`MAX_HOOK_INPUT_BYTES`].
///
/// This reads until stdin reaches EOF; Claude Code pipes the payload and closes stdin.
/// If stdin is an interactive terminal (the command was run by hand) nothing is read
/// and `Err(HookInputError::Io { kind: ErrorKind::InvalidInput })` is returned at once,
/// so the hook never sits waiting for input.
pub fn read_bounded_stdin() -> Result<Vec<u8>, HookInputError> {
    use std::io::IsTerminal;
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(HookInputError::Io {
            kind: io::ErrorKind::InvalidInput,
        });
    }
    read_bounded(stdin.lock(), MAX_HOOK_INPUT_BYTES)
}

/// What `hook_event_name` said.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PayloadEvent {
    /// The field was missing or not a string.
    #[default]
    Absent,
    /// A known event.
    Known(HookEvent),
    /// Some other event name (its text is not retained).
    Unknown,
}

/// The fields of a hook payload that PeerHarness uses. Everything else, notably
/// `transcript_path`, `last_assistant_message`, `tool_input`, `tool_response` and
/// `error`, is dropped at parse time and never stored.
///
/// `Debug` prints lengths only.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HookPayload {
    /// `hook_event_name`.
    pub event: PayloadEvent,
    /// `session_id` (only ever hashed).
    pub session_id: Option<String>,
    /// `cwd` (only ever hashed, or reduced to a basename label for local display).
    pub cwd: Option<String>,
    /// `prompt` (`UserPromptSubmit`).
    pub prompt: Option<String>,
    /// `stop_hook_active` (`Stop`).
    pub stop_hook_active: Option<bool>,
    /// `tool_name` (`PostToolUseFailure`).
    pub tool_name: Option<String>,
    /// `is_interrupt` (`PostToolUseFailure`).
    pub is_interrupt: Option<bool>,
}

impl fmt::Debug for HookPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = |o: &Option<String>| o.as_ref().map(String::len);
        f.debug_struct("HookPayload")
            .field("event", &self.event)
            .field("session_id_len", &len(&self.session_id))
            .field("cwd_len", &len(&self.cwd))
            .field("prompt_len", &len(&self.prompt))
            .field("stop_hook_active", &self.stop_hook_active)
            .field("tool_name_len", &len(&self.tool_name))
            .field("is_interrupt", &self.is_interrupt)
            .finish()
    }
}

/// Parses a hook payload leniently.
///
/// Unknown fields are ignored, missing optional fields and fields of the wrong JSON type
/// become `None`, and a leading UTF-8 BOM is tolerated. Only non-JSON input or a
/// non-object top level is an error. Never panics (serde_json bounds nesting depth).
pub fn parse_hook_payload(bytes: &[u8]) -> Result<HookPayload, HookInputError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let value: Value = serde_json::from_slice(bytes).map_err(|e| HookInputError::Malformed {
        line: e.line(),
        column: e.column(),
    })?;
    let Value::Object(obj) = value else {
        return Err(HookInputError::NotAnObject);
    };
    let string = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_owned);
    let boolean = |k: &str| obj.get(k).and_then(Value::as_bool);
    let event = match obj.get("hook_event_name").and_then(Value::as_str) {
        None => PayloadEvent::Absent,
        Some(name) => HookEvent::from_event_name(name)
            .map(PayloadEvent::Known)
            .unwrap_or(PayloadEvent::Unknown),
    };
    Ok(HookPayload {
        event,
        session_id: string("session_id"),
        cwd: string("cwd"),
        prompt: string("prompt"),
        stop_hook_active: boolean("stop_hook_active"),
        tool_name: string("tool_name"),
        is_interrupt: boolean("is_interrupt"),
    })
}

/// `Digest::domain("peerharness-session-v0", session_id)`; `None` for an empty id.
pub fn session_hash(session_id: &str) -> Option<Digest> {
    if session_id.is_empty() {
        None
    } else {
        Some(Digest::domain(SESSION_HASH_CONTEXT, session_id.as_bytes()))
    }
}

/// Trailing slashes removed, except for the root `/`.
fn trim_trailing_slashes(path: &str) -> &str {
    let t = path.trim_end_matches('/');
    if t.is_empty() && path.starts_with('/') {
        "/"
    } else {
        t
    }
}

/// The local repository key for a working directory: `"repo:"` followed by the first 16
/// hex characters of `Digest::domain("peerharness-repo-v0", cwd)`.
///
/// Trailing slashes are ignored. An empty `cwd` gives [`UNKNOWN_REPO_KEY`]. No raw path
/// is stored. The key is per directory: a session started in a subdirectory of a
/// repository gets a different key (finding the repository root would need filesystem
/// access, which normalization deliberately does not do).
pub fn repo_key(cwd: &str) -> String {
    let p = trim_trailing_slashes(cwd);
    if p.is_empty() {
        return UNKNOWN_REPO_KEY.to_owned();
    }
    let hex = Digest::domain(REPO_KEY_CONTEXT, p.as_bytes()).to_hex();
    format!("repo:{}", hex.get(..16).unwrap_or(&hex))
}

/// A short display label for a working directory, for **local display only**: its last
/// path component with every character outside `[A-Za-z0-9._-]` replaced by `_`, cut to
/// [`MAX_REPO_LABEL_CHARS`]. Gives `"unknown"` when nothing usable remains.
pub fn repo_label(cwd: &str) -> String {
    let p = trim_trailing_slashes(cwd);
    let base = p.rsplit(['/', '\\']).next().unwrap_or("");
    let label: String = base
        .chars()
        .take(MAX_REPO_LABEL_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if label.is_empty() || label == "." || label == ".." {
        "unknown".to_owned()
    } else {
        label
    }
}

/// Keeps `[A-Za-z0-9_.:-]` (MCP tool names such as `mcp__server__tool` fit), bounded.
fn sanitize_tool_name(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
        .take(MAX_TOOL_NAME_CHARS)
        .collect();
    if s.is_empty() {
        "unknown".to_owned()
    } else {
        s
    }
}

/// Turns a parsed payload into a local observation. **Pure**: no I/O of any kind.
///
/// `invoked_as` is the event named on the command line (`peerharness hook <event>`), if
/// any. The event is the payload's `hook_event_name` when present; if both are known and
/// disagree, or the payload names an event we do not handle, the result is `None`. A
/// missing `hook_event_name` falls back to `invoked_as`.
///
/// * `UserPromptSubmit` gives [`ObservationKind::UserPrompt`] with the prompt passed
///   through [`NormalizedObservation::from_raw`] (redaction, then bounding to 4 KiB).
///   An empty or whitespace-only prompt gives `None`.
/// * `Stop` gives [`ObservationKind::AgentStop`] with empty text. Assistant output is
///   never stored.
/// * `PostToolUseFailure` gives [`ObservationKind::ToolFailure`] whose text is only the
///   sanitized tool name (no input, output or error text). Interrupts
///   (`is_interrupt: true`) give `None`.
///
/// The source is always [`ObservationSource::Hook`]; `session_hash` is
/// [`session_hash`] of `session_id` and `repo_key` is [`repo_key`] of `cwd`.
pub fn normalize(
    payload: &HookPayload,
    invoked_as: Option<HookEvent>,
    id: ObservationId,
    now: Timestamp,
) -> Option<NormalizedObservation> {
    let event = match (payload.event, invoked_as) {
        (PayloadEvent::Known(p), Some(cli)) if p != cli => return None,
        (PayloadEvent::Known(p), _) => p,
        (PayloadEvent::Absent, Some(cli)) => cli,
        (PayloadEvent::Absent, None) | (PayloadEvent::Unknown, _) => return None,
    };
    let (kind, raw): (ObservationKind, String) = match event {
        HookEvent::UserPromptSubmit => {
            let prompt = payload.prompt.as_deref()?;
            if prompt.trim().is_empty() {
                return None;
            }
            (ObservationKind::UserPrompt, prompt.to_owned())
        }
        HookEvent::Stop => (ObservationKind::AgentStop, String::new()),
        HookEvent::PostToolUseFailure => {
            if payload.is_interrupt == Some(true) {
                return None;
            }
            let name = sanitize_tool_name(payload.tool_name.as_deref().unwrap_or(""));
            (ObservationKind::ToolFailure, name)
        }
    };
    let session = payload.session_id.as_deref().and_then(session_hash);
    let repo = payload
        .cwd
        .as_deref()
        .map(repo_key)
        .unwrap_or_else(|| UNKNOWN_REPO_KEY.to_owned());
    Some(NormalizedObservation::from_raw(
        id,
        now,
        ObservationSource::Hook,
        session,
        repo,
        kind,
        &raw,
    ))
}

/// Result of [`observe_hook_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookObservation {
    /// The effective event (payload `hook_event_name`, or `invoked_as` when absent), if
    /// the input could be parsed and the two agree.
    pub event: Option<HookEvent>,
    /// The normalized observation to store, if any.
    pub observation: Option<NormalizedObservation>,
}

/// Steps 1-3 of the hook flow in one call: bounded read from `reader`, lenient parse,
/// pure normalization with a fresh random [`ObservationId`].
///
/// Never fails: every error is logged at debug level as a content-free code and turns
/// into `observation: None`. The caller then stores the observation and writes
/// [`HookOutput::for_event`] for `invoked_as`.
pub fn observe_hook_input<R: Read>(
    reader: R,
    invoked_as: HookEvent,
    now: Timestamp,
) -> HookObservation {
    let none = HookObservation {
        event: None,
        observation: None,
    };
    let bytes = match read_bounded(reader, MAX_HOOK_INPUT_BYTES) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(code = e.code(), "hook input rejected");
            return none;
        }
    };
    let payload = match parse_hook_payload(&bytes) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(code = e.code(), bytes = bytes.len(), "hook input rejected");
            return none;
        }
    };
    let event = match payload.event {
        PayloadEvent::Known(e) if e == invoked_as => Some(e),
        PayloadEvent::Absent => Some(invoked_as),
        _ => {
            tracing::debug!(code = "event_mismatch", "hook input ignored");
            return none;
        }
    };
    let id = match ObservationId::random() {
        Ok(id) => id,
        Err(_) => {
            tracing::debug!(code = "randomness", "hook observation dropped");
            return HookObservation {
                event,
                observation: None,
            };
        }
    };
    let observation = normalize(&payload, Some(invoked_as), id, now);
    tracing::debug!(
        event = invoked_as.event_name(),
        observed = observation.is_some(),
        text_len = observation.as_ref().map_or(0, |o| o.text.len()),
        "hook input normalized"
    );
    HookObservation { event, observation }
}

/// What the hook process prints to stdout. The exit code is always 0.
///
/// For `UserPromptSubmit` stdout is always empty (Claude Code injects it into the
/// model's context). For `Stop` it is empty or one JSON object
/// `{"systemMessage": "..."}`, which Claude Code shows to the user.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct HookOutput {
    stdout: String,
}

impl HookOutput {
    /// The exit code our hook always uses, even after internal errors.
    pub const EXIT_CODE: i32 = 0;

    /// Empty stdout.
    pub fn silent() -> Self {
        Self::default()
    }

    /// The output for `event`: silent for everything except `Stop` with a notice.
    /// A notice for any other event is ignored.
    pub fn for_event(event: HookEvent, notice: Option<&str>) -> Self {
        match (event, notice) {
            (HookEvent::Stop, Some(msg)) => Self::stop_notice(msg),
            _ => Self::silent(),
        }
    }

    /// A `Stop` hook output carrying `{"systemMessage": message}`.
    ///
    /// The message is sanitized: control characters and bidi/format controls (terminal
    /// escape and Trojan-source vectors) are removed and it is cut to
    /// [`MAX_SYSTEM_MESSAGE_CHARS`] characters. If nothing remains the output is silent.
    /// Callers should pass only PeerHarness-authored text (for example "1 new item in
    /// `peerharness inbox`"), never prompts or peer-supplied content.
    pub fn stop_notice(message: &str) -> Self {
        let clean: String = message
            .chars()
            .filter(|&c| !is_unsafe_display_char(c))
            .take(MAX_SYSTEM_MESSAGE_CHARS)
            .collect();
        let clean = clean.trim();
        if clean.is_empty() {
            return Self::silent();
        }
        let json = serde_json::json!({ "systemMessage": clean });
        Self {
            stdout: json.to_string(),
        }
    }

    /// [`HookOutput::stop_notice`] only when [`should_notify`] allows it for `topic`
    /// given `history` of `(topic, shown_at)`; silent otherwise. The caller records the
    /// notification (topic, `now`) when the returned output is not silent.
    pub fn stop_notice_if_allowed(
        message: &str,
        policy: &NotifyPolicy,
        history: &[(String, Timestamp)],
        topic: &str,
        now: Timestamp,
    ) -> Self {
        if should_notify(policy, history, topic, now) {
            Self::stop_notice(message)
        } else {
            Self::silent()
        }
    }

    /// The exact stdout text (possibly empty, no trailing newline).
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    /// True when nothing will be printed.
    pub fn is_silent(&self) -> bool {
        self.stdout.is_empty()
    }

    /// Always [`HookOutput::EXIT_CODE`] (0).
    pub const fn exit_code(&self) -> i32 {
        Self::EXIT_CODE
    }

    /// Writes stdout (followed by a newline when non-empty) and flushes. Writes nothing
    /// at all when silent.
    pub fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        if self.stdout.is_empty() {
            return Ok(());
        }
        w.write_all(self.stdout.as_bytes())?;
        w.write_all(b"\n")?;
        w.flush()
    }
}

/// Control characters, bidi controls and other invisible format characters.
fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{061C}'
                | '\u{FEFF}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        Timestamp::from_unix_seconds(1_800_000_000).unwrap()
    }

    fn id() -> ObservationId {
        ObservationId::new("obs_test").unwrap()
    }

    #[test]
    fn event_names_round_trip() {
        for e in HookEvent::ALL {
            assert_eq!(HookEvent::from_event_name(e.event_name()), Some(e));
            assert_eq!(HookEvent::from_cli_arg(e.cli_arg()), Some(e));
            assert_eq!(e.cli_arg().parse::<HookEvent>().unwrap(), e);
            assert_eq!(e.event_name().parse::<HookEvent>().unwrap(), e);
        }
        assert!("userpromptsubmit".parse::<HookEvent>().is_err());
    }

    #[test]
    fn read_bounded_accepts_exact_limit_and_rejects_more() {
        let data = [b'a'; 10];
        assert_eq!(read_bounded(&data[..], 10).unwrap().len(), 10);
        assert_eq!(
            read_bounded(&data[..], 9),
            Err(HookInputError::Oversized { max: 9 })
        );
        assert_eq!(read_bounded(&b""[..], 9).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn read_bounded_drains_oversized_input() {
        let data = vec![b'x'; 1000];
        let mut cursor = io::Cursor::new(data);
        assert!(read_bounded(&mut cursor, 10).is_err());
        assert_eq!(cursor.position(), 1000);
    }

    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "secret-ish detail",
            ))
        }
    }

    #[test]
    fn read_error_has_no_detail() {
        let e = read_bounded(FailingReader, 10).unwrap_err();
        assert_eq!(e.code(), "io");
        assert!(!e.to_string().contains("secret"));
    }

    #[test]
    fn parse_is_lenient() {
        let p = parse_hook_payload(
            br#"{"hook_event_name":"UserPromptSubmit","prompt":42,"session_id":null,"cwd":"/r","extra":{"x":[1,2]}}"#,
        )
        .unwrap();
        assert_eq!(p.event, PayloadEvent::Known(HookEvent::UserPromptSubmit));
        assert_eq!(p.prompt, None);
        assert_eq!(p.session_id, None);
        assert_eq!(p.cwd.as_deref(), Some("/r"));
        let p = parse_hook_payload(b"\xEF\xBB\xBF{}").unwrap();
        assert_eq!(p, HookPayload::default());
        assert_eq!(
            parse_hook_payload(br#"{"hook_event_name":"Bogus"}"#)
                .unwrap()
                .event,
            PayloadEvent::Unknown
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(
            parse_hook_payload(b"[]").unwrap_err(),
            HookInputError::NotAnObject
        );
        assert_eq!(parse_hook_payload(b"").unwrap_err().code(), "malformed");
        assert_eq!(
            parse_hook_payload(b"{\"a\":").unwrap_err().code(),
            "malformed"
        );
        assert_eq!(
            parse_hook_payload(b"\xff\xfe").unwrap_err().code(),
            "malformed"
        );
        // Deep nesting is rejected by serde_json's recursion limit, not a stack overflow.
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert_eq!(
            parse_hook_payload(deep.as_bytes()).unwrap_err().code(),
            "malformed"
        );
    }

    #[test]
    fn malformed_error_does_not_echo_input() {
        let e =
            parse_hook_payload(br#"{"prompt": "sk-ant-api03-FAKEFAKEFAKEFAKE" oops}"#).unwrap_err();
        assert!(!e.to_string().contains("FAKE"));
        assert!(!format!("{e:?}").contains("FAKE"));
    }

    #[test]
    fn debug_of_payload_hides_text() {
        let p = HookPayload {
            prompt: Some("very private prompt".into()),
            cwd: Some("/home/alice/secret-project".into()),
            ..HookPayload::default()
        };
        let d = format!("{p:?}");
        assert!(!d.contains("private"));
        assert!(!d.contains("secret-project"));
    }

    #[test]
    fn event_resolution() {
        let mut p = HookPayload {
            event: PayloadEvent::Known(HookEvent::Stop),
            ..HookPayload::default()
        };
        assert!(normalize(&p, Some(HookEvent::Stop), id(), ts()).is_some());
        assert!(normalize(&p, None, id(), ts()).is_some());
        assert!(normalize(&p, Some(HookEvent::UserPromptSubmit), id(), ts()).is_none());
        p.event = PayloadEvent::Absent;
        assert!(normalize(&p, Some(HookEvent::Stop), id(), ts()).is_some());
        assert!(normalize(&p, None, id(), ts()).is_none());
        p.event = PayloadEvent::Unknown;
        assert!(normalize(&p, Some(HookEvent::Stop), id(), ts()).is_none());
    }

    #[test]
    fn prompt_required_for_user_prompt() {
        let mut p = HookPayload {
            event: PayloadEvent::Known(HookEvent::UserPromptSubmit),
            ..HookPayload::default()
        };
        assert!(normalize(&p, None, id(), ts()).is_none());
        p.prompt = Some("  \n\t ".into());
        assert!(normalize(&p, None, id(), ts()).is_none());
        p.prompt = Some("use pnpm".into());
        let o = normalize(&p, None, id(), ts()).unwrap();
        assert_eq!(o.kind, ObservationKind::UserPrompt);
        assert_eq!(o.text, "use pnpm");
        assert_eq!(o.repo_key, UNKNOWN_REPO_KEY);
        assert_eq!(o.session_hash, None);
        assert_eq!(o.source, ObservationSource::Hook);
        assert_eq!(o.created_at, ts());
    }

    #[test]
    fn tool_failure_keeps_only_sanitized_name() {
        let mut p = HookPayload {
            event: PayloadEvent::Known(HookEvent::PostToolUseFailure),
            tool_name: Some("mcp__srv__do it; rm -rf /\n".into()),
            ..HookPayload::default()
        };
        let o = normalize(&p, None, id(), ts()).unwrap();
        assert_eq!(o.kind, ObservationKind::ToolFailure);
        assert_eq!(o.text, "mcp__srv__doitrm-rf");
        p.tool_name = None;
        assert_eq!(normalize(&p, None, id(), ts()).unwrap().text, "unknown");
        p.tool_name = Some("x".repeat(1000));
        assert_eq!(
            normalize(&p, None, id(), ts()).unwrap().text.len(),
            MAX_TOOL_NAME_CHARS
        );
        p.is_interrupt = Some(true);
        assert!(normalize(&p, None, id(), ts()).is_none());
    }

    #[test]
    fn repo_key_shape_and_stability() {
        let k = repo_key("/home/a/proj");
        assert!(k.starts_with("repo:"));
        assert_eq!(k.len(), 5 + 16);
        assert!(k[5..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(k, repo_key("/home/a/proj/"));
        assert_eq!(k, repo_key("/home/a/proj///"));
        assert_ne!(k, repo_key("/home/a/proj2"));
        assert!(!k.contains("proj"));
        assert_eq!(repo_key(""), UNKNOWN_REPO_KEY);
        assert_eq!(repo_key("/"), repo_key("//"));
        assert_ne!(repo_key("/"), UNKNOWN_REPO_KEY);
        // Matches the documented derivation.
        let expected = Digest::domain(REPO_KEY_CONTEXT, b"/home/a/proj").to_hex();
        assert_eq!(k, format!("repo:{}", &expected[..16]));
    }

    #[test]
    fn repo_label_sanitizes() {
        assert_eq!(repo_label("/home/a/my-proj"), "my-proj");
        assert_eq!(repo_label("/home/a/my proj/"), "my_proj");
        assert_eq!(repo_label("C:\\Users\\a\\repo"), "repo");
        assert_eq!(repo_label("/x/\u{1b}[31mevil"), "__31mevil");
        assert_eq!(repo_label("/"), "unknown");
        assert_eq!(repo_label(""), "unknown");
        assert_eq!(repo_label("/a/.."), "unknown");
        assert_eq!(repo_label(&format!("/{}", "a".repeat(500))).len(), 64);
    }

    #[test]
    fn session_hash_is_domain_separated() {
        let h = session_hash("abc").unwrap();
        assert_eq!(h, Digest::domain(SESSION_HASH_CONTEXT, b"abc"));
        assert_ne!(h, Digest::sha256(b"abc"));
        assert_eq!(session_hash(""), None);
    }

    #[test]
    fn hook_output_rules() {
        assert!(HookOutput::for_event(HookEvent::UserPromptSubmit, Some("hi")).is_silent());
        assert!(HookOutput::for_event(HookEvent::PostToolUseFailure, Some("hi")).is_silent());
        assert!(HookOutput::for_event(HookEvent::Stop, None).is_silent());
        let o = HookOutput::for_event(HookEvent::Stop, Some("1 new question"));
        assert_eq!(o.stdout(), r#"{"systemMessage":"1 new question"}"#);
        assert_eq!(o.exit_code(), 0);
        let mut out = Vec::new();
        o.write_to(&mut out).unwrap();
        assert_eq!(out, b"{\"systemMessage\":\"1 new question\"}\n");
        let mut out = Vec::new();
        HookOutput::silent().write_to(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn stop_notice_is_sanitized_and_bounded() {
        let o = HookOutput::stop_notice("\u{1b}]0;pwn\u{7}hi\u{202e}there\n");
        let v: Value = serde_json::from_str(o.stdout()).unwrap();
        assert_eq!(v["systemMessage"], "]0;pwnhithere");
        assert!(HookOutput::stop_notice("\u{1b}\u{7}\n").is_silent());
        let o = HookOutput::stop_notice(&"é".repeat(1000));
        let v: Value = serde_json::from_str(o.stdout()).unwrap();
        assert_eq!(
            v["systemMessage"].as_str().unwrap().chars().count(),
            MAX_SYSTEM_MESSAGE_CHARS
        );
    }

    #[test]
    fn stop_notice_if_allowed_respects_throttle() {
        let policy = NotifyPolicy::default();
        let now = ts();
        assert!(!HookOutput::stop_notice_if_allowed("m", &policy, &[], "t", now).is_silent());
        let hist = vec![("t".to_owned(), now.minus_secs(10))];
        assert!(HookOutput::stop_notice_if_allowed("m", &policy, &hist, "t", now).is_silent());
    }
}
