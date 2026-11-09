//! Claude Code CLI provider (`claude -p`). Remote inference through the user's own
//! login; PeerHarness passes no credentials.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use super::process::{prepare, run_bounded, Sandbox};
use super::{
    sanitize_output, validate_model, AdvisoryRequest, AdvisoryResponse, AgentProvider,
    ProviderError, CLAUDE_BIN_ENV, DEFAULT_TIMEOUT_SECS, MAX_OUTPUT_BYTES,
};

/// Spawns the user's unmodified `claude` binary, non-interactively:
///
/// ```text
/// claude -p --output-format json --max-turns 1 --no-session-persistence \
///        --disable-slash-commands --strict-mcp-config [--model <m>] --tools ""
/// ```
///
/// * The prompt ([`AdvisoryRequest::exact_payload`], already redacted) goes on **stdin**,
///   never on the command line (so it is not visible in `ps` and cannot be parsed as an
///   option). `--tools` is variadic, so it is last and no positional argument follows.
/// * `--tools ""` disables every built-in tool; `--strict-mcp-config` (with no
///   `--mcp-config`) loads no MCP servers, so no MCP tools exist either;
///   `--disable-slash-commands` disables skills and commands; `--max-turns 1` (a hidden but supported flag in Claude Code
///   2.x) allows one model turn; `--no-session-persistence` keeps nothing on disk.
/// * cwd is a fresh empty temporary directory, so no repository content or `CLAUDE.md`
///   is in reach. stderr is discarded.
/// * stdout is capped at [`MAX_OUTPUT_BYTES`] and the child is killed on timeout.
///
/// Flags were verified against `claude --help` of Claude Code 2.1.
#[derive(Clone, Debug)]
pub struct ClaudeCodeCli {
    binary: PathBuf,
    model: Option<String>,
    timeout: Duration,
}

impl ClaudeCodeCli {
    /// Uses `binary` (a path, or a bare name looked up on `PATH`) with the default
    /// timeout and model.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            model: None,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Uses `$PEERHARNESS_CLAUDE_BIN`, or `claude` on `PATH`.
    pub fn from_env() -> Self {
        Self::new(super::resolve_binary(None, CLAUDE_BIN_ENV, "claude"))
    }

    /// Sets the model passed as `--model` (validated with [`validate_model`]).
    pub fn with_model(mut self, model: &str) -> Result<Self, ProviderError> {
        validate_model(model)?;
        self.model = Some(model.to_owned());
        Ok(self)
    }

    /// Sets the timeout for one completion.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The binary that will be spawned.
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// The exact argument vector (without the program name).
    pub fn args(&self) -> Vec<OsString> {
        let mut a: Vec<OsString> = [
            "-p",
            "--output-format",
            "json",
            "--max-turns",
            "1",
            "--no-session-persistence",
            "--disable-slash-commands",
            "--strict-mcp-config",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        if let Some(m) = &self.model {
            a.push("--model".into());
            a.push(m.into());
        }
        a.push("--tools".into());
        a.push("".into());
        a
    }
}

impl AgentProvider for ClaudeCodeCli {
    fn name(&self) -> &str {
        "claude-code"
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn disclosure(&self) -> String {
        "REMOTE: this text will be sent to Anthropic for inference by your own `claude` \
         login (Claude Code CLI, tools disabled, one turn, no session saved)."
            .to_owned()
    }

    fn complete(&self, req: &AdvisoryRequest) -> Result<AdvisoryResponse, ProviderError> {
        let payload = req.exact_payload();
        let sandbox = Sandbox::new()?;
        let mut cmd = Command::new(&self.binary);
        cmd.args(self.args());
        prepare(&mut cmd, sandbox.work_dir());
        tracing::debug!(
            provider = "claude-code",
            payload_bytes = payload.len(),
            "spawning advisory provider"
        );
        let out = run_bounded(&mut cmd, payload.as_bytes(), self.timeout, MAX_OUTPUT_BYTES)?;
        let parsed = parse_claude_json(&out.stdout);
        match parsed {
            Ok(text) if out.status.success() => Ok(AdvisoryResponse {
                text,
                provider: self.name().to_owned(),
            }),
            Ok(_) => Err(ProviderError::ExitStatus(out.status.code())),
            Err(ProviderError::Malformed(_)) if !out.status.success() => {
                Err(ProviderError::ExitStatus(out.status.code()))
            }
            Err(e) => Err(e),
        }
    }
}

/// Parses `claude -p --output-format json` stdout and returns the sanitized `result`.
///
/// Accepts the single result object
/// `{"type":"result","subtype":"success","is_error":false,"result":"..."}`, an array of
/// messages (the last `type == "result"` element is used), or JSON lines (the last line
/// that parses). `is_error: true`, or a `subtype` starting with `error`, gives
/// [`ProviderError::Reported`]; a missing or non-string `result` gives
/// [`ProviderError::Malformed`].
pub fn parse_claude_json(stdout: &[u8]) -> Result<String, ProviderError> {
    let text = String::from_utf8_lossy(stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ProviderError::Malformed("empty output"));
    }
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => trimmed
            .lines()
            .rev()
            .filter(|l| !l.trim().is_empty())
            .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .ok_or(ProviderError::Malformed("not JSON"))?,
    };
    let obj = match &value {
        Value::Array(items) => items
            .iter()
            .rev()
            .find(|v| v.get("type").and_then(Value::as_str) == Some("result"))
            .ok_or(ProviderError::Malformed("no result message"))?,
        Value::Object(_) => &value,
        _ => return Err(ProviderError::Malformed("unexpected JSON shape")),
    };
    match obj.get("type") {
        None => {}
        Some(Value::String(t)) if t == "result" => {}
        Some(_) => return Err(ProviderError::Malformed("not a result message")),
    }
    if obj.get("is_error").and_then(Value::as_bool) == Some(true) {
        return Err(ProviderError::Reported);
    }
    if obj
        .get("subtype")
        .and_then(Value::as_str)
        .is_some_and(|s| s.starts_with("error"))
    {
        return Err(ProviderError::Reported);
    }
    match obj.get("result") {
        Some(Value::String(s)) => {
            let s = sanitize_output(s);
            if s.is_empty() {
                Err(ProviderError::Malformed("empty result"))
            } else {
                Ok(s)
            }
        }
        _ => Err(ProviderError::Malformed("missing result")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_end_with_empty_tools_and_have_no_prompt() {
        let p = ClaudeCodeCli::new("claude").with_model("sonnet").unwrap();
        let a = p.args();
        assert_eq!(a.last().unwrap(), "");
        assert_eq!(a.get(a.len() - 2).unwrap(), "--tools");
        assert!(a.iter().any(|x| x == "--no-session-persistence"));
        assert!(a.iter().any(|x| x == "--strict-mcp-config"));
        assert!(a.windows(2).any(|w| w[0] == "--max-turns" && w[1] == "1"));
        assert!(a.windows(2).any(|w| w[0] == "--model" && w[1] == "sonnet"));
        assert!(ClaudeCodeCli::new("claude")
            .with_model("--dangerously-skip-permissions")
            .is_err());
    }

    #[test]
    fn parse_variants() {
        assert_eq!(
            parse_claude_json(br#"{"type":"result","subtype":"success","is_error":false,"result":"ok\u001b[31m"}"#).unwrap(),
            "ok[31m"
        );
        assert!(matches!(
            parse_claude_json(br#"{"type":"result","is_error":true,"result":"secret details"}"#),
            Err(ProviderError::Reported)
        ));
        assert!(matches!(
            parse_claude_json(br#"{"type":"result","subtype":"error_max_turns","is_error":false}"#),
            Err(ProviderError::Reported)
        ));
        assert_eq!(
            parse_claude_json(
                br#"[{"type":"system"},{"type":"result","is_error":false,"result":"a"}]"#
            )
            .unwrap(),
            "a"
        );
        assert_eq!(
            parse_claude_json(b"{\"type\":\"system\"}\n{\"type\":\"result\",\"result\":\"b\"}\n")
                .unwrap(),
            "b"
        );
        for bad in [
            &b""[..],
            b"hello",
            b"[1,2]",
            b"42",
            br#"{"type":"assistant"}"#,
            br#"{"result":5}"#,
        ] {
            assert!(matches!(
                parse_claude_json(bad),
                Err(ProviderError::Malformed(_))
            ));
        }
    }
}
