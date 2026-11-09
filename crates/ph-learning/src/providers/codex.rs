//! Codex CLI provider (`codex exec`). Remote inference through the user's own login;
//! PeerHarness passes no credentials.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::process::{prepare, run_bounded, Sandbox};
use super::{
    sanitize_output, validate_model, AdvisoryRequest, AdvisoryResponse, AgentProvider,
    ProviderError, CODEX_BIN_ENV, DEFAULT_TIMEOUT_SECS, MAX_OUTPUT_BYTES,
};

const LAST_MESSAGE_FILE: &str = "last-message.txt";

/// Spawns the user's unmodified `codex` binary, non-interactively:
///
/// ```text
/// codex exec --sandbox read-only --skip-git-repo-check --ephemeral --ignore-rules \
///            --color never -c approval_policy="never" --disable shell_tool \
///            -C <empty tmp dir> --output-last-message <tmp>/last-message.txt [-m <model>] -
/// ```
///
/// * The prompt ([`AdvisoryRequest::exact_payload`], already redacted) goes on stdin
///   (`-` as the prompt argument means "read stdin").
/// * `--disable shell_tool` removes the shell tool, so the model cannot run commands at
///   all. Without it, `read-only` would still let model-generated commands *read* any
///   file (for example `~/.ssh`) and send the output to the model, and a hostile
///   `SKILL.md` under review could ask for exactly that.
/// * `--sandbox read-only` and `approval_policy="never"` mean any remaining tool cannot
///   write and nothing waits for approval; `--ephemeral` persists no session
///   files; cwd (and `-C`) is a fresh empty temporary directory.
/// * The answer is read from the `--output-last-message` file (capped at
///   [`MAX_OUTPUT_BYTES`]); stdout is drained under the same cap and otherwise ignored;
///   stderr is discarded. The child is killed on timeout.
///
/// Flags were verified against `codex exec --help` of codex-cli 0.167.
#[derive(Clone, Debug)]
pub struct CodexCli {
    binary: PathBuf,
    model: Option<String>,
    timeout: Duration,
}

impl CodexCli {
    /// Uses `binary` (a path, or a bare name looked up on `PATH`) with the default
    /// timeout and model.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            model: None,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Uses `$PEERHARNESS_CODEX_BIN`, or `codex` on `PATH`.
    pub fn from_env() -> Self {
        Self::new(super::resolve_binary(None, CODEX_BIN_ENV, "codex"))
    }

    /// Sets the model passed as `-m` (validated with [`validate_model`]).
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

    /// The exact argument vector (without the program name) for a given working
    /// directory and output file.
    pub fn args(&self, work_dir: &Path, last_message: &Path) -> Vec<OsString> {
        let mut a: Vec<OsString> = [
            "exec",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-rules",
            "--color",
            "never",
            "-c",
            "approval_policy=\"never\"",
            "--disable",
            "shell_tool",
            "-C",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        a.push(work_dir.as_os_str().to_owned());
        a.push("--output-last-message".into());
        a.push(last_message.as_os_str().to_owned());
        if let Some(m) = &self.model {
            a.push("-m".into());
            a.push(m.into());
        }
        a.push("-".into());
        a
    }
}

fn read_capped(path: &Path) -> Result<Vec<u8>, ProviderError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProviderError::Malformed("no final message written"))
        }
        Err(e) => return Err(ProviderError::Io(e.kind())),
    };
    let mut buf = Vec::new();
    file.take(MAX_OUTPUT_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| ProviderError::Io(e.kind()))?;
    if buf.len() > MAX_OUTPUT_BYTES {
        return Err(ProviderError::OutputTooLarge {
            max: MAX_OUTPUT_BYTES,
        });
    }
    Ok(buf)
}

impl AgentProvider for CodexCli {
    fn name(&self) -> &str {
        "codex"
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn disclosure(&self) -> String {
        "REMOTE: this text will be sent to the model provider configured in your own \
         `codex` login (Codex CLI, read-only sandbox, no approvals, no session saved)."
            .to_owned()
    }

    fn complete(&self, req: &AdvisoryRequest) -> Result<AdvisoryResponse, ProviderError> {
        let payload = req.exact_payload();
        let sandbox = Sandbox::new()?;
        let last = sandbox.output_path(LAST_MESSAGE_FILE);
        let mut cmd = Command::new(&self.binary);
        cmd.args(self.args(sandbox.work_dir(), &last));
        prepare(&mut cmd, sandbox.work_dir());
        tracing::debug!(
            provider = "codex",
            payload_bytes = payload.len(),
            "spawning advisory provider"
        );
        let out = run_bounded(&mut cmd, payload.as_bytes(), self.timeout, MAX_OUTPUT_BYTES)?;
        if !out.status.success() {
            return Err(ProviderError::ExitStatus(out.status.code()));
        }
        let raw = read_capped(&last)?;
        let text = sanitize_output(&String::from_utf8_lossy(&raw));
        if text.is_empty() {
            return Err(ProviderError::Malformed("empty final message"));
        }
        Ok(AdvisoryResponse {
            text,
            provider: self.name().to_owned(),
        })
    }
}
