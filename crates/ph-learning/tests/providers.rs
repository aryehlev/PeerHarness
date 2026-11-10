//! Provider tests with fake `claude` / `codex` executables and a tiny local HTTP server.
//! No real agent CLI or model is ever invoked.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ph_core::{Confidence, ObservationId, SkillCandidate};
use ph_learning::providers::{
    check_endpoint, parse_claude_json, ADVISORY_CHILD_ENV, DEFAULT_OLLAMA_URL, MAX_OUTPUT_BYTES,
};
use ph_learning::{
    build_provider, AdvisoryPurpose, AdvisoryRequest, AgentProvider, ClaudeCodeCli, CodexCli,
    OllamaLocal, ProviderConfig, ProviderError, ProviderKind,
};

const FAKE_SECRET: &str = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKE";
const FAKE_GH: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

fn secret_request() -> AdvisoryRequest {
    AdvisoryRequest::new(
        AdvisoryPurpose::RefineCandidate,
        format!(
            "Statement: This repository uses pnpm, not npm. key={FAKE_SECRET} token {FAKE_GH} \
             see /Users/alice/work/repo"
        ),
    )
}

/// Writes an executable `/bin/sh` script `name` into `dir`. `@DIR@` in `body` is replaced
/// by `dir`.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let text = format!(
        "#!/bin/sh\n{}\n",
        body.replace("@DIR@", &dir.display().to_string())
    );
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f.sync_all().unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Records stdin, args, cwd listing and selected env into @DIR@.
const RECORD: &str = r#"ls -A > "@DIR@/cwd_listing.txt"
pwd > "@DIR@/cwd.txt"
cat > "@DIR@/stdin.txt"
for a in "$@"; do printf '[%s]\n' "$a"; done > "@DIR@/args.txt"
printf '%s' "${PEERHARNESS_ADVISORY_CHILD:-unset}" > "@DIR@/child_env.txt""#;

fn read(dir: &Path, f: &str) -> String {
    std::fs::read_to_string(dir.join(f)).unwrap()
}

// ---------------------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------------------

#[test]
fn claude_success_redacts_and_uses_expected_flags() {
    let dir = tempfile::tempdir().unwrap();
    let bin = script(
        dir.path(),
        "claude",
        &format!(
            "{RECORD}\necho '{{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"num_turns\":1,\"result\":\"This repository uses pnpm instead of npm.\\u001b[0m\",\"session_id\":\"x\"}}'"
        ),
    );
    let p = ClaudeCodeCli::new(&bin)
        .with_model("sonnet")
        .unwrap()
        .with_timeout(Duration::from_secs(20));
    assert_eq!(p.name(), "claude-code");
    assert!(p.is_remote());
    let req = secret_request();
    let resp = p.complete(&req).unwrap();
    assert_eq!(resp.provider, "claude-code");
    assert_eq!(resp.text, "This repository uses pnpm instead of npm.[0m");

    let stdin = read(dir.path(), "stdin.txt");
    assert_eq!(
        stdin,
        req.exact_payload(),
        "sent bytes must equal the preview payload"
    );
    assert!(!stdin.contains("FAKEFAKE"));
    assert!(!stdin.contains(FAKE_GH));
    assert!(!stdin.contains("/Users/alice"));
    assert!(stdin.contains("[REDACTED]"));
    assert!(stdin.contains("This repository uses pnpm, not npm."));

    let args = read(dir.path(), "args.txt");
    assert_eq!(
        args,
        "[-p]\n[--output-format]\n[json]\n[--max-turns]\n[1]\n[--no-session-persistence]\n\
         [--disable-slash-commands]\n[--strict-mcp-config]\n[--model]\n[sonnet]\n[--tools]\n[]\n"
    );
    assert!(
        !args.contains("pnpm"),
        "the prompt must not be on the command line"
    );
    assert_eq!(read(dir.path(), "cwd_listing.txt"), "", "cwd must be empty");
    let cwd = read(dir.path(), "cwd.txt");
    assert!(cwd.contains("peerharness-advisory-"), "{cwd}");
    assert!(
        !Path::new(cwd.trim()).exists(),
        "temp dir is removed afterwards"
    );
    assert_eq!(read(dir.path(), "child_env.txt"), "1");
}

#[test]
fn claude_is_error_true_is_reported_without_message() {
    let dir = tempfile::tempdir().unwrap();
    let bin = script(
        dir.path(),
        "claude",
        "cat >/dev/null\necho '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"result\":\"Invalid API key PRIVATE-DETAIL\"}'\nexit 1",
    );
    let err = ClaudeCodeCli::new(&bin)
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Reported), "{err:?}");
    assert!(!err.to_string().contains("PRIVATE-DETAIL"));
}

#[test]
fn claude_malformed_output() {
    let dir = tempfile::tempdir().unwrap();
    let bin = script(
        dir.path(),
        "claude",
        "cat >/dev/null\necho 'hello, not json'",
    );
    let err = ClaudeCodeCli::new(&bin)
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");

    let bin = script(
        dir.path(),
        "claude2",
        "cat >/dev/null\necho '{\"type\":\"result\",\"is_error\":false}'",
    );
    let err = ClaudeCodeCli::new(&bin)
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");

    let bin = script(
        dir.path(),
        "claude3",
        "cat >/dev/null\necho garbage\nexit 3",
    );
    let err = ClaudeCodeCli::new(&bin)
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::ExitStatus(Some(3))), "{err:?}");

    let bin = script(
        dir.path(),
        "claude4",
        "cat >/dev/null\necho '{\"type\":\"result\",\"is_error\":false,\"result\":\"ok\"}'\nexit 2",
    );
    let err = ClaudeCodeCli::new(&bin)
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::ExitStatus(Some(2))), "{err:?}");
}

#[test]
fn claude_timeout_kills_child() {
    let dir = tempfile::tempdir().unwrap();
    let bin = script(
        dir.path(),
        "claude",
        "sleep 5\necho '{\"type\":\"result\",\"result\":\"late\"}'",
    );
    let start = Instant::now();
    let err = ClaudeCodeCli::new(&bin)
        .with_timeout(Duration::from_secs(1))
        .complete(&secret_request())
        .unwrap_err();
    let elapsed = start.elapsed();
    assert!(matches!(err, ProviderError::Timeout { secs: 1 }), "{err:?}");
    assert!(elapsed < Duration::from_secs(4), "took {elapsed:?}");
}

#[test]
fn claude_huge_output_is_capped() {
    let dir = tempfile::tempdir().unwrap();
    // Endless output: must be cut off at the cap, not at the timeout.
    let bin = script(
        dir.path(),
        "claude",
        "cat >/dev/null\nyes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let start = Instant::now();
    let err = ClaudeCodeCli::new(&bin)
        .with_timeout(Duration::from_secs(30))
        .complete(&secret_request())
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::OutputTooLarge { max } if max == MAX_OUTPUT_BYTES),
        "{err:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(10));

    // Finite but over the cap.
    let bin = script(
        dir.path(),
        "claude2",
        &format!(
            "cat >/dev/null\nhead -c {} /dev/zero | tr '\\0' a",
            MAX_OUTPUT_BYTES + 10
        ),
    );
    let err = ClaudeCodeCli::new(&bin)
        .complete(&secret_request())
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::OutputTooLarge { .. }),
        "{err:?}"
    );
}

#[test]
fn claude_child_that_ignores_stdin_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let bin = script(
        dir.path(),
        "claude",
        "echo '{\"type\":\"result\",\"result\":\"fine\"}'",
    );
    let big = AdvisoryRequest::new(AdvisoryPurpose::ReviewSkill, "word ".repeat(6000));
    let resp = ClaudeCodeCli::new(&bin).complete(&big).unwrap();
    assert_eq!(resp.text, "fine");
}

#[test]
fn missing_binary_is_spawn_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = ClaudeCodeCli::new(dir.path().join("does-not-exist"))
        .complete(&secret_request())
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::Spawn(std::io::ErrorKind::NotFound)),
        "{err:?}"
    );
    let err = CodexCli::new(dir.path().join("nope"))
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Spawn(_)), "{err:?}");
}

#[test]
fn parse_claude_json_is_public_and_defensive() {
    assert_eq!(
        parse_claude_json(br#"{"type":"result","is_error":false,"result":" hi \n"}"#).unwrap(),
        "hi"
    );
    assert!(parse_claude_json(&[0xff, 0xfe, 0x00]).is_err());
    let deep = "[".repeat(10_000);
    assert!(parse_claude_json(deep.as_bytes()).is_err());
}

// ---------------------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------------------

const CODEX_FIND_OUT: &str = r#"out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "--output-last-message" ]; then out="$a"; fi
  prev="$a"
done"#;

#[test]
fn codex_success_redacts_and_uses_expected_flags() {
    let dir = tempfile::tempdir().unwrap();
    let bin = script(
        dir.path(),
        "codex",
        &format!(
            "{RECORD}\n{CODEX_FIND_OUT}\necho 'some progress output'\nprintf 'Looks fine.\\n\\033[31m- one point\\n' > \"$out\""
        ),
    );
    let p = CodexCli::new(&bin)
        .with_model("gpt-5")
        .unwrap()
        .with_timeout(Duration::from_secs(20));
    assert_eq!(p.name(), "codex");
    assert!(p.is_remote());
    let req = secret_request();
    let resp = p.complete(&req).unwrap();
    assert_eq!(resp.provider, "codex");
    assert_eq!(resp.text, "Looks fine.\n[31m- one point");

    let stdin = read(dir.path(), "stdin.txt");
    assert_eq!(stdin, req.exact_payload());
    assert!(!stdin.contains("FAKEFAKE"));
    assert!(stdin.contains("[REDACTED]"));

    let args = read(dir.path(), "args.txt");
    let lines: Vec<&str> = args.lines().collect();
    assert_eq!(lines[0], "[exec]");
    for flag in [
        "[--sandbox]\n[read-only]",
        "[--skip-git-repo-check]",
        "[--ephemeral]",
        "[--ignore-rules]",
        "[-c]\n[approval_policy=\"never\"]",
        "[--disable]\n[shell_tool]",
        "[-m]\n[gpt-5]",
        "[--output-last-message]",
        "[-C]",
    ] {
        assert!(args.contains(flag), "missing {flag} in {args}");
    }
    assert_eq!(*lines.last().unwrap(), "[-]", "prompt must come from stdin");
    assert!(!args.contains("pnpm"));
    assert_eq!(read(dir.path(), "cwd_listing.txt"), "");
    assert_eq!(read(dir.path(), "child_env.txt"), "1");
}

#[test]
fn codex_failures() {
    let dir = tempfile::tempdir().unwrap();
    // No last-message file.
    let bin = script(dir.path(), "codex1", "cat >/dev/null\necho done");
    let err = CodexCli::new(&bin).complete(&secret_request()).unwrap_err();
    assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");
    // Empty last message.
    let bin = script(
        dir.path(),
        "codex2",
        &format!("cat >/dev/null\n{CODEX_FIND_OUT}\n: > \"$out\""),
    );
    let err = CodexCli::new(&bin).complete(&secret_request()).unwrap_err();
    assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");
    // Failure exit.
    let bin = script(
        dir.path(),
        "codex3",
        &format!("cat >/dev/null\n{CODEX_FIND_OUT}\necho hi > \"$out\"\nexit 7"),
    );
    let err = CodexCli::new(&bin).complete(&secret_request()).unwrap_err();
    assert!(matches!(err, ProviderError::ExitStatus(Some(7))), "{err:?}");
    // Huge last message.
    let bin = script(
        dir.path(),
        "codex4",
        &format!(
            "cat >/dev/null\n{CODEX_FIND_OUT}\nhead -c {} /dev/zero | tr '\\0' a > \"$out\"",
            MAX_OUTPUT_BYTES + 1
        ),
    );
    let err = CodexCli::new(&bin).complete(&secret_request()).unwrap_err();
    assert!(
        matches!(err, ProviderError::OutputTooLarge { .. }),
        "{err:?}"
    );
    // Timeout.
    let bin = script(dir.path(), "codex5", "sleep 5");
    let start = Instant::now();
    let err = CodexCli::new(&bin)
        .with_timeout(Duration::from_secs(1))
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Timeout { .. }), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(4));
    // Huge stdout.
    let bin = script(
        dir.path(),
        "codex6",
        "cat >/dev/null\nyes bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let err = CodexCli::new(&bin).complete(&secret_request()).unwrap_err();
    assert!(
        matches!(err, ProviderError::OutputTooLarge { .. }),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------------------
// Ollama
// ---------------------------------------------------------------------------------------

/// Serves exactly one HTTP request with `status` and `body`, after `delay`. Returns the
/// base URL and a handle to the received request body.
fn one_shot_server(status: u16, body: Vec<u8>, delay: Duration) -> (String, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&received);
    thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read headers.
        let header_end = loop {
            let n = s.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
        let len: usize = headers
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0);
        while buf.len() < header_end + len {
            let n = s.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        *rec.lock().unwrap() = buf[header_end..].to_vec();
        thread::sleep(delay);
        let head = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = s.write_all(head.as_bytes());
        let _ = s.write_all(&body);
        let _ = s.flush();
    });
    (format!("http://{addr}"), received)
}

#[test]
fn ollama_success_sends_redacted_prompt() {
    let (url, received) = one_shot_server(
        200,
        br#"{"model":"llama3.2","response":"This repository uses pnpm.\u0007","done":true}"#
            .to_vec(),
        Duration::ZERO,
    );
    let p = OllamaLocal::new(&url, "llama3.2", false)
        .unwrap()
        .with_timeout(Duration::from_secs(10));
    assert!(!p.is_remote());
    assert!(p.disclosure().starts_with("Local"));
    let req = secret_request();
    let resp = p.complete(&req).unwrap();
    assert_eq!(resp.text, "This repository uses pnpm.");
    assert_eq!(resp.provider, "ollama");
    let body: serde_json::Value = serde_json::from_slice(&received.lock().unwrap()).unwrap();
    assert_eq!(body["model"], "llama3.2");
    assert_eq!(body["stream"], false);
    let prompt = body["prompt"].as_str().unwrap();
    assert_eq!(prompt, req.exact_payload());
    assert!(!prompt.contains("FAKEFAKE"));
    assert!(prompt.contains("[REDACTED]"));
}

#[test]
fn ollama_error_paths() {
    let (url, _) = one_shot_server(500, br#"{"error":"boom"}"#.to_vec(), Duration::ZERO);
    let err = OllamaLocal::new(&url, "m", false)
        .unwrap()
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::HttpStatus(500)), "{err:?}");

    let (url, _) = one_shot_server(
        200,
        br#"{"error":"model not found"}"#.to_vec(),
        Duration::ZERO,
    );
    let err = OllamaLocal::new(&url, "m", false)
        .unwrap()
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Reported), "{err:?}");

    let (url, _) = one_shot_server(200, b"not json".to_vec(), Duration::ZERO);
    let err = OllamaLocal::new(&url, "m", false)
        .unwrap()
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");

    let (url, _) = one_shot_server(200, br#"{"done":true}"#.to_vec(), Duration::ZERO);
    let err = OllamaLocal::new(&url, "m", false)
        .unwrap()
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");

    let huge = format!(r#"{{"response":"{}"}}"#, "a".repeat(MAX_OUTPUT_BYTES + 10));
    let (url, _) = one_shot_server(200, huge.into_bytes(), Duration::ZERO);
    let err = OllamaLocal::new(&url, "m", false)
        .unwrap()
        .complete(&secret_request())
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::OutputTooLarge { .. }),
        "{err:?}"
    );

    let (url, _) = one_shot_server(
        200,
        br#"{"response":"late"}"#.to_vec(),
        Duration::from_secs(4),
    );
    let start = Instant::now();
    let err = OllamaLocal::new(&url, "m", false)
        .unwrap()
        .with_timeout(Duration::from_secs(1))
        .complete(&secret_request())
        .unwrap_err();
    assert!(matches!(err, ProviderError::Timeout { .. }), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(3));

    // Nothing listening.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = OllamaLocal::new(&format!("http://127.0.0.1:{port}"), "m", false)
        .unwrap()
        .with_timeout(Duration::from_secs(2))
        .complete(&secret_request())
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::Transport(_) | ProviderError::Io(_)),
        "{err:?}"
    );
}

#[test]
fn ollama_localhost_is_pinned_to_ipv4_loopback() {
    let (url, received) = one_shot_server(
        200,
        br#"{"response":"This repository uses pnpm."}"#.to_vec(),
        Duration::ZERO,
    );
    let port = url.rsplit(':').next().unwrap().to_owned();
    let p = OllamaLocal::new(&format!("http://localhost:{port}"), "m", false)
        .unwrap()
        .with_timeout(Duration::from_secs(10));
    assert_eq!(p.endpoint().base, format!("http://127.0.0.1:{port}"));
    assert!(!p.is_remote());
    let resp = p.complete(&secret_request()).unwrap();
    assert_eq!(resp.text, "This repository uses pnpm.");
    assert!(!received.lock().unwrap().is_empty());
}

#[test]
fn ollama_loopback_enforcement() {
    assert!(matches!(
        OllamaLocal::new("http://192.168.1.10:11434", "m", false),
        Err(ProviderError::NonLoopback)
    ));
    assert!(matches!(
        check_endpoint("http://example.com:11434", false),
        Err(ProviderError::NonLoopback)
    ));
    let remote = OllamaLocal::new("http://192.168.1.10:11434", "m", true).unwrap();
    assert!(remote.is_remote());
    assert!(
        check_endpoint(DEFAULT_OLLAMA_URL, false)
            .unwrap()
            .is_loopback
    );
    // Look-alike hosts, userinfo tricks and odd IP spellings never count as loopback.
    for u in [
        "http://127.0.0.1.evil.com:11434",
        "http://localhost.evil.com",
        "http://0177.0.0.1",
        "http://2130706433",
        "http://[::2]:11434",
    ] {
        assert!(
            matches!(check_endpoint(u, false), Err(ProviderError::NonLoopback)),
            "{u}"
        );
    }
    for u in [
        "http://127.0.0.1@evil.com",
        "http://evil.com@127.0.0.1",
        "http://127.0.0.1:11434@evil.com:80",
    ] {
        assert!(
            matches!(
                check_endpoint(u, true),
                Err(ProviderError::InvalidConfig(_))
            ),
            "{u}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Config, build_provider, preview
// ---------------------------------------------------------------------------------------

#[test]
fn config_defaults_and_serde() {
    let d = ProviderConfig::default();
    assert_eq!(d.kind, ProviderKind::None);
    assert!(!d.enabled);
    assert_eq!(d.ollama_url, "http://127.0.0.1:11434");
    assert!(!d.allow_non_loopback);
    assert_eq!(d.timeout_secs, 120);
    assert!(d.model.is_none() && d.binary.is_none());
    assert!(!d.is_active());

    let empty: ProviderConfig = toml::from_str("").unwrap();
    assert_eq!(empty, d);
    let c: ProviderConfig =
        toml::from_str("kind = \"claude-code\"\nenabled = true\nmodel = \"sonnet\"").unwrap();
    assert_eq!(c.kind, ProviderKind::ClaudeCode);
    assert!(c.is_active());
    assert_eq!(c.timeout_secs, 120);
    assert!(toml::from_str::<ProviderConfig>("enabeld = true").is_err());
    assert!(toml::from_str::<ProviderConfig>("kind = \"gpt\"").is_err());
    let back: ProviderConfig = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
    assert_eq!(back, c);
    let j = serde_json::to_value(&d).unwrap();
    assert_eq!(j["kind"], "none");
    for k in [
        ProviderKind::None,
        ProviderKind::ClaudeCode,
        ProviderKind::Codex,
        ProviderKind::Ollama,
    ] {
        assert_eq!(k.as_str().parse::<ProviderKind>().unwrap(), k);
    }
}

#[test]
fn build_provider_rules() {
    assert!(build_provider(&ProviderConfig::default())
        .unwrap()
        .is_none());
    // Kind set but not enabled: still none.
    let mut c = ProviderConfig {
        kind: ProviderKind::ClaudeCode,
        ..ProviderConfig::default()
    };
    assert!(build_provider(&c).unwrap().is_none());
    c.enabled = true;
    c.binary = Some(PathBuf::from("/nonexistent/claude"));
    let p = build_provider(&c).unwrap().unwrap();
    assert_eq!(p.name(), "claude-code");
    assert!(p.is_remote());

    c.kind = ProviderKind::Codex;
    let p = build_provider(&c).unwrap().unwrap();
    assert_eq!(p.name(), "codex");

    c.kind = ProviderKind::None;
    assert!(build_provider(&c).unwrap().is_none());

    let mut o = ProviderConfig {
        kind: ProviderKind::Ollama,
        enabled: true,
        ..ProviderConfig::default()
    };
    assert!(matches!(
        build_provider(&o),
        Err(ProviderError::InvalidConfig(_))
    ));
    o.model = Some("llama3.2".into());
    let p = build_provider(&o).unwrap().unwrap();
    assert!(!p.is_remote());
    o.ollama_url = "http://10.0.0.1:11434".into();
    assert!(matches!(
        build_provider(&o),
        Err(ProviderError::NonLoopback)
    ));
    o.allow_non_loopback = true;
    assert!(build_provider(&o).unwrap().unwrap().is_remote());

    let mut t = c.clone();
    t.kind = ProviderKind::ClaudeCode;
    t.timeout_secs = 0;
    assert!(matches!(
        build_provider(&t),
        Err(ProviderError::InvalidConfig(_))
    ));
    t.timeout_secs = 3601;
    assert!(build_provider(&t).is_err());
    t.timeout_secs = 5;
    t.model = Some("--dangerously-skip-permissions".into());
    assert!(matches!(
        build_provider(&t),
        Err(ProviderError::InvalidConfig(_))
    ));
    t.model = Some("a b".into());
    assert!(build_provider(&t).is_err());
}

#[test]
fn preview_shows_provider_disclosure_and_exact_payload() {
    let p = ClaudeCodeCli::new("claude");
    let req = secret_request();
    let preview = req.preview(&p);
    assert!(preview.contains("claude-code"));
    assert!(preview.contains("REMOTE"));
    assert!(preview.contains(&req.exact_payload()));
    assert!(preview.contains("refine-candidate"));
    assert!(!preview.contains("FAKEFAKE"));

    let local = OllamaLocal::new(DEFAULT_OLLAMA_URL, "m", false).unwrap();
    let lp = req.preview(&local);
    assert!(lp.contains("ollama") && lp.contains("Local"));
    assert!(!lp.contains("REMOTE"));

    // exact_payload is deterministic, bounded and stripped of controls.
    let r = AdvisoryRequest::new(
        AdvisoryPurpose::ReviewSkill,
        format!("a\u{1b}[2Jb\u{202E}c{}", "x".repeat(100_000)),
    );
    let pl = r.exact_payload();
    assert_eq!(pl, r.exact_payload());
    assert!(pl.len() < 40 * 1024);
    assert!(!pl.contains('\u{1b}') && !pl.contains('\u{202E}'));
    let dbg = format!("{r:?}");
    assert!(!dbg.contains("xxxx"));
}

#[test]
fn refine_candidate_request_contains_only_tokens() {
    let c = SkillCandidate {
        concept_key: "prefer:pnpm|avoid:npm".into(),
        repo_key: "sha256:REPOKEYSHOULDNOTLEAK".into(),
        statement: "This repository uses pnpm, not npm.".into(),
        preferred: Some("pnpm".into()),
        avoided: Some("npm".into()),
        confidence: Confidence::Medium,
        evidence: vec![ObservationId::new("obs_EVIDENCEID").unwrap()],
        suggested_skill_name: "pnpm-repository-convention".into(),
        topic: "package-manager".into(),
    };
    let r = AdvisoryRequest::refine_candidate(&c);
    let pl = r.exact_payload();
    assert!(!pl.contains("REPOKEY"));
    assert!(!pl.contains("EVIDENCEID"));
    assert!(pl.contains("Preferred: pnpm") && pl.contains("Avoided: npm"));
    assert_eq!(r.purpose, AdvisoryPurpose::RefineCandidate);
    let s = AdvisoryRequest::review_skill(&ph_learning::draft_skill(&c));
    assert!(s
        .exact_payload()
        .contains("name: pnpm-repository-convention"));
    let _ = ADVISORY_CHILD_ENV;
}
