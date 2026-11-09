//! Hook payload fixtures, normalization privacy, and the never-open-transcript rule.

use std::path::PathBuf;

use ph_core::{ObservationId, ObservationKind, ObservationSource, Timestamp, REDACTED};
use ph_observer::hook::{MAX_HOOK_INPUT_BYTES, UNKNOWN_REPO_KEY};
use ph_observer::{
    normalize, observe_hook_input, parse_hook_payload, repo_key, repo_label, session_hash,
    HookEvent, HookInputError, HookOutput, PayloadEvent,
};
use proptest::prelude::*;

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hooks")
        .join(name);
    std::fs::read(p).expect("fixture")
}

fn now() -> Timestamp {
    "2026-11-09T18:10:00Z".parse().unwrap()
}

fn id() -> ObservationId {
    ObservationId::new("obs_fixture").unwrap()
}

/// Everything an observation would put anywhere: its JSON form and Debug form.
fn all_output(o: &ph_core::NormalizedObservation) -> String {
    format!("{}\n{:?}", serde_json::to_string(o).unwrap(), o)
}

#[test]
fn user_prompt_fixture_is_redacted() {
    let p = parse_hook_payload(&fixture("user_prompt_submit_secret.json")).unwrap();
    assert_eq!(p.event, PayloadEvent::Known(HookEvent::UserPromptSubmit));
    let o = normalize(&p, Some(HookEvent::UserPromptSubmit), id(), now()).unwrap();
    assert_eq!(o.kind, ObservationKind::UserPrompt);
    assert_eq!(o.source, ObservationSource::Hook);
    assert_eq!(o.created_at, now());
    assert!(o.text.contains("use pnpm, not npm"));
    assert!(o.text.contains(REDACTED));
    let out = all_output(&o);
    for forbidden in [
        "sk-ant-api03",
        "FAKEFAKE",
        "ghp_",
        "alice",
        "acme-web",
        "transcript",
        "/nonexistent",
        "00893aaf",
    ] {
        assert!(!out.contains(forbidden), "leaked {forbidden:?}");
    }
    assert_eq!(
        o.session_hash,
        session_hash("00893aaf-19fa-41d2-8238-13269b9b3ca0")
    );
    assert_eq!(o.repo_key, repo_key("/Users/alice/src/acme-web"));
    assert_eq!(repo_label("/Users/alice/src/acme-web"), "acme-web");
}

#[test]
fn stop_fixture_stores_no_assistant_output() {
    let p = parse_hook_payload(&fixture("stop.json")).unwrap();
    assert_eq!(p.stop_hook_active, Some(false));
    let o = normalize(&p, Some(HookEvent::Stop), id(), now()).unwrap();
    assert_eq!(o.kind, ObservationKind::AgentStop);
    assert_eq!(o.text, "");
    assert!(!all_output(&o).contains("ASSISTANT-OUTPUT"));
    assert!(!format!("{p:?}").contains("ASSISTANT-OUTPUT"));
}

#[test]
fn tool_failure_fixture_keeps_only_tool_name() {
    let p = parse_hook_payload(&fixture("post_tool_use_failure.json")).unwrap();
    let o = normalize(&p, None, id(), now()).unwrap();
    assert_eq!(o.kind, ObservationKind::ToolFailure);
    assert_eq!(o.text, "Bash");
    let out = all_output(&o);
    assert!(!out.contains("TOOL-INPUT"));
    assert!(!out.contains("TOOL-ERROR"));
    assert!(!out.contains("express"));
}

#[test]
fn unknown_event_fixture_is_ignored() {
    let p = parse_hook_payload(&fixture("unknown_event.json")).unwrap();
    assert_eq!(p.event, PayloadEvent::Unknown);
    for invoked in [
        None,
        Some(HookEvent::UserPromptSubmit),
        Some(HookEvent::Stop),
    ] {
        assert!(normalize(&p, invoked, id(), now()).is_none());
    }
    let r = observe_hook_input(
        &fixture("unknown_event.json")[..],
        HookEvent::UserPromptSubmit,
        now(),
    );
    assert_eq!(r.observation, None);
    assert_eq!(r.event, None);
}

#[test]
fn malformed_fixture_is_rejected_without_echo() {
    let e = parse_hook_payload(&fixture("malformed.json")).unwrap_err();
    assert!(matches!(e, HookInputError::Malformed { .. }));
    assert!(!e.to_string().contains("FAKE"));
    let r = observe_hook_input(
        &fixture("malformed.json")[..],
        HookEvent::UserPromptSubmit,
        now(),
    );
    assert_eq!(r.observation, None);
}

#[test]
fn huge_input_is_discarded() {
    let mut huge = br#"{"hook_event_name":"UserPromptSubmit","prompt":""#.to_vec();
    huge.resize(MAX_HOOK_INPUT_BYTES + 10, b'a');
    huge.extend_from_slice(b"\"}");
    assert_eq!(
        ph_observer::read_bounded(&huge[..], MAX_HOOK_INPUT_BYTES),
        Err(HookInputError::Oversized {
            max: MAX_HOOK_INPUT_BYTES
        })
    );
    let r = observe_hook_input(&huge[..], HookEvent::UserPromptSubmit, now());
    assert_eq!(r.observation, None);
}

#[test]
fn large_but_allowed_prompt_is_bounded() {
    let prompt = format!(
        "{} sk-ant-api03-FAKEFAKEFAKEFAKEFAKE {}",
        "x ".repeat(200_000),
        "y ".repeat(100)
    );
    let payload = serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": prompt});
    let bytes = serde_json::to_vec(&payload).unwrap();
    assert!(bytes.len() < MAX_HOOK_INPUT_BYTES);
    let r = observe_hook_input(&bytes[..], HookEvent::UserPromptSubmit, now());
    let o = r.observation.unwrap();
    assert!(o.text.len() <= ph_core::MAX_OBSERVATION_TEXT_BYTES);
    assert!(!o.text.contains("FAKE"));
}

#[test]
fn observe_full_flow_from_fixture() {
    let r = observe_hook_input(
        &fixture("user_prompt_submit_secret.json")[..],
        HookEvent::UserPromptSubmit,
        now(),
    );
    assert_eq!(r.event, Some(HookEvent::UserPromptSubmit));
    let o = r.observation.unwrap();
    assert!(o.id.as_str().starts_with("obs_"));
    assert!(!all_output(&o).contains("sk-ant"));
    // The matching output prints nothing for UserPromptSubmit.
    assert!(HookOutput::for_event(HookEvent::UserPromptSubmit, Some("x")).is_silent());

    // Invoked as a different event than the payload says: ignored.
    let r = observe_hook_input(
        &fixture("user_prompt_submit_secret.json")[..],
        HookEvent::Stop,
        now(),
    );
    assert_eq!(r.observation, None);
}

#[test]
fn missing_optional_fields_are_tolerated() {
    let p = parse_hook_payload(br#"{"hook_event_name":"Stop"}"#).unwrap();
    let o = normalize(&p, None, id(), now()).unwrap();
    assert_eq!(o.session_hash, None);
    assert_eq!(o.repo_key, UNKNOWN_REPO_KEY);
    // Event name missing entirely: falls back to the CLI event.
    let p = parse_hook_payload(br#"{"prompt":"hi there"}"#).unwrap();
    assert!(normalize(&p, Some(HookEvent::UserPromptSubmit), id(), now()).is_some());
}

/// `transcript_path` is dropped at parse time: the parsed payload is identical with and
/// without it, so nothing downstream can ever see the path.
#[test]
fn transcript_path_is_not_retained() {
    let with = parse_hook_payload(
        br#"{"hook_event_name":"Stop","session_id":"s","cwd":"/r","transcript_path":"/secret/t.jsonl","last_assistant_message":"m"}"#,
    )
    .unwrap();
    let without =
        parse_hook_payload(br#"{"hook_event_name":"Stop","session_id":"s","cwd":"/r"}"#).unwrap();
    assert_eq!(with, without);
}

/// The transcript path points at a FIFO. Opening a FIFO for reading blocks until a
/// writer appears, so if anything in the hook flow tried to open it this test would hang
/// and fail on the timeout instead of completing.
#[cfg(unix)]
#[test]
fn transcript_fifo_is_never_opened() {
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("transcript.jsonl");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    // Also a regular canary file next to it, as a second form of the same check.
    let canary = dir.path().join("canary.jsonl");
    std::fs::write(&canary, "CANARY-TRANSCRIPT-CONTENT").unwrap();

    for path in [&fifo, &canary] {
        let payload = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s",
            "cwd": dir.path(),
            "transcript_path": path,
            "prompt": "use pnpm not npm",
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = observe_hook_input(&bytes[..], HookEvent::UserPromptSubmit, now());
            let _ = tx.send(r);
        });
        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("hook flow blocked: it tried to open transcript_path");
        let o = r.observation.unwrap();
        assert!(!all_output(&o).contains("CANARY"));
        assert!(!all_output(&o).contains("transcript"));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_hook_payload(&bytes);
        let _ = observe_hook_input(&bytes[..], HookEvent::UserPromptSubmit, now());
    }

    #[test]
    fn parse_never_panics_on_jsonish(s in r#"\{("[a-z_]{1,16}":(null|true|-?[0-9]{1,20}|"[^"\\]{0,20}"|\[\]|\{\}),?){0,8}\}"#) {
        let _ = parse_hook_payload(s.as_bytes());
    }

    #[test]
    fn embedded_secret_never_survives(
        before in "[a-zA-Z ,.]{0,200}",
        after in "[a-zA-Z ,.]{0,200}",
        body in "[A-Za-z0-9]{24,64}",
    ) {
        let prompt = format!("{before} sk-ant-api03-{body} {after}");
        let payload = serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": prompt});
        let bytes = serde_json::to_vec(&payload).unwrap();
        let r = observe_hook_input(&bytes[..], HookEvent::UserPromptSubmit, now());
        let o = r.observation.unwrap();
        prop_assert!(!all_output(&o).contains(&body));
        prop_assert!(!o.text.contains("sk-ant-api03"));
    }
}
