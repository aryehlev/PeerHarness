//! # ph-observer
//!
//! Local, opt-in observation of Claude Code sessions (specification sections 7.1, 7.2 and
//! 13; architecture sections 1 and 13).
//!
//! * [`hook`]: bounded stdin reading, lenient hook payload parsing, pure normalization
//!   into a redacted [`ph_core::NormalizedObservation`], and the hook's stdout
//!   ([`hook::HookOutput`]).
//! * [`settings`]: idempotent install/remove/status of our hook entries in a Claude Code
//!   `settings.json`, with backups and atomic writes. [`settings::HookCommand`] renders
//!   the POSIX-shell-safe command line.
//! * [`spool`]: the append-only JSON-lines fallback spool used when SQLite is busy.
//! * [`notify`]: the pure throttle that keeps unsolicited notifications to at most two
//!   a day, with a per-topic cooldown and quiet hours.
//!
//! ## Verified Claude Code hook contract
//!
//! Checked against <https://code.claude.com/docs/en/hooks> (2026-11-09):
//!
//! * `settings.json`: `{"hooks": {"<Event>": [{"matcher"?: "...", "hooks": [{"type":
//!   "command", "command": "...", "timeout": <seconds>}]}]}}`. `UserPromptSubmit` and
//!   `Stop` have no matcher support (a matcher is silently ignored), so we omit it.
//! * stdin JSON, common fields: `session_id`, `transcript_path`, `cwd`,
//!   `permission_mode`, `hook_event_name` (plus newer optional ones such as `prompt_id`,
//!   `effort`, `agent_id`). `UserPromptSubmit` adds `prompt`; `Stop` adds
//!   `stop_hook_active`, `last_assistant_message`, `background_tasks`, `session_crons`;
//!   `PostToolUseFailure` adds `tool_name`, `tool_input`, `tool_use_id`, `error`,
//!   `is_interrupt`, `duration_ms`.
//! * Exit 0: success, JSON stdout fields are applied. Exit 2: blocking error (blocks the
//!   prompt / prevents stopping). Other codes: non-blocking error. Our hook always exits 0.
//! * `UserPromptSubmit` plain stdout on exit 0 is injected into the model's context, so
//!   our hook prints nothing for it.
//! * `{"systemMessage": "..."}` is a warning shown to the user; `Stop` does not discard
//!   it, so it is how our `Stop` hook surfaces a throttled notice.
//!
//! ## Privacy
//!
//! Nothing in this crate opens `transcript_path` or any other path taken from a hook
//! payload; [`hook::HookPayload`] does not even retain it. Errors and logs contain codes,
//! counts and static text only, never prompts, observation text or tool output.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod fsutil;
pub mod hook;
mod json_doc;
pub mod notify;
pub mod settings;
mod shell;
pub mod spool;

pub use hook::{
    normalize, observe_hook_input, parse_hook_payload, read_bounded, read_bounded_stdin, repo_key,
    repo_label, session_hash, HookEvent, HookInputError, HookObservation, HookOutput, HookPayload,
    PayloadEvent, MAX_HOOK_INPUT_BYTES,
};
pub use notify::{evaluate, should_notify, NotifyDecision, NotifyPolicy, QuietHours};
pub use settings::{
    claude_user_settings_path, hooks_status, install_hooks, remove_hooks, remove_hooks_for,
    HookCommand, HookStatus, InstallReport, InstalledHook, RemoveReport, SettingsError,
};
pub use spool::{
    append_observation, claim_spool, drain, AppendOutcome, Claimed, Drained, SpoolError,
};
