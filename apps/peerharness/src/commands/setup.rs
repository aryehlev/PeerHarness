//! `peerharness setup`: everything a person does once before they use PeerHarness from
//! their coding agent, as one command in their own terminal (ADR-039).
//!
//! It runs what three commands ran, in this order, and nothing they did not do:
//!
//! 1. `init`, when this home has no node yet;
//! 2. `watch claude --install`, with the confirmation windows where this machine can
//!    show one and the owner did not pass `--no-dialogs`. Its preview and its
//!    confirmation are the ones of that command;
//! 3. `claude mcp add --scope user peerharness -- <this binary> mcp`, Claude Code's own
//!    command for registering an MCP server, after showing the line and asking.
//!
//! Inside a coding agent's session it is refused as a whole: step 2 is where the owner
//! allows what their agent may start, and no session takes that step for them.
//!
//! Step 3 runs a program that edits Claude Code's configuration. Debug builds never
//! look for it on `PATH`: they run only the program named by
//! `PEERHARNESS_TEST_CLAUDE_BIN`, a stand-in for tests, so that no test can touch the
//! developer's own Claude Code. Release builds do not read that variable.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Result;
use serde_json::{json, Value};

use super::Ctx;
use crate::cli::{SetupArgs, WatchClaudeArgs};
use crate::consent::{confirm, human_only};
use crate::output::{Report, Text};
use crate::window::Window;

/// The name the server is registered under.
const SERVER_NAME: &str = "peerharness";

/// Environment variable naming the stand-in for Claude Code's `claude` command (debug
/// builds only).
#[cfg(debug_assertions)]
pub const TEST_CLAUDE_ENV: &str = "PEERHARNESS_TEST_CLAUDE_BIN";

pub fn run(ctx: &Ctx, a: SetupArgs) -> Result<Report> {
    human_only("setting PeerHarness up")?;
    let mut t = Text::new();

    // 1. The node.
    let created = !ctx.home.is_initialized();
    let node = if created {
        let made = super::init::run(ctx, a.init)?;
        t.line("1. Your node: created.");
        made.json
    } else {
        t.line("1. Your node: already there.");
        Value::Null
    };

    // 2. The agent: the hooks, the skill, and what it may ask in a window.
    let dialogs = !a.no_dialogs && Window::find().is_some();
    let agent = super::watch::claude(
        ctx,
        WatchClaudeArgs {
            install: true,
            remove: false,
            no_agent_notes: false,
            windows: dialogs,
            no_windows: a.no_dialogs,
            status: false,
            settings: None,
            yes: a.yes,
        },
    )?;
    t.line(format!(
        "2. Claude Code: {}",
        if agent.json["changed"] == true {
            "connected."
        } else {
            "already connected."
        }
    ));
    for line in agent.text.lines().skip(1) {
        // The command's own lines, without the one about the tools: that is step 3.
        if !line.contains("as tools") {
            t.line(line);
        }
    }
    if !dialogs && !a.no_dialogs {
        t.line("  This machine has no window PeerHarness can show: every decision needs your own terminal.");
    }

    // 3. The tools.
    let tools = register(ctx, a.yes)?;
    t.line(format!("3. The tools: {}", tools.says()));

    t.line("");
    t.line("Start a new Claude Code session and ask it, for example:");
    t.line("  \"What is my PeerHarness device key?\"");
    t.line("  \"Create a PeerHarness team called acme.\"");
    Ok(Report::new(
        json!({
            "node_created": created,
            "node": node,
            "agent": agent.json,
            "tools": tools.code(),
            "tools_command": command_line(&server_command(ctx)?),
        }),
        t.finish(),
    ))
}

/// How registering the tools with Claude Code came out.
#[derive(Debug, PartialEq, Eq)]
enum Tools {
    Registered,
    /// Claude Code already had a server of that name.
    Already,
    /// There is no `claude` command to run.
    NoClaude(String),
    /// `claude mcp add` failed.
    Failed(String, String),
}

impl Tools {
    const fn code(&self) -> &'static str {
        match self {
            Tools::Registered => "registered",
            Tools::Already => "already_registered",
            Tools::NoClaude(_) => "claude_not_found",
            Tools::Failed(..) => "failed",
        }
    }

    fn says(&self) -> String {
        match self {
            Tools::Registered => "registered with Claude Code.".to_owned(),
            Tools::Already => format!(
                "Claude Code already has them (`claude mcp get {SERVER_NAME}` shows the command)."
            ),
            Tools::NoClaude(line) => format!(
                "not registered: Claude Code's `claude` command was not found. Once it is \
                 installed, run:\n  {line}"
            ),
            Tools::Failed(why, line) => format!(
                "not registered: `claude mcp add` failed ({why}). To try it yourself:\n  {line}"
            ),
        }
    }
}

/// What Claude Code is told to start: this binary, for this home, as an MCP server.
fn server_command(ctx: &Ctx) -> Result<Vec<OsString>> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|_| anyhow::anyhow!("cannot determine the path of this executable"))?;
    let mut command = vec![exe.into_os_string()];
    if !ctx.home.is_default() {
        command.push("--home".into());
        command.push(ctx.home.root().into());
    }
    command.push("mcp".into());
    Ok(command)
}

/// The arguments of `claude mcp add` for `server`.
fn add_arguments(server: &[OsString]) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["mcp", "add", "--scope", "user", SERVER_NAME, "--"]
        .iter()
        .map(Into::into)
        .collect();
    args.extend(server.iter().cloned());
    args
}

/// A command as a person would type it, for showing.
fn command_line(server: &[OsString]) -> String {
    let mut line = format!("claude mcp add --scope user {SERVER_NAME} --");
    for word in server {
        let word = word.to_string_lossy();
        line.push(' ');
        if word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
        {
            line.push_str(&word);
        } else {
            line.push('\'');
            line.push_str(&word.replace('\'', "'\\''"));
            line.push('\'');
        }
    }
    line
}

/// Registers the MCP server with Claude Code, by running Claude Code's own command for
/// that, after showing the line and asking.
fn register(ctx: &Ctx, yes: bool) -> Result<Tools> {
    let server = server_command(ctx)?;
    let line = command_line(&server);
    let Some(claude) = claude_program() else {
        return Ok(Tools::NoClaude(line));
    };
    let quiet = |args: &[&str]| {
        Command::new(&claude)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if quiet(&["mcp", "get", SERVER_NAME]) {
        return Ok(Tools::Already);
    }
    let preview = format!(
        "This gives Claude Code the PeerHarness steps as tools, by running Claude Code's own \
         command for that:\n  {line}\n\
         Claude Code then starts that program in each session. The tools start steps for \
         you. They never decide: that stays your click in a window, or your own terminal.\n\
         Take it out again with `claude mcp remove {SERVER_NAME} --scope user`."
    );
    confirm(
        &ctx.out,
        &preview,
        yes,
        "registering the tools with Claude Code",
    )?;
    let out = Command::new(&claude)
        .args(add_arguments(&server))
        .stdin(Stdio::null())
        .output();
    Ok(match out {
        Ok(out) if out.status.success() => Tools::Registered,
        Ok(out) => {
            let said = String::from_utf8_lossy(&out.stderr);
            let said = said.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            let why = if said.is_empty() {
                "it gave no reason".to_owned()
            } else {
                crate::output::safe(said.trim()).chars().take(200).collect()
            };
            Tools::Failed(why, line)
        }
        Err(_) => Tools::Failed("it could not be started".to_owned(), line),
    })
}

/// Claude Code's `claude` command, when there is one to run.
fn claude_program() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(TEST_CLAUDE_ENV)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_file())
    }
    #[cfg(not(debug_assertions))]
    {
        on_path("claude", &std::env::var_os("PATH")?)
    }
}

/// The first regular file named `name` in the directories of `path`.
#[cfg_attr(debug_assertions, allow(dead_code))] // release builds look on PATH; see the module docs
fn on_path(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_program(candidate))
}

fn is_program(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<OsString> {
        list.iter().map(Into::into).collect()
    }

    #[test]
    fn the_line_shown_is_the_command_that_runs() {
        let server = words(&["/opt/ph/peerharness", "mcp"]);
        assert_eq!(
            command_line(&server),
            "claude mcp add --scope user peerharness -- /opt/ph/peerharness mcp"
        );
        assert_eq!(
            add_arguments(&server),
            words(&[
                "mcp",
                "add",
                "--scope",
                "user",
                "peerharness",
                "--",
                "/opt/ph/peerharness",
                "mcp"
            ])
        );
        // A home of its own, with a space in it, is one quoted word when shown and one
        // argument when run.
        let server = words(&["/opt/ph/peerharness", "--home", "/x y/it's", "mcp"]);
        assert_eq!(
            command_line(&server),
            "claude mcp add --scope user peerharness -- /opt/ph/peerharness --home '/x y/it'\\''s' mcp"
        );
        assert_eq!(add_arguments(&server).len(), 10);
    }

    #[test]
    fn a_program_is_found_in_the_first_directory_that_has_it() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("claude"), "").unwrap();
        let path = std::env::join_paths([a.clone(), b.clone()]).unwrap();
        assert_eq!(on_path("claude", &path), Some(b.join("claude")));
        std::fs::write(a.join("claude"), "").unwrap();
        assert_eq!(on_path("claude", &path), Some(a.join("claude")));
        assert_eq!(on_path("no-such-program", &path), None);
        // A relative entry, the current directory included, is never searched.
        let relative = std::env::join_paths([PathBuf::from("."), PathBuf::from("")]).unwrap();
        assert_eq!(on_path("claude", &relative), None);
    }

    #[test]
    fn every_outcome_tells_the_person_where_they_stand() {
        let line = "claude mcp add --scope user peerharness -- /p mcp".to_owned();
        assert!(Tools::Registered
            .says()
            .contains("registered with Claude Code"));
        assert!(Tools::Already.says().contains("already has them"));
        let none = Tools::NoClaude(line.clone());
        assert!(none.says().contains("was not found") && none.says().ends_with(&line));
        let failed = Tools::Failed("no reason".to_owned(), line.clone());
        assert!(failed.says().contains("failed (no reason)") && failed.says().ends_with(&line));
        assert_eq!(none.code(), "claude_not_found");
    }
}
