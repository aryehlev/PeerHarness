//! `peerharness setup`: everything a person does once before they use PeerHarness from
//! their coding agent, as one command in their own terminal (ADR-039).
//!
//! It runs what three commands ran, in this order, and nothing they did not do:
//!
//! 1. `init`, when this home has no node yet: no device identity in its database,
//!    which includes a home that an interrupted `init` left half made;
//! 2. `watch claude --install`, with the confirmation windows where this machine can
//!    show one and the owner did not pass `--no-dialogs`. Its preview and its
//!    confirmation are the ones of that command;
//! 3. `claude mcp add --scope user peerharness -- <this binary> mcp`, Claude Code's own
//!    command for registering an MCP server, after showing the line and asking;
//! 4. `watch <agent> --install` for each other coding agent named with `--agent`, or
//!    else for each one found on this machine (ADR-050), each with its own preview.
//!
//! Inside a coding agent's session it is refused as a whole: step 2 is where the owner
//! allows what their agent may start, and no session takes that step for them.
//!
//! It ends by saying what the owner can do now, and that depends on the windows.
//! Without them (a machine that can show none, or `--no-dialogs`) the agent's tools
//! other than `note` run nothing (ADR-038), so it does not suggest asking the agent for
//! anything: it says what works there and where the terminal's commands are.
//!
//! One state is in between: the settings allow windows (they were turned on where one
//! could be shown, and came along with the home) and this machine can show none.
//! `setup` turns nothing off by itself, and a tool runs at the level the settings
//! allow. The steps that would ask in a window are refused there, and the ones that
//! need none still run: the status, the inbox, founding a circle, the exchange and the
//! daemon. The closing lines say so, and name the command that turns them off.
//!
//! For a node that is already there, step 1 names the keystore its private key is in.
//! A plaintext keystore (`insecure-dev`) gets a warning: an earlier `init` may have
//! chosen it where its own warning reached nobody.
//!
//! Step 3 runs a program that edits Claude Code's configuration. Debug builds never
//! look for it on `PATH`: they run only the program named by
//! `PEERHARNESS_TEST_CLAUDE_BIN`, a stand-in for tests, so that no test can touch the
//! developer's own Claude Code. Release builds do not read that variable.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Result;
use ph_identity::KeystoreBackend;
use serde_json::{json, Value};

use super::Ctx;
use crate::agents::Agent;
use crate::cli::{SetupArgs, WatchClaudeArgs, WatchOtherArgs};
use crate::consent::{confirm, human_only};
use crate::output::{Report, Text};
use crate::window::Window;

/// The name the server is registered under.
const SERVER_NAME: &str = "peerharness";

/// Claude Code's own command that takes the server out again. `reset` names it too:
/// the registration is in Claude Code's configuration, which PeerHarness never edits.
pub const UNREGISTER: &str = "claude mcp remove peerharness --scope user";

/// The terminal guide: every step as a command, the ones without a window included.
pub const TERMINAL_GUIDE: &str =
    concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/terminal.md");

/// Environment variable naming the stand-in for Claude Code's `claude` command (debug
/// builds only).
#[cfg(debug_assertions)]
pub const TEST_CLAUDE_ENV: &str = "PEERHARNESS_TEST_CLAUDE_BIN";

pub fn run(ctx: &Ctx, a: SetupArgs) -> Result<Report> {
    human_only("setting PeerHarness up")?;
    let mut t = Text::new();

    // 1. The node. Whether there is one is asked of the database, not only of the
    // files: an `init` that was interrupted leaves a config file and a database without
    // an identity, and that home has no node yet. `init` completes it.
    let created = !(ctx.home.is_initialized() && super::init::has_identity(&ctx.home));
    let node = if created {
        let made = super::init::run(ctx, a.init)?;
        t.line("1. Your node: created.");
        made.json
    } else {
        t.line("1. Your node: already there.");
        Value::Null
    };
    // Which keystore holds the node's key: read from the node, which is not unlocked.
    let backend = ctx.open_node()?.backend()?;
    if !created {
        t.line(format!("  {}", keystore_says(backend)));
        if backend == KeystoreBackend::InsecureDev {
            // `init` warned whoever ran it, which may not have been the owner. On
            // standard error as well, where `--json` does not hide it.
            ctx.out.warn(PLAINTEXT_WARNING);
            t.line(format!("  WARNING: {PLAINTEXT_WARNING}"));
        }
    }

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

    // 4. The other agents: the ones named, or every one found here (ADR-050). Each is
    // its own preview and confirmation (`watch <agent> --install`).
    let others: Vec<Agent> = if a.agent.is_empty() {
        Agent::ALL.into_iter().filter(|x| x.detected()).collect()
    } else {
        let mut chosen = a.agent.clone();
        chosen.sort();
        chosen.dedup();
        chosen
    };
    let mut other_json = Vec::new();
    if others.is_empty() {
        t.line(format!(
            "4. Other agents: none found here ({}). To connect one later:              `peerharness watch <agent> --install`.",
            crate::agents::names(&Agent::ALL)
        ));
    } else {
        t.line("4. Other agents:");
    }
    for other in others {
        let r = super::agent::run(
            ctx,
            other,
            &WatchOtherArgs {
                install: true,
                no_hooks: a.no_agent_hooks,
                remove: false,
                status: false,
                yes: a.yes,
            },
        )?;
        t.line(format!(
            "  {}: {}",
            other.name(),
            if r.json["changed"] == true {
                "connected."
            } else {
                "already connected."
            }
        ));
        for line in r.text.lines().skip(1) {
            t.line(format!("  {line}"));
        }
        other_json.push(r.json);
    }

    // What the owner can do now. With the windows off, every tool but `note` answers
    // that the step is the owner's. What a tool may run is read from the settings
    // alone, so where they are on and no window can be shown, the tools that need no
    // window still run.
    let agent_can_ask = agent.json["windows"] == true && Window::find().is_some();
    let config = crate::config::Config::load(&ctx.home)?;
    let allowed = config.agent.asked();
    t.line("");
    for line in next_steps(agent_can_ask, allowed, &config.agents.connected) {
        t.line(line);
    }
    Ok(Report::new(
        json!({
            "node_created": created,
            "node": node,
            "keystore": backend.as_str(),
            "agent": agent.json,
            "agent_can_ask": agent_can_ask,
            "tools": tools.code(),
            "tools_command": command_line(&server_command(ctx)?),
            "other_agents": other_json,
        }),
        t.finish(),
    ))
}

/// What step 1 says about the keystore of a node that was already there.
const fn keystore_says(backend: KeystoreBackend) -> &'static str {
    match backend {
        KeystoreBackend::Os => "Its private key is in the operating system's keychain.",
        KeystoreBackend::File => {
            "Its private key is in an encrypted file, protected by your passphrase."
        }
        KeystoreBackend::InsecureDev => {
            "Its private key is in a plaintext file (the insecure-dev keystore)."
        }
    }
}

/// What the owner of a node with a plaintext keystore is told.
const PLAINTEXT_WARNING: &str = "this node's private keys are stored in PLAINTEXT, in its home \
    directory (the insecure-dev keystore, meant for development). Any program that runs as \
    you can read them and sign your ballots. No command moves a key to another keystore: a \
    node with a protected key is a new node, with a new device key (`peerharness reset` \
    says what it deletes, then `peerharness setup`).";

/// The closing lines: what to do next. It depends on whether the agent can put a
/// decision in front of the owner (`agent_can_ask`), and on what the settings allow
/// the agent's tools (`allowed`), which is what they run at whether or not this
/// machine can show a window.
fn next_steps(agent_can_ask: bool, allowed: crate::config::Asked, others: &[Agent]) -> Vec<String> {
    use crate::config::Asked;

    if agent_can_ask {
        let session = if others.is_empty() {
            "Start a new Claude Code session and ask it, for example:".to_owned()
        } else {
            format!(
                "Start a new session of Claude Code (or {}) and ask it, for example:",
                crate::agents::names(others).replace(" and ", " or ")
            )
        };
        return vec![
            session,
            "  \"What is my PeerHarness device key?\"".to_owned(),
            "  \"Create a PeerHarness team called acme.\"".to_owned(),
        ];
    }
    let mut lines = vec!["Without confirmation windows, this is what works from here:".to_owned()];
    if allowed == Asked::Nothing {
        lines.push(
            "  Your agent notes a rule when you correct it or state one. That is all it does: \
             asked for anything else, it answers that the step is yours."
                .to_owned(),
        );
    } else {
        // Windows are on in the settings and this machine can show none.
        lines.push(
            "  Your agent notes a rule when you correct it or state one. A step that would \
             ask you in a window is refused on this machine."
                .to_owned(),
        );
        let mut still = "this node's status and what waits for you".to_owned();
        if allowed >= Asked::RulesAndCircle {
            still.push_str(
                ", founding a circle, exchanging with the members of your circles over the \
                 public network, and keeping this node reachable there",
            );
        }
        lines.push(format!(
            "  This node's settings still allow your agent the steps that need no window, \
             because windows were turned on for it (on a machine that could show one): \
             {still}. To turn those off as well, so that your agent only notes rules: \
             `peerharness setup --no-dialogs`."
        ));
    }
    lines.extend([
        "  At the end of a turn, at most once a day, Claude Code tells you how many noted \
         rules and proposals wait for you."
            .to_owned(),
        "  Every decision is typed in your own terminal: `peerharness inbox` shows what \
         waits, `peerharness keep <id>` keeps a rule for your own agent, and proposing, \
         voting, inviting and joining are commands as well."
            .to_owned(),
        format!("  The commands, step by step: {TERMINAL_GUIDE}"),
    ]);
    lines
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
pub fn server_command(ctx: &Ctx) -> Result<Vec<OsString>> {
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
    format!(
        "claude mcp add --scope user {SERVER_NAME} --{}",
        shell_words(server)
    )
}

/// Words as a POSIX shell reads them, each after a space: plain where that is safe, else
/// single-quoted.
pub fn shell_words(server: &[OsString]) -> String {
    let mut line = String::new();
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
    // `claude` is another program: the passphrase of the key file is not in its
    // environment (ADR-051), as it is not in an advisory provider's.
    let quiet = |args: &[&str]| {
        Command::new(&claude)
            .args(args)
            .env_remove(ph_identity::PASSPHRASE_ENV)
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
         Take it out again with `{UNREGISTER}`."
    );
    confirm(
        &ctx.out,
        &preview,
        yes,
        "registering the tools with Claude Code",
    )?;
    let out = Command::new(&claude)
        .args(add_arguments(&server))
        .env_remove(ph_identity::PASSPHRASE_ENV)
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
    fn the_closing_lines_follow_what_the_agent_can_do() {
        use crate::config::Asked;

        // With windows: something to ask the agent.
        let with = next_steps(true, Asked::All, &[]).join("\n");
        assert!(with.contains("Start a new Claude Code session"));
        let with_others = next_steps(true, Asked::All, &[Agent::Codex, Agent::Pi]).join("\n");
        assert!(
            with_others.contains("session of Claude Code (or Codex or Pi)"),
            "{with_others}"
        );
        assert!(!with.contains("terminal.md"));
        // Without: what works, where the commands are, and no prompt for the agent.
        let without = next_steps(false, Asked::Nothing, &[]).join("\n");
        assert!(without.contains("Your agent notes a rule"));
        assert!(without.contains("That is all it does"));
        assert!(without.contains("typed in your own terminal"));
        assert!(without.ends_with("/blob/main/docs/terminal.md"));
        assert!(TERMINAL_GUIDE.starts_with("https://"));
        assert!(!without.contains("ask it") && !without.contains("PeerHarness team called"));
        // Windows on in the settings, on a machine that can show none: the agent's tools
        // run at the level the settings allow, so "that is all it does" would be false.
        // What still runs is named, per level, with the command that turns it off.
        for allowed in [Asked::Rules, Asked::RulesAndCircle, Asked::All] {
            let between = next_steps(false, allowed, &[]).join("\n");
            assert!(!between.contains("That is all it does"), "{between}");
            assert!(between.contains("is refused on this machine"), "{between}");
            assert!(
                between.contains("this node's status and what waits for you"),
                "{between}"
            );
            assert_eq!(
                between.contains("founding a circle")
                    && between.contains("over the public network")
                    && between.contains("keeping this node reachable"),
                allowed >= Asked::RulesAndCircle,
                "{allowed:?}: {between}"
            );
            assert!(
                between.contains("`peerharness setup --no-dialogs`"),
                "{between}"
            );
            assert!(between.contains("typed in your own terminal"));
            assert!(!between.contains("ask it"), "{between}");
        }
        // The command `reset` names is the one that removes what `add` registered.
        assert_eq!(
            UNREGISTER,
            format!("claude mcp remove {SERVER_NAME} --scope user")
        );
        // Every keystore is named, and only the plaintext one as plaintext.
        for backend in KeystoreBackend::ALL {
            let says = keystore_says(backend);
            assert_eq!(
                says.contains("plaintext"),
                backend == KeystoreBackend::InsecureDev,
                "{says}"
            );
        }
        assert!(PLAINTEXT_WARNING.contains("PLAINTEXT"));
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
