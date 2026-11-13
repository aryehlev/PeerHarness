//! The coding agents besides Claude Code that PeerHarness connects to (ADR-050,
//! ADR-052): Codex, opencode, Pi, Google Antigravity, DeepSeek Harness, Gemini CLI, Qwen
//! Code, GitHub Copilot CLI, Cursor, Amp, Factory's Droid, Crush, Kilo and goose.
//!
//! Claude Code stays where rules are installed: its skills directory (or a project's
//! `.claude/skills`) is where every decision about installing, holding and removing a
//! rule is taken (`governance::apply_rules`). An agent connected here gets these,
//! each checked against its own source or documentation on 2026-11-12:
//!
//! * **The rules.** An agent that reads Claude Code's skills directory itself (opencode,
//!   Copilot CLI in a project, Cursor, Amp, Crush, goose) needs nothing there. For the
//!   others, PeerHarness keeps managed copies of what it manages there in the directory
//!   the agent reads ([`crate::copies`]): `~/.agents/skills` for Codex, Pi, DeepSeek
//!   Harness, Gemini CLI, Qwen Code, Copilot CLI, Droid and Kilo,
//!   `~/.gemini/config/skills` for Antigravity, and a project's `.agents/skills` for a
//!   project.
//! * **The tools.** `peerharness mcp` is registered in the agent's configuration file,
//!   with a backup, when the agent has one PeerHarness can edit safely: a TOML block for
//!   Codex, a JSON entry for the others. DeepSeek Harness and goose keep their servers in
//!   YAML, which PeerHarness does not edit, so the entry is shown for the owner to add.
//! * **The hooks**, for the seven agents that run command hooks from a JSON file
//!   (ADR-053, [`Agent::hook_spec`]): the hook that keeps a redacted copy of each
//!   prompt, and, for the four that show a hook's message to the person alone, the
//!   notice at the end of a turn. Checked on 2026-11-13.
//! * **Its sessions are recognized.** The variables each agent sets in the commands it
//!   runs are in [`crate::consent::AGENT_SESSION_ENV`], so a decision started there is
//!   refused, or asked in a window, as from Claude Code.
//!
//! Where an agent's files are: under the user's home directory, honouring the agent's
//! own variables that move them (`CODEX_HOME`, `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`,
//! `PI_CODING_AGENT_DIR`, `DSH_HOME`, `DSH_AGENTS_HOME`, `GEMINI_CLI_HOME`, `QWEN_HOME`,
//! `COPILOT_HOME`, `CRUSH_GLOBAL_CONFIG`, `GOOSE_PATH_ROOT`, `AMP_SETTINGS_FILE`,
//! `FACTORY_HOME_OVERRIDE`). `PEERHARNESS_AGENTS_HOME`
//! stands in for the home directory, and the agents' own variables are then not read.
//! A debug build reads only that variable: without it, it finds no agent, so that no
//! test can touch a developer's own agents.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Stands in for the home directory when the agents' files are looked for.
pub const AGENTS_HOME_ENV: &str = "PEERHARNESS_AGENTS_HOME";

/// The name the MCP server is registered under.
pub const SERVER_NAME: &str = "peerharness";

/// A coding agent PeerHarness can connect besides Claude Code.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    /// OpenAI's Codex CLI.
    Codex,
    /// opencode.
    Opencode,
    /// Pi, the coding agent of earendil-works.
    Pi,
    /// Google Antigravity (the app, the IDE and the `agy` CLI).
    Antigravity,
    /// DeepSeek Harness (`dsh`).
    Deepseek,
    /// Google's Gemini CLI.
    Gemini,
    /// Qwen Code.
    Qwen,
    /// GitHub Copilot CLI.
    Copilot,
    /// Crush, by Charm.
    Crush,
    /// Kilo Code's CLI.
    Kilo,
    /// goose.
    Goose,
    /// Cursor (its agent CLI and the editor).
    Cursor,
    /// Amp.
    Amp,
    /// Factory's Droid.
    Droid,
}

/// Where an agent's MCP servers are registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolsFile {
    /// A TOML file with a `[mcp_servers.<name>]` table (Codex).
    Toml(PathBuf),
    /// A JSON file with the servers under `at` (Pi, Antigravity, opencode).
    Json {
        file: PathBuf,
        at: &'static [&'static str],
    },
    /// A file PeerHarness does not edit: the owner adds the entry (DeepSeek Harness).
    Manual(PathBuf),
}

impl ToolsFile {
    pub fn path(&self) -> &Path {
        match self {
            ToolsFile::Toml(p) | ToolsFile::Json { file: p, .. } | ToolsFile::Manual(p) => p,
        }
    }
}

/// Where one agent's files are on this machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// Directories whose existence says that the agent is installed here.
    pub detect: Vec<PathBuf>,
    /// Where it reads the user's skills, when that is not Claude Code's directory.
    pub skills: Option<PathBuf>,
    /// Where its MCP servers are registered.
    pub tools: ToolsFile,
    /// The file its hooks go in, for an agent of [`Agent::hook_spec`].
    pub hooks: Option<PathBuf>,
    /// A file whose hooks the agent stops reading once [`Paths::hooks`] exists
    /// (Droid's `settings.json`).
    pub hooks_shadow: Option<PathBuf>,
}

/// What an entry in an agent's hooks file looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookEntry {
    /// Claude Code's: a group of one hook, with a timeout in the agent's unit.
    Group { timeout: u64 },
    /// Cursor's: the command and a timeout in seconds.
    Flat,
    /// Copilot CLI's: the command under `bash`, and `timeoutSec`.
    Bash,
}

/// How PeerHarness's hooks fit one agent (ADR-053), as read in its source or its
/// documentation on 2026-11-13.
#[derive(Clone, Copy, Debug)]
pub struct HookSpec {
    /// The members down to the object of events in the file.
    pub at: &'static [&'static str],
    /// Whether a new file starts with `"version": 1`.
    pub version: bool,
    /// Directories above the file that exist only for it.
    pub own_dirs: usize,
    /// The event that fires when the person submits a prompt.
    pub prompt_event: &'static str,
    /// The event at the end of a turn, only where what the hook prints there is shown
    /// to the person and not to the model. Elsewhere no such hook is installed.
    pub stop_event: Option<&'static str>,
    pub entry: HookEntry,
    /// Where the payload keeps the prompt, the session and the directory.
    pub payload: ph_observer::PayloadShape,
    /// What the owner has to know or do besides.
    pub note: Option<&'static str>,
}

/// The payload of the agents that kept Claude Code's names.
const CLAUDE_PAYLOAD: ph_observer::PayloadShape = ph_observer::PayloadShape {
    prompt: &["prompt"],
    session: &["session_id"],
    cwd: &["cwd"],
    cwd_list: None,
};

/// The seconds a hook may take, as in Claude Code's settings.
const HOOK_TIMEOUT_SECS: u64 = ph_observer::HookCommand::TIMEOUT_SECS;

/// The base the agents' paths are resolved from.
struct Base {
    home: PathBuf,
    /// Whether the agents' own variables are read.
    native: bool,
}

impl Base {
    fn find() -> Option<Self> {
        if let Some(d) = std::env::var_os(AGENTS_HOME_ENV).filter(|d| !d.is_empty()) {
            let d = PathBuf::from(d);
            return d.is_absolute().then_some(Self {
                home: d,
                native: false,
            });
        }
        #[cfg(debug_assertions)]
        {
            None
        }
        #[cfg(not(debug_assertions))]
        {
            crate::home::user_home().map(|home| Self { home, native: true })
        }
    }

    /// An agent's own variable naming a directory, when those are read.
    fn var(&self, name: &str) -> Option<PathBuf> {
        if !self.native {
            return None;
        }
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    }

    fn join(&self, parts: &[&str]) -> PathBuf {
        parts.iter().fold(self.home.clone(), |p, x| p.join(x))
    }
}

impl Agent {
    pub const ALL: [Agent; 14] = [
        Agent::Codex,
        Agent::Opencode,
        Agent::Pi,
        Agent::Antigravity,
        Agent::Deepseek,
        Agent::Gemini,
        Agent::Qwen,
        Agent::Copilot,
        Agent::Crush,
        Agent::Kilo,
        Agent::Goose,
        Agent::Cursor,
        Agent::Amp,
        Agent::Droid,
    ];

    /// The word used on the command line and in the config file.
    pub const fn id(self) -> &'static str {
        match self {
            Agent::Codex => "codex",
            Agent::Opencode => "opencode",
            Agent::Pi => "pi",
            Agent::Antigravity => "antigravity",
            Agent::Deepseek => "deepseek",
            Agent::Gemini => "gemini",
            Agent::Qwen => "qwen",
            Agent::Copilot => "copilot",
            Agent::Crush => "crush",
            Agent::Kilo => "kilo",
            Agent::Goose => "goose",
            Agent::Cursor => "cursor",
            Agent::Amp => "amp",
            Agent::Droid => "droid",
        }
    }

    /// The name of its line in `doctor`.
    pub const fn check_name(self) -> &'static str {
        match self {
            Agent::Codex => "agent codex",
            Agent::Opencode => "agent opencode",
            Agent::Pi => "agent pi",
            Agent::Antigravity => "agent antigravity",
            Agent::Deepseek => "agent deepseek",
            Agent::Gemini => "agent gemini",
            Agent::Qwen => "agent qwen",
            Agent::Copilot => "agent copilot",
            Agent::Crush => "agent crush",
            Agent::Kilo => "agent kilo",
            Agent::Goose => "agent goose",
            Agent::Cursor => "agent cursor",
            Agent::Amp => "agent amp",
            Agent::Droid => "agent droid",
        }
    }

    /// Its name, for people.
    pub const fn name(self) -> &'static str {
        match self {
            Agent::Codex => "Codex",
            Agent::Opencode => "opencode",
            Agent::Pi => "Pi",
            Agent::Antigravity => "Antigravity",
            Agent::Deepseek => "DeepSeek Harness",
            Agent::Gemini => "Gemini CLI",
            Agent::Qwen => "Qwen Code",
            Agent::Copilot => "Copilot CLI",
            Agent::Crush => "Crush",
            Agent::Kilo => "Kilo",
            Agent::Goose => "goose",
            Agent::Cursor => "Cursor",
            Agent::Amp => "Amp",
            Agent::Droid => "Droid",
        }
    }

    /// The variables that mark a command this agent runs. Every one of them is in
    /// [`crate::consent::AGENT_SESSION_ENV`].
    pub const fn session_env(self) -> &'static [&'static str] {
        match self {
            Agent::Codex => &["CODEX_CI", "CODEX_TOOL_CALL_ID", "CODEX_THREAD_ID"],
            Agent::Opencode => &["OPENCODE", "AI_AGENT"],
            Agent::Pi => &["PI_CODING_AGENT", "AI_AGENT"],
            Agent::Antigravity => &["ANTIGRAVITY_AGENT"],
            Agent::Deepseek => &["DSH_SHELL"],
            Agent::Gemini => &["GEMINI_CLI"],
            Agent::Qwen => &["QWEN_CODE"],
            Agent::Copilot => &["COPILOT_CLI"],
            Agent::Crush => &["CRUSH", "AI_AGENT"],
            Agent::Kilo => &["KILO", "OPENCODE"],
            Agent::Goose => &["AGENT_SESSION_ID", "GOOSE_TERMINAL"],
            Agent::Cursor => &["CURSOR_AGENT"],
            Agent::Amp => &["AMP_CURRENT_THREAD_ID"],
            Agent::Droid => &["FACTORY_SESSION_ID"],
        }
    }

    /// Whether the agent is known to mark every command its agent runs. Antigravity
    /// documents no mark.
    pub const fn marks_its_commands(self) -> bool {
        !matches!(self, Agent::Antigravity)
    }

    /// Where, below a project directory, it reads that project's skills, when that is
    /// not `.claude/skills`.
    pub const fn project_skills(self) -> Option<&'static str> {
        match self {
            // These read a project's `.claude/skills` themselves.
            Agent::Opencode
            | Agent::Copilot
            | Agent::Crush
            | Agent::Goose
            | Agent::Cursor
            | Agent::Amp => None,
            _ => Some(".agents/skills"),
        }
    }

    /// Where its files are, or `None` when this build looks for none (a debug build
    /// without [`AGENTS_HOME_ENV`]).
    pub fn paths(self) -> Option<Paths> {
        let b = Base::find()?;
        Some(match self {
            Agent::Codex => {
                let codex = b.var("CODEX_HOME").unwrap_or_else(|| b.join(&[".codex"]));
                Paths {
                    detect: vec![codex.clone()],
                    skills: Some(b.join(&[".agents", "skills"])),
                    tools: ToolsFile::Toml(codex.join("config.toml")),
                    hooks: Some(codex.join("hooks.json")),
                    hooks_shadow: None,
                }
            }
            Agent::Opencode => {
                let dir = b
                    .var("OPENCODE_CONFIG_DIR")
                    .or_else(|| b.var("XDG_CONFIG_HOME").map(|x| x.join("opencode")))
                    .unwrap_or_else(|| b.join(&[".config", "opencode"]));
                let json = dir.join("opencode.json");
                let jsonc = dir.join("opencode.jsonc");
                let file = if !json.exists() && jsonc.exists() {
                    jsonc
                } else {
                    json
                };
                let at = opencode_servers_at(&file);
                Paths {
                    detect: vec![dir],
                    skills: None,
                    tools: ToolsFile::Json { file, at },
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Pi => {
                let dir = b
                    .var("PI_CODING_AGENT_DIR")
                    .unwrap_or_else(|| b.join(&[".pi", "agent"]));
                Paths {
                    detect: vec![dir.clone(), b.join(&[".pi"])],
                    skills: Some(b.join(&[".agents", "skills"])),
                    tools: ToolsFile::Json {
                        file: dir.join("mcp.json"),
                        at: &["mcpServers"],
                    },
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Antigravity => {
                let config = b.join(&[".gemini", "config"]);
                Paths {
                    detect: vec![
                        config.clone(),
                        b.join(&[".gemini", "antigravity"]),
                        b.join(&[".gemini", "antigravity-cli"]),
                    ],
                    skills: Some(config.join("skills")),
                    tools: ToolsFile::Json {
                        file: config.join("mcp_config.json"),
                        at: &["mcpServers"],
                    },
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Deepseek => {
                let dsh = b.var("DSH_HOME").unwrap_or_else(|| b.join(&[".dsh"]));
                let agents = b
                    .var("DSH_AGENTS_HOME")
                    .unwrap_or_else(|| b.join(&[".agents"]));
                Paths {
                    detect: vec![dsh.clone()],
                    skills: Some(agents.join("skills")),
                    tools: ToolsFile::Manual(dsh.join("cordis.patch.yml")),
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Gemini => {
                // `GEMINI_CLI_HOME` stands in for the home directory, `.agents` included.
                let home = b.var("GEMINI_CLI_HOME").unwrap_or_else(|| b.home.clone());
                let dir = home.join(".gemini");
                Paths {
                    // Antigravity uses `~/.gemini` too, but only its `config` and
                    // `antigravity*` directories: these are Gemini CLI's own.
                    detect: vec![
                        dir.join("settings.json"),
                        dir.join("installation_id"),
                        dir.join("tmp"),
                    ],
                    skills: Some(home.join(".agents").join("skills")),
                    tools: ToolsFile::Json {
                        file: dir.join("settings.json"),
                        at: &["mcpServers"],
                    },
                    hooks: Some(dir.join("settings.json")),
                    hooks_shadow: None,
                }
            }
            Agent::Qwen => {
                let dir = b.var("QWEN_HOME").unwrap_or_else(|| b.join(&[".qwen"]));
                Paths {
                    detect: vec![dir.clone()],
                    // `QWEN_HOME` does not move this one.
                    skills: Some(b.join(&[".agents", "skills"])),
                    tools: ToolsFile::Json {
                        file: dir.join("settings.json"),
                        at: &["mcpServers"],
                    },
                    hooks: Some(dir.join("settings.json")),
                    hooks_shadow: None,
                }
            }
            Agent::Copilot => {
                let moved = b.var("COPILOT_HOME");
                let dir = moved.clone().unwrap_or_else(|| b.join(&[".copilot"]));
                Paths {
                    detect: vec![dir.clone()],
                    // With `COPILOT_HOME` set, it no longer reads `~/.agents/skills`.
                    skills: Some(if moved.is_some() {
                        dir.join("skills")
                    } else {
                        b.join(&[".agents", "skills"])
                    }),
                    tools: ToolsFile::Json {
                        file: dir.join("mcp-config.json"),
                        at: &["mcpServers"],
                    },
                    hooks: Some(dir.join("hooks").join("peerharness.json")),
                    hooks_shadow: None,
                }
            }
            Agent::Crush => {
                let dir = b
                    .var("CRUSH_GLOBAL_CONFIG")
                    .or_else(|| b.var("XDG_CONFIG_HOME").map(|x| x.join("crush")))
                    .unwrap_or_else(|| b.join(&[".config", "crush"]));
                Paths {
                    detect: vec![dir.clone(), b.join(&[".local", "share", "crush"])],
                    // It reads `~/.claude/skills`.
                    skills: None,
                    tools: ToolsFile::Json {
                        file: dir.join("crush.json"),
                        at: &["mcp"],
                    },
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Kilo => {
                let dir = b
                    .var("XDG_CONFIG_HOME")
                    .map(|x| x.join("kilo"))
                    .unwrap_or_else(|| b.join(&[".config", "kilo"]));
                // The file it reads first, as Kilo picks it; the one it creates if none.
                let file = KILO_FILES
                    .iter()
                    .map(|f| dir.join(f))
                    .find(|f| f.exists())
                    .unwrap_or_else(|| dir.join(KILO_FILES[0]));
                Paths {
                    detect: vec![dir],
                    skills: Some(b.join(&[".agents", "skills"])),
                    tools: ToolsFile::Json { file, at: &["mcp"] },
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Goose => {
                let dir = b
                    .var("GOOSE_PATH_ROOT")
                    .map(|r| r.join("config"))
                    .or_else(|| b.var("XDG_CONFIG_HOME").map(|x| x.join("goose")))
                    .unwrap_or_else(|| b.join(&[".config", "goose"]));
                Paths {
                    detect: vec![dir.clone()],
                    // It reads `~/.claude/skills`.
                    skills: None,
                    tools: ToolsFile::Manual(dir.join("config.yaml")),
                    hooks: Some(
                        b.var("GOOSE_PATH_ROOT")
                            .map(|r| r.join(".agents"))
                            .unwrap_or_else(|| b.join(&[".agents"]))
                            .join("plugins")
                            .join("peerharness")
                            .join("hooks")
                            .join("hooks.json"),
                    ),
                    hooks_shadow: None,
                }
            }
            Agent::Cursor => {
                // Its own variables move other files, never these.
                let dir = b.join(&[".cursor"]);
                Paths {
                    detect: vec![dir.clone()],
                    // It reads `~/.claude/skills` unless third-party extensibility is off.
                    skills: None,
                    tools: ToolsFile::Json {
                        file: dir.join("mcp.json"),
                        at: &["mcpServers"],
                    },
                    hooks: Some(dir.join("hooks.json")),
                    hooks_shadow: None,
                }
            }
            Agent::Amp => {
                let dir = b
                    .var("XDG_CONFIG_HOME")
                    .map(|x| x.join("amp"))
                    .unwrap_or_else(|| b.join(&[".config", "amp"]));
                let file = b.var("AMP_SETTINGS_FILE").unwrap_or_else(|| {
                    let json = dir.join("settings.json");
                    let jsonc = dir.join("settings.jsonc");
                    if !json.exists() && jsonc.exists() {
                        jsonc
                    } else {
                        json
                    }
                });
                Paths {
                    detect: vec![dir, b.join(&[".amp"])],
                    // It reads `~/.claude/skills`.
                    skills: None,
                    // One key with a dot in it, not a nested object.
                    tools: ToolsFile::Json {
                        file,
                        at: &["amp.mcpServers"],
                    },
                    hooks: None,
                    hooks_shadow: None,
                }
            }
            Agent::Droid => {
                let home = b
                    .var("FACTORY_HOME_OVERRIDE")
                    .unwrap_or_else(|| b.home.clone());
                let dir = home.join(".factory");
                Paths {
                    detect: vec![dir.clone()],
                    // It reads `~/.agents/skills`, not Claude Code's.
                    skills: Some(b.join(&[".agents", "skills"])),
                    tools: ToolsFile::Json {
                        file: dir.join("mcp.json"),
                        at: &["mcpServers"],
                    },
                    hooks: Some(dir.join("hooks.json")),
                    hooks_shadow: Some(dir.join("settings.json")),
                }
            }
        })
    }

    /// Whether the agent appears to be installed here: one of its files exists.
    pub fn detected(self) -> bool {
        self.paths()
            .is_some_and(|p| p.detect.iter().any(|d| d.exists()))
    }

    /// The JSON entry of the MCP server for `server` (this binary and its arguments).
    pub fn json_entry(self, server: &[String], at: &[&str]) -> Value {
        let (program, args) = server
            .split_first()
            .map_or(("", &[][..]), |(p, a)| (p.as_str(), a));
        match self {
            // The first major version's shape, which the second reads too; under
            // `mcp.servers` the second version's own.
            Agent::Opencode if at.len() == 2 => json!({"type": "local", "command": server}),
            Agent::Opencode => json!({"type": "local", "command": server, "enabled": true}),
            // Pi exposes a server's tools to the model only with `direct`.
            Agent::Pi => json!({"command": program, "args": args, "exposure": "direct"}),
            // What `copilot mcp add` writes.
            Agent::Copilot => {
                json!({"type": "local", "command": program, "args": args, "tools": ["*"]})
            }
            Agent::Crush | Agent::Droid => {
                json!({"type": "stdio", "command": program, "args": args})
            }
            // opencode's first version's shape, which Kilo keeps.
            Agent::Kilo => json!({"type": "local", "command": server, "enabled": true}),
            _ => json!({"command": program, "args": args}),
        }
    }

    /// The TOML server for `server` (Codex).
    pub fn toml_server(server: &[String]) -> ph_observer::agent_config::TomlServer {
        let (program, args) = server
            .split_first()
            .map_or((String::new(), Vec::new()), |(p, a)| {
                (p.clone(), a.to_vec())
            });
        ph_observer::agent_config::TomlServer {
            table: "mcp_servers".into(),
            name: SERVER_NAME.into(),
            command: program,
            args,
        }
    }

    /// The agent with this id.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }

    /// How PeerHarness's hooks fit this agent, or `None` for one that gets none: it has
    /// no command hooks in a file (opencode, Kilo, Pi and Amp run code plugins,
    /// DeepSeek Harness a package to install), its event carries no prompt (Crush), or
    /// what its documentation says could not be relied on (Antigravity). ADR-053 has
    /// the reasons.
    pub const fn hook_spec(self) -> Option<HookSpec> {
        let claude_like = HookSpec {
            at: &["hooks"],
            version: false,
            own_dirs: 0,
            prompt_event: "UserPromptSubmit",
            stop_event: Some("Stop"),
            entry: HookEntry::Group {
                timeout: HOOK_TIMEOUT_SECS,
            },
            payload: CLAUDE_PAYLOAD,
            note: None,
        };
        Some(match self {
            Agent::Codex => HookSpec {
                note: Some(
                    "Codex runs a hook only after you trusted it: it asks when it next \
                     starts, and `/hooks` in Codex shows them. It does not show the notice \
                     in `codex exec`.",
                ),
                ..claude_like
            },
            // The events are the top level of its `hooks.json`.
            Agent::Droid => HookSpec {
                at: &[],
                ..claude_like
            },
            // Its timeout is in milliseconds.
            Agent::Gemini => HookSpec {
                prompt_event: "BeforeAgent",
                stop_event: Some("AfterAgent"),
                entry: HookEntry::Group {
                    timeout: HOOK_TIMEOUT_SECS * 1000,
                },
                note: Some(
                    "Gemini CLI runs hooks only in a folder you trusted, and shows the \
                     notice only when you work with it interactively.",
                ),
                ..claude_like
            },
            // Its prompt event also fires when tool results go back to the model;
            // `submitted_prompt` is there only for what the person submitted.
            Agent::Qwen => HookSpec {
                payload: ph_observer::PayloadShape {
                    prompt: &["submitted_prompt"],
                    ..CLAUDE_PAYLOAD
                },
                ..claude_like
            },
            // At the end of a turn its hook can only start another turn.
            Agent::Cursor => HookSpec {
                version: true,
                prompt_event: "beforeSubmitPrompt",
                stop_event: None,
                entry: HookEntry::Flat,
                payload: ph_observer::PayloadShape {
                    prompt: &["prompt"],
                    session: &["conversation_id", "session_id"],
                    cwd: &[],
                    cwd_list: Some("workspace_roots"),
                },
                note: Some(
                    "Cursor's log says of each run that the hook printed nothing: that is \
                     how it is meant.",
                ),
                ..claude_like
            },
            // A file of PeerHarness's own in its hooks directory. Nothing a hook
            // prints at the end of a turn is known to reach the person alone.
            Agent::Copilot => HookSpec {
                version: true,
                prompt_event: "userPromptSubmitted",
                stop_event: None,
                entry: HookEntry::Bash,
                payload: ph_observer::PayloadShape {
                    prompt: &["prompt"],
                    session: &["sessionId", "session_id"],
                    cwd: &["cwd"],
                    cwd_list: None,
                },
                note: Some("Copilot CLI reads its hooks when it starts."),
                ..claude_like
            },
            // Hooks come in a plugin's folder. Anything a hook prints at the end of a
            // turn counts as a failure there.
            Agent::Goose => HookSpec {
                own_dirs: 2,
                stop_event: None,
                payload: ph_observer::PayloadShape {
                    prompt: &["message"],
                    session: &["session_id"],
                    cwd: &["working_dir"],
                    cwd_list: None,
                },
                note: Some(
                    "goose finds the folder when a session starts and lists it under \
                     `plugins` in its config.yaml.",
                ),
                ..claude_like
            },
            Agent::Opencode
            | Agent::Pi
            | Agent::Antigravity
            | Agent::Deepseek
            | Agent::Crush
            | Agent::Kilo
            | Agent::Amp => return None,
        })
    }

    /// The entry for `command` in this agent's hooks file.
    pub fn hook_entry(self, command: &str) -> Option<Value> {
        Some(match self.hook_spec()?.entry {
            HookEntry::Group { timeout } => json!({
                "hooks": [{ "type": "command", "command": command, "timeout": timeout }]
            }),
            HookEntry::Flat => json!({ "command": command, "timeout": HOOK_TIMEOUT_SECS }),
            HookEntry::Bash => json!({
                "type": "command",
                "bash": command,
                "timeoutSec": HOOK_TIMEOUT_SECS,
            }),
        })
    }

    /// What the owner has to do besides, for the agent to start the tools.
    pub const fn tools_note(self) -> Option<&'static str> {
        match self {
            Agent::Gemini => Some(
                "Gemini CLI starts it only in a folder you trusted (it asks when you open one).",
            ),
            Agent::Cursor => Some(
                "Cursor's CLI asks you to approve it once in each project (`agent mcp enable \
                 peerharness`, or when it asks).",
            ),
            _ => None,
        }
    }

    /// The entry the owner adds by hand, for an agent whose file PeerHarness does not
    /// edit: DeepSeek Harness's Cordis patch file, goose's `config.yaml`. Both are YAML.
    pub fn manual_entry(self, server: &[String]) -> String {
        let (program, args) = server
            .split_first()
            .map_or(("", &[][..]), |(p, a)| (p.as_str(), a));
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let args: Vec<String> = args.iter().map(|a| quote(a)).collect();
        match self {
            Agent::Goose => format!(
                "extensions:\n  {SERVER_NAME}:\n    type: stdio\n    name: {SERVER_NAME}\n    \
                 enabled: true\n    cmd: {}\n    args: [{}]\n    envs: {{}}\n    \
                 env_keys: []\n    timeout: 300\n",
                quote(program),
                args.join(", ")
            ),
            _ => format!(
                "- insert:\n    - id: peerharness-mcp\n      name: '@deepseek-ai/dsh-mcp-client'\n      \
                 config:\n        serverName: {SERVER_NAME}\n        transport: stdio\n        \
                 command: {}\n        args: [{}]\n",
                quote(program),
                args.join(", ")
            ),
        }
    }
}

/// Kilo's global configuration files, in the order it looks for the one it writes.
const KILO_FILES: [&str; 5] = [
    "kilo.jsonc",
    "kilo.json",
    "opencode.jsonc",
    "opencode.json",
    "config.json",
];

/// Where opencode's servers go in `file`: under `mcp.servers` when the file already
/// uses the second major version's layout, else under `mcp`, which both versions read.
fn opencode_servers_at(file: &Path) -> &'static [&'static str] {
    let uses_servers = std::fs::read(file)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .is_some_and(|v| v["mcp"]["servers"].is_object());
    if uses_servers {
        &["mcp", "servers"]
    } else {
        &["mcp"]
    }
}

/// The server command as strings, for a configuration file. A path that is not UTF-8
/// cannot be written there.
pub fn utf8_command(server: &[OsString]) -> Result<Vec<String>> {
    server
        .iter()
        .map(|w| {
            w.to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("the path of this executable or home is not valid UTF-8"))
        })
        .collect()
}

/// "Codex", "Codex and Pi", "Codex, Pi and opencode".
pub fn names(agents: &[Agent]) -> String {
    let names: Vec<&str> = agents.iter().map(|a| a.name()).collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_owned(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mark_of_an_agent_is_a_mark_of_a_session() {
        for a in Agent::ALL {
            assert!(!a.session_env().is_empty(), "{a:?}");
            for v in a.session_env() {
                assert!(crate::consent::AGENT_SESSION_ENV.contains(v), "{a:?}: {v}");
            }
        }
    }

    #[test]
    fn ids_and_names() {
        for a in Agent::ALL {
            let parsed: Agent = serde_json::from_value(json!(a.id())).unwrap();
            assert_eq!(parsed, a);
            assert_eq!(
                <Agent as clap::ValueEnum>::from_str(a.id(), false).unwrap(),
                a
            );
        }
        assert_eq!(names(&[Agent::Codex]), "Codex");
        assert_eq!(names(&[Agent::Codex, Agent::Pi]), "Codex and Pi");
        assert_eq!(
            names(&[Agent::Codex, Agent::Pi, Agent::Opencode]),
            "Codex, Pi and opencode"
        );
    }

    #[test]
    fn entries_carry_the_command_as_given() {
        let server: Vec<String> = ["/opt/ph/peerharness", "--home", "/h", "mcp"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            Agent::Pi.json_entry(&server, &["mcpServers"]),
            json!({"command": "/opt/ph/peerharness", "args": ["--home", "/h", "mcp"], "exposure": "direct"})
        );
        assert_eq!(
            Agent::Antigravity.json_entry(&server, &["mcpServers"]),
            json!({"command": "/opt/ph/peerharness", "args": ["--home", "/h", "mcp"]})
        );
        assert_eq!(
            Agent::Opencode.json_entry(&server, &["mcp"]),
            json!({"type": "local", "command": ["/opt/ph/peerharness", "--home", "/h", "mcp"], "enabled": true})
        );
        assert_eq!(
            Agent::Opencode.json_entry(&server, &["mcp", "servers"]),
            json!({"type": "local", "command": ["/opt/ph/peerharness", "--home", "/h", "mcp"]})
        );
        let t = Agent::toml_server(&server);
        assert_eq!(t.command, "/opt/ph/peerharness");
        assert_eq!(t.args, ["--home", "/h", "mcp"]);
        let args = ["--home", "/h", "mcp"];
        assert_eq!(
            Agent::Copilot.json_entry(&server, &["mcpServers"]),
            json!({"type": "local", "command": "/opt/ph/peerharness", "args": args, "tools": ["*"]})
        );
        for a in [Agent::Crush, Agent::Droid] {
            assert_eq!(
                a.json_entry(&server, &["mcp"]),
                json!({"type": "stdio", "command": "/opt/ph/peerharness", "args": args}),
                "{a:?}"
            );
        }
        assert_eq!(
            Agent::Kilo.json_entry(&server, &["mcp"]),
            json!({"type": "local", "command": ["/opt/ph/peerharness", "--home", "/h", "mcp"], "enabled": true})
        );
        for a in [Agent::Gemini, Agent::Qwen, Agent::Cursor, Agent::Amp] {
            assert_eq!(
                a.json_entry(&server, &["mcpServers"]),
                json!({"command": "/opt/ph/peerharness", "args": args}),
                "{a:?}"
            );
        }
        let g = Agent::Goose.manual_entry(&["/a b/it's".to_owned(), "mcp".to_owned()]);
        assert!(
            g.starts_with("extensions:\n  peerharness:\n    type: stdio\n"),
            "{g}"
        );
        assert!(
            g.contains("    cmd: '/a b/it''s'\n    args: ['mcp']\n"),
            "{g}"
        );
        let y = Agent::Deepseek.manual_entry(&["/a b/it's".to_owned(), "mcp".to_owned()]);
        assert!(y.contains("command: '/a b/it''s'"), "{y}");
        assert!(y.contains("args: ['mcp']"), "{y}");
    }

    #[test]
    fn opencode_keeps_the_layout_its_file_uses() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("opencode.json");
        assert_eq!(opencode_servers_at(&f), &["mcp"]);
        std::fs::write(&f, r#"{"mcp": {"servers": {}}}"#).unwrap();
        assert_eq!(opencode_servers_at(&f), &["mcp", "servers"]);
        std::fs::write(&f, r#"{"mcp": {"x": {"type": "local"}}}"#).unwrap();
        assert_eq!(opencode_servers_at(&f), &["mcp"]);
    }
}
