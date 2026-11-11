//! The coding agents besides Claude Code that PeerHarness connects to (ADR-050):
//! Codex, opencode, Pi, Google Antigravity and DeepSeek Harness.
//!
//! Claude Code stays where rules are installed: its skills directory (or a project's
//! `.claude/skills`) is where every decision about installing, holding and removing a
//! rule is taken (`governance::apply_rules`). An agent connected here gets three things,
//! each checked against its own source or documentation on 2026-11-12:
//!
//! * **The rules.** An agent that reads Claude Code's skills directory itself (opencode)
//!   needs nothing. For the others, PeerHarness keeps managed copies of what it manages
//!   there in the directory the agent reads ([`crate::copies`]): `~/.agents/skills` for
//!   Codex, Pi and DeepSeek Harness, `~/.gemini/config/skills` for Antigravity, and a
//!   project's `.agents/skills` for a project.
//! * **The tools.** `peerharness mcp` is registered in the agent's configuration file,
//!   with a backup, when the agent has one PeerHarness can edit safely: a TOML block for
//!   Codex, a JSON entry for Pi, Antigravity and opencode. DeepSeek Harness keeps its
//!   servers in its own YAML patch files, so the entry is shown for the owner to add.
//! * **Its sessions are recognized.** The variables each agent sets in the commands it
//!   runs are in [`crate::consent::AGENT_SESSION_ENV`], so a decision started there is
//!   refused, or asked in a window, as from Claude Code.
//!
//! Where an agent's files are: under the user's home directory, honouring the agent's
//! own variables that move them (`CODEX_HOME`, `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`,
//! `PI_CODING_AGENT_DIR`, `DSH_HOME`, `DSH_AGENTS_HOME`). `PEERHARNESS_AGENTS_HOME`
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
}

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
    pub const ALL: [Agent; 5] = [
        Agent::Codex,
        Agent::Opencode,
        Agent::Pi,
        Agent::Antigravity,
        Agent::Deepseek,
    ];

    /// The word used on the command line and in the config file.
    pub const fn id(self) -> &'static str {
        match self {
            Agent::Codex => "codex",
            Agent::Opencode => "opencode",
            Agent::Pi => "pi",
            Agent::Antigravity => "antigravity",
            Agent::Deepseek => "deepseek",
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
        }
    }

    /// Whether the agent is known to mark every command it runs. Antigravity documents
    /// no mark.
    pub const fn marks_its_commands(self) -> bool {
        !matches!(self, Agent::Antigravity)
    }

    /// Where, below a project directory, it reads that project's skills, when that is
    /// not `.claude/skills`.
    pub const fn project_skills(self) -> Option<&'static str> {
        match self {
            Agent::Opencode => None,
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
                }
            }
        })
    }

    /// Whether the agent appears to be installed here: one of its directories exists.
    pub fn detected(self) -> bool {
        self.paths()
            .is_some_and(|p| p.detect.iter().any(|d| d.is_dir()))
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

    /// The entry the owner adds by hand, for an agent whose file PeerHarness does not
    /// edit (DeepSeek Harness's Cordis patch file).
    pub fn manual_entry(self, server: &[String]) -> String {
        let (program, args) = server
            .split_first()
            .map_or(("", &[][..]), |(p, a)| (p.as_str(), a));
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let args: Vec<String> = args.iter().map(|a| quote(a)).collect();
        format!(
            "- insert:\n    - id: peerharness-mcp\n      name: '@deepseek-ai/dsh-mcp-client'\n      \
             config:\n        serverName: {SERVER_NAME}\n        transport: stdio\n        \
             command: {}\n        args: [{}]\n",
            quote(program),
            args.join(", ")
        )
    }
}

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
