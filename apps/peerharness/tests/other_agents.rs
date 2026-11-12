//! The coding agents besides Claude Code (ADR-050), through the real binary: `setup`
//! connects the ones it finds, their skills directories hold copies of what PeerHarness
//! manages and follow every change, their configuration gets the tools entry with the
//! rest of the file kept, and `watch <agent> --remove` takes out what was put in and
//! nothing else. Connecting is refused inside any agent's session, and a debug build
//! finds no agent outside `PEERHARNESS_AGENTS_HOME`.
//!
//! Nothing here touches the developer's own agents: every agent's files are under a
//! temporary `PEERHARNESS_AGENTS_HOME`, `HOME` is a temporary directory too, Claude
//! Code's skills and settings go to temporary paths, and the window is a stand-in that
//! declines.
#![cfg(all(unix, debug_assertions))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

/// The variables that mark an agent's session, taken out for the person.
const MARKS: [&str; 20] = [
    "CLAUDECODE",
    "PEERHARNESS_AGENT_SESSION",
    "CODEX_CI",
    "CODEX_TOOL_CALL_ID",
    "CODEX_THREAD_ID",
    "OPENCODE",
    "PI_CODING_AGENT",
    "AI_AGENT",
    "ANTIGRAVITY_AGENT",
    "DSH_SHELL",
    "GEMINI_CLI",
    "QWEN_CODE",
    "COPILOT_CLI",
    "CURSOR_AGENT",
    "AMP_CURRENT_THREAD_ID",
    "FACTORY_SESSION_ID",
    "CRUSH",
    "KILO",
    "GOOSE_TERMINAL",
    "AGENT_SESSION_ID",
];

const CODEX_CONFIG: &str = "# my Codex settings\nmodel = \"gpt-5\"  # keep this\n\n[mcp_servers.other]\ncommand = \"other\"\n";

struct Machine {
    home: PathBuf,
    skills: PathBuf,
    settings: PathBuf,
    window: PathBuf,
    agents: PathBuf,
    fake_home: PathBuf,
}

impl Machine {
    fn new(root: &Path) -> Self {
        let m = Self {
            home: root.join("ph"),
            skills: root.join("claude-skills"),
            settings: root.join("claude-settings.json"),
            window: root.join("window.sh"),
            agents: root.join("agents-home"),
            fake_home: root.join("home"),
        };
        std::fs::write(&m.window, "#!/bin/sh\ncat > /dev/null\necho declined\n").unwrap();
        std::fs::set_permissions(&m.window, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(&m.fake_home).unwrap();
        std::fs::create_dir_all(&m.agents).unwrap();
        m
    }

    /// Codex, Pi and opencode are installed here; Antigravity and DeepSeek Harness are not.
    fn with_three_agents(self) -> Self {
        std::fs::create_dir_all(self.agents.join(".codex")).unwrap();
        std::fs::write(self.agents.join(".codex/config.toml"), CODEX_CONFIG).unwrap();
        std::fs::create_dir_all(self.agents.join(".pi/agent")).unwrap();
        std::fs::create_dir_all(self.agents.join(".config/opencode")).unwrap();
        self
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("peerharness"));
        cmd.env("PEERHARNESS_HOME", &self.home)
            .env("PEERHARNESS_CLAUDE_SKILLS_DIR", &self.skills)
            .env("PEERHARNESS_CLAUDE_SETTINGS", &self.settings)
            .env("PEERHARNESS_TEST_WINDOW_BIN", &self.window)
            .env("PEERHARNESS_AGENTS_HOME", &self.agents)
            .env("HOME", &self.fake_home)
            .env("USER", "alice")
            .env_remove("PEERHARNESS_TEST_CLAUDE_BIN")
            .args(args);
        for mark in MARKS {
            cmd.env_remove(mark);
        }
        cmd
    }

    fn setup(&self, more: &[&str]) -> Output {
        let mut args = vec![
            "setup",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
            "--yes",
        ];
        args.extend(more);
        self.cmd(&args).output().unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend(args);
        let out = self.cmd(&all).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", text(&out));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn copies(&self) -> PathBuf {
        self.agents.join(".agents/skills")
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn exe() -> String {
    assert_cmd::cargo::cargo_bin("peerharness")
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn setup_connects_the_agents_it_finds_and_the_rules_follow_them() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path()).with_three_agents();
    // A skill of the owner's own where Codex and Pi read skills.
    std::fs::create_dir_all(m.copies().join("mine")).unwrap();
    std::fs::write(m.copies().join("mine/SKILL.md"), "my own").unwrap();

    let out = m.setup(&[]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    // Each agent was shown what would change before it changed.
    let f = flat(&said);
    assert!(f.contains("This connects Codex to PeerHarness."), "{said}");
    assert!(f.contains("This connects Pi to PeerHarness."), "{said}");
    assert!(
        f.contains("This connects opencode to PeerHarness."),
        "{said}"
    );
    assert!(
        f.contains("opencode already reads Claude Code's skills"),
        "{said}"
    );
    assert!(
        f.contains("CODEX_CI, CODEX_TOOL_CALL_ID, CODEX_THREAD_ID"),
        "{said}"
    );
    assert!(said.contains("4. Other agents:"), "{said}");
    for name in ["Codex", "Pi", "opencode"] {
        assert!(
            said.contains(&format!("  {name}: connected.")),
            "{name}: {said}"
        );
    }
    assert!(!said.contains("Antigravity: connected"), "{said}");
    assert!(!m.agents.join(".gemini").exists());
    assert!(!m.agents.join(".dsh").exists());
    assert!(
        f.contains("session of Claude Code (or Codex, opencode or Pi)"),
        "{said}"
    );

    // Codex: the block appended, the owner's file kept as it was above it.
    let toml_text = std::fs::read_to_string(m.agents.join(".codex/config.toml")).unwrap();
    assert!(toml_text.starts_with(CODEX_CONFIG), "{toml_text}");
    let t: toml::Table = toml_text.parse().unwrap();
    let entry = &t["mcp_servers"]["peerharness"];
    assert_eq!(entry["command"].as_str(), Some(exe().as_str()));
    let args: Vec<&str> = entry["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(args.last(), Some(&"mcp"));
    assert!(t["mcp_servers"]["other"].is_table());
    // Pi: its tools reach the model directly.
    let pi = read_json(&m.agents.join(".pi/agent/mcp.json"));
    assert_eq!(pi["mcpServers"]["peerharness"]["command"], exe().as_str());
    assert_eq!(pi["mcpServers"]["peerharness"]["exposure"], "direct");
    // opencode: a file made for it, in the shape both its versions read.
    let oc = read_json(&m.agents.join(".config/opencode/opencode.json"));
    assert_eq!(oc["mcp"]["peerharness"]["type"], "local");
    assert_eq!(oc["mcp"]["peerharness"]["command"][0], exe().as_str());
    assert_eq!(oc["$schema"], "https://opencode.ai/config.json");

    // PeerHarness's own skill is copied where Codex and Pi read skills, the owner's
    // own skill there is untouched, and opencode needs no copy.
    let notes = std::fs::read(m.skills.join("peerharness-notes/SKILL.md")).unwrap();
    assert_eq!(
        std::fs::read(m.copies().join("peerharness-notes/SKILL.md")).unwrap(),
        notes
    );
    assert_eq!(
        std::fs::read_to_string(m.copies().join("mine/SKILL.md")).unwrap(),
        "my own"
    );
    assert!(!m.agents.join(".config/opencode/skills").exists());

    // A rule kept for oneself reaches them too, and goes when it is uninstalled.
    let noted = m.json(&[
        "note",
        "--name",
        "use-pnpm",
        "Use pnpm, not npm, in this repository.",
    ]);
    let cand = noted["candidate_id"].as_str().unwrap().to_owned();
    m.json(&["keep", &cand, "--yes"]);
    assert!(m.skills.join("use-pnpm/SKILL.md").is_file());
    assert_eq!(
        std::fs::read(m.copies().join("use-pnpm/SKILL.md")).unwrap(),
        std::fs::read(m.skills.join("use-pnpm/SKILL.md")).unwrap()
    );
    m.json(&["skills", "uninstall", "use-pnpm"]);
    assert!(!m.skills.join("use-pnpm").exists());
    assert!(!m.copies().join("use-pnpm").exists());

    // A second run changes nothing.
    let again = m.setup(&[]);
    let said = text(&again);
    assert!(again.status.success(), "{said}");
    for name in ["Codex", "Pi", "opencode"] {
        assert!(
            said.contains(&format!("  {name}: already connected.")),
            "{name}: {said}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".codex/config.toml")).unwrap(),
        toml_text
    );

    // Doctor names them.
    let doctor = m.json(&["doctor"]);
    let checks = doctor["checks"].as_array().unwrap();
    for check in ["agent codex", "agent pi", "agent opencode"] {
        assert!(
            checks
                .iter()
                .any(|c| c["check"] == check && c["level"] == "ok"),
            "{check}: {doctor}"
        );
    }

    // Disconnecting Codex takes out its block alone; the copies stay for Pi.
    let out = m
        .cmd(&["watch", "codex", "--remove", "--yes"])
        .output()
        .unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(
        flat(&said).contains("stay, because Pi reads them too"),
        "{said}"
    );
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".codex/config.toml")).unwrap(),
        CODEX_CONFIG
    );
    assert!(m.copies().join("peerharness-notes/SKILL.md").is_file());
    let st = m.json(&["watch", "codex", "--status"]);
    assert_eq!(st["connected"], false);
    assert_eq!(st["tools"], "not_registered");

    // Disconnecting Pi removes the copies, and only them.
    let st = m.json(&["watch", "pi", "--remove", "--yes"]);
    assert_eq!(st["connected"], false);
    assert!(!m.copies().join("peerharness-notes").exists());
    assert_eq!(
        std::fs::read_to_string(m.copies().join("mine/SKILL.md")).unwrap(),
        "my own"
    );
    let pi = read_json(&m.agents.join(".pi/agent/mcp.json"));
    assert!(pi["mcpServers"].get("peerharness").is_none(), "{pi}");
    // Nothing comes back after another command.
    m.json(&["status"]);
    assert!(!m.copies().join("peerharness-notes").exists());
}

#[test]
fn a_configuration_peerharness_cannot_edit_safely_is_left_and_the_entry_shown() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    // opencode's file with comments, and a server of that name the owner wrote in Pi's.
    std::fs::create_dir_all(m.agents.join(".config/opencode")).unwrap();
    let jsonc = "{\n  // mine\n  \"theme\": \"dark\"\n}\n";
    std::fs::write(m.agents.join(".config/opencode/opencode.jsonc"), jsonc).unwrap();
    std::fs::create_dir_all(m.agents.join(".pi/agent")).unwrap();
    let theirs = r#"{"mcpServers": {"peerharness": {"command": "peerharness", "args": ["mcp"]}}}"#;
    std::fs::write(m.agents.join(".pi/agent/mcp.json"), theirs).unwrap();
    // DeepSeek Harness: PeerHarness never edits its files.
    std::fs::create_dir_all(m.agents.join(".dsh")).unwrap();

    let out = m.setup(&[]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".config/opencode/opencode.jsonc")).unwrap(),
        jsonc
    );
    assert!(
        said.contains("\"peerharness\""),
        "the entry is shown: {said}"
    );
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".pi/agent/mcp.json")).unwrap(),
        theirs
    );
    assert!(
        flat(&said)
            .contains("already has a server named peerharness that PeerHarness did not write"),
        "{said}"
    );
    assert!(flat(&said).contains("merge this into"), "{said}");
    assert!(said.contains("serverName: peerharness"), "{said}");
    assert!(!m.agents.join(".dsh/cordis.patch.yml").exists());
    // The rules still reach DeepSeek Harness and Pi.
    assert!(m.copies().join("peerharness-notes/SKILL.md").is_file());
    let st = m.json(&["watch", "deepseek", "--status"]);
    assert_eq!(st["connected"], true);
    assert_eq!(st["tools"], "manual");

    // Removing leaves the owner's entry.
    m.json(&["watch", "pi", "--remove", "--yes"]);
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".pi/agent/mcp.json")).unwrap(),
        theirs
    );
}

#[test]
fn connecting_an_agent_is_refused_inside_any_agents_session() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path()).with_three_agents();
    let out = m.setup(&["--no-dialogs", "--agent", "codex"]);
    assert!(out.status.success(), "{}", text(&out));
    let noted = m.json(&[
        "note",
        "--name",
        "use-pnpm",
        "Use pnpm, not npm, in this repository.",
    ]);
    let cand = noted["candidate_id"].as_str().unwrap().to_owned();

    for (mark, value) in [
        ("CODEX_CI", "1"),
        ("CODEX_THREAD_ID", "0199a"),
        ("OPENCODE", "1"),
        ("PI_CODING_AGENT", "true"),
        ("AI_AGENT", "pi"),
        ("ANTIGRAVITY_AGENT", "1"),
        ("DSH_SHELL", "1"),
        ("GEMINI_CLI", "1"),
        ("QWEN_CODE", "1"),
        ("COPILOT_CLI", "1"),
        ("CURSOR_AGENT", "1"),
        ("AMP_CURRENT_THREAD_ID", "T-0199a"),
        ("FACTORY_SESSION_ID", "0199a"),
        ("CRUSH", "1"),
        ("KILO", "1"),
        ("GOOSE_TERMINAL", "1"),
        ("AGENT_SESSION_ID", "20261111_1"),
    ] {
        for args in [
            vec!["watch", "pi", "--install", "--yes"],
            vec!["watch", "codex", "--remove", "--yes"],
            vec!["keep", cand.as_str(), "--yes"],
            vec!["setup", "--yes"],
        ] {
            let out = m.cmd(&args).env(mark, value).output().unwrap();
            let said = text(&out);
            assert!(!out.status.success(), "{mark} {args:?}: {said}");
            assert!(
                said.contains("inside a coding agent's session"),
                "{mark} {args:?}: {said}"
            );
            // The refusal names the variable, never its value, for a person refused in a
            // shell of their own.
            assert!(
                said.contains(&format!("({mark} is set here.)")),
                "{mark} {args:?}: {said}"
            );
            // A value long enough not to stand in other words is not repeated.
            assert!(value.len() < 5 || !said.contains(value), "{mark}: {said}");
        }
    }
    // Nothing changed meanwhile.
    assert_eq!(m.json(&["watch", "pi", "--status"])["connected"], false);
    assert_eq!(m.json(&["watch", "codex", "--status"])["connected"], true);
    assert!(!m.skills.join("use-pnpm").exists());
}

#[test]
fn a_debug_build_finds_no_agent_outside_its_own_variable() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    // Agents installed in the home directory these commands see.
    std::fs::create_dir_all(m.fake_home.join(".codex")).unwrap();
    std::fs::create_dir_all(m.fake_home.join(".pi/agent")).unwrap();
    let run = |args: &[&str]| {
        let mut cmd = m.cmd(args);
        cmd.env_remove("PEERHARNESS_AGENTS_HOME");
        cmd.output().unwrap()
    };
    let out = run(&[
        "setup",
        "--keystore",
        "insecure-dev",
        "--insecure-dev-keystore",
        "--yes",
    ]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("4. Other agents: none found here"), "{said}");
    let out = run(&["watch", "codex", "--install", "--yes"]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("PEERHARNESS_AGENTS_HOME"),
        "{}",
        text(&out)
    );
    assert!(!m.fake_home.join(".agents").exists());
    assert_eq!(
        std::fs::read_dir(m.fake_home.join(".codex"))
            .unwrap()
            .count(),
        0
    );
}

/// What one agent is expected to get: where it reads skills (`None`: Claude Code's
/// directory), and how its tools entry is read back.
struct Expect {
    agent: &'static str,
    detect: &'static str,
    copies: Option<&'static str>,
    tools: &'static str,
}

const EVERY_AGENT: [Expect; 14] = [
    Expect {
        agent: "codex",
        detect: ".codex",
        copies: Some(".agents/skills"),
        tools: ".codex/config.toml",
    },
    Expect {
        agent: "opencode",
        detect: ".config/opencode",
        copies: None,
        tools: ".config/opencode/opencode.json",
    },
    Expect {
        agent: "pi",
        detect: ".pi/agent",
        copies: Some(".agents/skills"),
        tools: ".pi/agent/mcp.json",
    },
    Expect {
        agent: "antigravity",
        detect: ".gemini/config",
        copies: Some(".gemini/config/skills"),
        tools: ".gemini/config/mcp_config.json",
    },
    Expect {
        agent: "deepseek",
        detect: ".dsh",
        copies: Some(".agents/skills"),
        tools: ".dsh/cordis.patch.yml",
    },
    Expect {
        agent: "gemini",
        detect: ".gemini/settings.json",
        copies: Some(".agents/skills"),
        tools: ".gemini/settings.json",
    },
    Expect {
        agent: "qwen",
        detect: ".qwen",
        copies: Some(".agents/skills"),
        tools: ".qwen/settings.json",
    },
    Expect {
        agent: "copilot",
        detect: ".copilot",
        copies: Some(".agents/skills"),
        tools: ".copilot/mcp-config.json",
    },
    Expect {
        agent: "crush",
        detect: ".config/crush",
        copies: None,
        tools: ".config/crush/crush.json",
    },
    Expect {
        agent: "kilo",
        detect: ".config/kilo",
        copies: Some(".agents/skills"),
        tools: ".config/kilo/kilo.jsonc",
    },
    Expect {
        agent: "goose",
        detect: ".config/goose",
        copies: None,
        tools: ".config/goose/config.yaml",
    },
    Expect {
        agent: "cursor",
        detect: ".cursor",
        copies: None,
        tools: ".cursor/mcp.json",
    },
    Expect {
        agent: "amp",
        detect: ".config/amp",
        copies: None,
        tools: ".config/amp/settings.json",
    },
    Expect {
        agent: "droid",
        detect: ".factory",
        copies: Some(".agents/skills"),
        tools: ".factory/mcp.json",
    },
];

/// The command a tools entry starts, read back from the file the agent reads.
fn registered_command(e: &Expect, file: &Path) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    match e.agent {
        "codex" => {
            let t: toml::Table = text.parse().unwrap();
            t.get("mcp_servers")?
                .get("peerharness")?
                .get("command")?
                .as_str()
                .map(str::to_owned)
        }
        "opencode" | "kilo" => {
            let v: Value = serde_json::from_str(&text).unwrap();
            v["mcp"]["peerharness"]["command"][0]
                .as_str()
                .map(str::to_owned)
        }
        "crush" => {
            let v: Value = serde_json::from_str(&text).unwrap();
            v["mcp"]["peerharness"]["command"]
                .as_str()
                .map(str::to_owned)
        }
        "amp" => {
            let v: Value = serde_json::from_str(&text).unwrap();
            v["amp.mcpServers"]["peerharness"]["command"]
                .as_str()
                .map(str::to_owned)
        }
        "pi" | "antigravity" | "gemini" | "qwen" | "copilot" | "cursor" | "droid" => {
            let v: Value = serde_json::from_str(&text).unwrap();
            v["mcpServers"]["peerharness"]["command"]
                .as_str()
                .map(str::to_owned)
        }
        _ => None,
    }
}

#[test]
fn every_agent_is_connected_gets_the_rules_and_is_disconnected_alone() {
    for e in EVERY_AGENT {
        let tmp = TempDir::new().unwrap();
        let m = Machine::new(tmp.path());
        let found = m.agents.join(e.detect);
        if found.extension().is_some() {
            // A file of the agent's own, as it leaves it.
            std::fs::create_dir_all(found.parent().unwrap()).unwrap();
            std::fs::write(&found, "{}\n").unwrap();
        } else {
            std::fs::create_dir_all(&found).unwrap();
        }
        // `setup` finds this agent and no other.
        let out = m.setup(&[]);
        let said = text(&out);
        assert!(out.status.success(), "{}: {said}", e.agent);
        let st = m.json(&["watch", e.agent, "--status"]);
        assert_eq!(st["connected"], true, "{}: {st}", e.agent);
        assert_eq!(st["detected"], true, "{}: {st}", e.agent);
        for other in EVERY_AGENT.iter().filter(|o| o.agent != e.agent) {
            assert_eq!(
                m.json(&["watch", other.agent, "--status"])["connected"],
                false,
                "{} connected {}",
                e.agent,
                other.agent
            );
        }

        // The tools: written where the agent reads them, except in YAML (DeepSeek
        // Harness's and goose's), which is shown.
        let tools = m.agents.join(e.tools);
        if e.agent == "deepseek" || e.agent == "goose" {
            assert!(!tools.exists());
            assert_eq!(st["tools"], "manual");
            let line = if e.agent == "goose" {
                "cmd: '"
            } else {
                "serverName: peerharness"
            };
            assert!(said.contains(line), "{said}");
        } else {
            assert_eq!(st["tools"], "registered", "{}: {st}", e.agent);
            assert_eq!(
                registered_command(&e, &tools).as_deref(),
                Some(exe().as_str()),
                "{}",
                e.agent
            );
        }

        // The rules: a kept rule and PeerHarness's own skill where the agent reads
        // skills, byte for byte.
        let noted = m.json(&[
            "note",
            "--name",
            "use-pnpm",
            "Use pnpm, not npm, in this repository.",
        ]);
        let cand = noted["candidate_id"].as_str().unwrap().to_owned();
        m.json(&["keep", &cand, "--yes"]);
        match e.copies {
            None => {
                // It reads Claude Code's directory: nothing is copied anywhere.
                assert!(!m.agents.join(".agents").exists(), "{}", e.agent);
                assert!(!m.agents.join(".config/opencode/skills").exists());
                assert_eq!(st["skills_dir"], Value::Null, "{}: {st}", e.agent);
            }
            Some(dir) => {
                let dir = m.agents.join(dir);
                for skill in ["use-pnpm", "peerharness-notes"] {
                    assert_eq!(
                        std::fs::read(dir.join(skill).join("SKILL.md")).unwrap(),
                        std::fs::read(m.skills.join(skill).join("SKILL.md")).unwrap(),
                        "{}: {skill}",
                        e.agent
                    );
                }
                assert_eq!(st["skills_dir"], dir.to_str().unwrap());
            }
        }

        // Disconnected: the copies and the entry go, the owner's files stay.
        let st = m.json(&["watch", e.agent, "--remove", "--yes"]);
        assert_eq!(st["connected"], false, "{}: {st}", e.agent);
        if let Some(dir) = e.copies {
            let dir = m.agents.join(dir);
            assert!(!dir.join("use-pnpm").exists(), "{}", e.agent);
            assert!(!dir.join("peerharness-notes").exists(), "{}", e.agent);
        }
        if e.agent != "deepseek" && e.agent != "goose" {
            assert_eq!(registered_command(&e, &tools), None, "{}", e.agent);
            assert!(tools.exists(), "{}: the file itself stays", e.agent);
        }
        // Claude Code keeps its own.
        assert!(m.skills.join("use-pnpm/SKILL.md").is_file());
    }
}

/// Kilo reads the first of its five file names that exists, and the entry goes there:
/// a `kilo.json` of the owner's keeps its keys, and no `kilo.jsonc` appears beside it.
#[test]
fn kilo_gets_the_entry_in_the_file_it_reads() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    let dir = m.agents.join(".config/kilo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("kilo.json"), "{\"model\": \"mine\"}\n").unwrap();
    let out = m.setup(&["--agent", "kilo"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!dir.join("kilo.jsonc").exists());
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("kilo.json")).unwrap()).unwrap();
    assert_eq!(v["model"], "mine");
    assert_eq!(v["mcp"]["peerharness"]["type"], "local");
    assert_eq!(v["mcp"]["peerharness"]["command"][0], exe().as_str());
}
