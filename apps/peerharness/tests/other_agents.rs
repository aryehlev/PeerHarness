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
                assert!(!m.agents.join(".agents/skills").exists(), "{}", e.agent);
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

/// What one agent's hooks are expected to be (ADR-053): the file, where the command of
/// the prompt hook stands in it, where that of the hook at the end of a turn stands
/// (`None`: the agent gets none), and a prompt as the agent hands it over.
struct Hooked {
    agent: &'static str,
    detect: &'static str,
    file: &'static str,
    prompt_at: &'static str,
    stop_at: Option<&'static str>,
    payload: fn(&str) -> Value,
}

fn claude_shaped(prompt: &str) -> Value {
    serde_json::json!({"session_id": "s", "cwd": "/work/repo", "transcript_path": "/nowhere",
        "hook_event_name": "UserPromptSubmit", "prompt": prompt})
}

const HOOKED: [Hooked; 7] = [
    Hooked {
        agent: "codex",
        detect: ".codex",
        file: ".codex/hooks.json",
        prompt_at: "/hooks/UserPromptSubmit/0/hooks/0/command",
        stop_at: Some("/hooks/Stop/0/hooks/0/command"),
        payload: claude_shaped,
    },
    Hooked {
        agent: "droid",
        detect: ".factory",
        file: ".factory/hooks.json",
        prompt_at: "/UserPromptSubmit/0/hooks/0/command",
        stop_at: Some("/Stop/0/hooks/0/command"),
        payload: claude_shaped,
    },
    Hooked {
        agent: "gemini",
        detect: ".gemini/settings.json",
        file: ".gemini/settings.json",
        prompt_at: "/hooks/BeforeAgent/0/hooks/0/command",
        stop_at: Some("/hooks/AfterAgent/0/hooks/0/command"),
        payload: |p| {
            serde_json::json!({"session_id": "s", "cwd": "/work/repo",
            "hook_event_name": "BeforeAgent", "timestamp": "2026-11-13T00:00:00Z", "prompt": p})
        },
    },
    Hooked {
        agent: "qwen",
        detect: ".qwen",
        file: ".qwen/settings.json",
        prompt_at: "/hooks/UserPromptSubmit/0/hooks/0/command",
        stop_at: Some("/hooks/Stop/0/hooks/0/command"),
        payload: |p| {
            serde_json::json!({"session_id": "s", "cwd": "/work/repo",
            "hook_event_name": "UserPromptSubmit", "prompt": p, "submitted_prompt": p})
        },
    },
    Hooked {
        agent: "cursor",
        detect: ".cursor",
        file: ".cursor/hooks.json",
        prompt_at: "/hooks/beforeSubmitPrompt/0/command",
        stop_at: None,
        payload: |p| {
            serde_json::json!({"conversation_id": "c", "generation_id": "g",
            "hook_event_name": "beforeSubmitPrompt", "workspace_roots": ["/work/repo"],
            "transcript_path": null, "prompt": p, "attachments": []})
        },
    },
    Hooked {
        agent: "copilot",
        detect: ".copilot",
        file: ".copilot/hooks/peerharness.json",
        prompt_at: "/hooks/userPromptSubmitted/0/bash",
        stop_at: None,
        payload: |p| serde_json::json!({"sessionId": "s", "timestamp": 1, "cwd": "/work/repo", "prompt": p}),
    },
    Hooked {
        agent: "goose",
        detect: ".config/goose",
        file: ".agents/plugins/peerharness/hooks/hooks.json",
        prompt_at: "/hooks/UserPromptSubmit/0/hooks/0/command",
        stop_at: None,
        payload: |p| {
            serde_json::json!({"event": "UserPromptSubmit", "session_id": "s",
            "matcher_context": p, "message": p, "working_dir": "/work/repo"})
        },
    },
];

/// Runs a hook's command line as the agent's shell would, with `payload` on standard
/// input, inside that agent's session.
fn run_hook(m: &Machine, line: &str, payload: &Value) -> Output {
    use std::io::Write;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(line)
        .env("HOME", &m.fake_home)
        .env("PEERHARNESS_AGENTS_HOME", &m.agents)
        .env("PEERHARNESS_AGENT_SESSION", "1")
        .env_remove("PEERHARNESS_HOME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// The agents that run command hooks from a file get the hook that notices a
/// correction, and the notice at the end of a turn only where the agent shows it to
/// the person alone. The hook prints nothing for a prompt, and `--remove` takes the
/// hooks out again.
#[test]
fn the_agents_with_hooks_get_them_and_a_correction_typed_there_is_noticed() {
    for h in HOOKED {
        let tmp = TempDir::new().unwrap();
        let m = Machine::new(tmp.path());
        let found = m.agents.join(h.detect);
        if found.extension().is_some() {
            std::fs::create_dir_all(found.parent().unwrap()).unwrap();
            std::fs::write(&found, "{\"theme\": \"mine\"}\n").unwrap();
        } else {
            std::fs::create_dir_all(&found).unwrap();
        }
        let out = m.setup(&["--agent", h.agent]);
        let said = flat(&text(&out));
        assert!(out.status.success(), "{}: {said}", h.agent);
        // The preview said what is stored, before anything was written.
        assert!(
            said.contains("keeps a redacted copy of each prompt you type in"),
            "{}: {said}",
            h.agent
        );
        assert!(said.contains("which is not encrypted"), "{}", h.agent);
        assert_eq!(
            said.contains("shows to you and not to its model"),
            h.stop_at.is_some(),
            "{}: {said}",
            h.agent
        );
        let file = m.agents.join(h.file);
        let st = m.json(&["watch", h.agent, "--status"]);
        assert_eq!(st["hooks"], "installed", "{}: {st}", h.agent);
        assert_eq!(st["hooks_file"], file.to_str().unwrap(), "{}", h.agent);

        let doc = read_json(&file);
        let prompt_line = doc.pointer(h.prompt_at).and_then(Value::as_str).unwrap();
        assert!(
            prompt_line.ends_with(&format!("hook user-prompt-submit {}", h.agent)),
            "{}: {prompt_line}",
            h.agent
        );
        assert!(prompt_line.contains(&exe()), "{}", h.agent);
        // No hook at the end of a turn where its output would not reach the person alone.
        let stop_line = h
            .stop_at
            .map(|at| doc.pointer(at).and_then(Value::as_str).unwrap().to_owned());
        if h.stop_at.is_none() {
            assert!(!std::fs::read_to_string(&file)
                .unwrap()
                .contains("hook stop"));
        }

        // The same correction twice, as this agent hands a prompt over: the hook says
        // nothing, on either stream, and exits 0.
        for _ in 0..2 {
            let out = run_hook(&m, prompt_line, &(h.payload)("No, use pnpm, not npm"));
            assert!(out.status.success(), "{}", h.agent);
            assert!(
                out.stdout.is_empty() && out.stderr.is_empty(),
                "{}: {}",
                h.agent,
                text(&out)
            );
        }
        let status = m.json(&["status"]);
        assert_eq!(status["observations"], 2, "{}: {status}", h.agent);
        assert_eq!(status["candidates"]["detected"], 1, "{}: {status}", h.agent);

        match &stop_line {
            Some(line) => {
                // A count, in the message the agent shows to the person.
                let out = run_hook(
                    &m,
                    line,
                    &serde_json::json!({"session_id": "s", "cwd": "/work/repo"}),
                );
                assert!(out.status.success() && out.stderr.is_empty(), "{}", h.agent);
                let v: Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(v.as_object().unwrap().len(), 1, "{}: {v}", h.agent);
                assert!(
                    v["systemMessage"]
                        .as_str()
                        .unwrap()
                        .contains("1 possible convention to review"),
                    "{}: {v}",
                    h.agent
                );
                assert!(!v.to_string().contains("pnpm"), "{}: {v}", h.agent);
            }
            None => {
                // Even run by hand, the hook prints nothing there for this agent.
                let line = prompt_line.replace("hook user-prompt-submit", "hook stop");
                let out = run_hook(&m, &line, &serde_json::json!({"session_id": "s"}));
                assert!(out.status.success(), "{}", h.agent);
                assert!(
                    out.stdout.is_empty() && out.stderr.is_empty(),
                    "{}",
                    h.agent
                );
            }
        }

        // Connecting again changes nothing.
        let again = m.json(&["watch", h.agent, "--install", "--yes"]);
        assert_eq!(again["changed"], false, "{}: {again}", h.agent);

        // Disconnected: the hooks go, and what was the owner's stays.
        let st = m.json(&["watch", h.agent, "--remove", "--yes"]);
        assert_eq!(st["hooks"], "not_installed", "{}: {st}", h.agent);
        if matches!(h.agent, "gemini" | "qwen") {
            // Its settings file: the hooks member PeerHarness added is gone.
            let left = read_json(&file);
            assert_eq!(left.get("hooks"), None, "{}: {left}", h.agent);
            if h.file == h.detect {
                assert_eq!(left["theme"], "mine", "{}", h.agent);
            }
        } else {
            // A file that held nothing but PeerHarness's hooks.
            assert!(!file.exists(), "{}", h.agent);
        }
        if h.agent == "goose" {
            assert!(!m.agents.join(".agents/plugins/peerharness").exists());
        }
    }
}

/// The owner can leave the hooks out, and an agent connected without them gets them
/// only after a preview of their own. The owner's own hooks keep their place.
#[test]
fn hooks_are_left_out_on_request_and_added_later_only_after_their_own_preview() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    std::fs::create_dir_all(m.agents.join(".codex")).unwrap();
    let hooks = m.agents.join(".codex/hooks.json");
    let mine = serde_json::json!({"hooks": {"Stop": [
        {"hooks": [{"type": "command", "command": "say done"}]}
    ]}});
    std::fs::write(&hooks, mine.to_string()).unwrap();

    let out = m.setup(&["--agent", "codex", "--no-agent-hooks"]);
    let said = flat(&text(&out));
    assert!(out.status.success(), "{said}");
    assert!(!said.contains("redacted copy"), "{said}");
    assert_eq!(read_json(&hooks), mine);
    let st = m.json(&["watch", "codex", "--status"]);
    assert_eq!(
        (&st["connected"], &st["hooks"]),
        (&Value::Bool(true), &Value::from("not_installed"))
    );

    // Later, and without the flag: a preview about the hooks alone.
    let out = m
        .cmd(&["watch", "codex", "--install", "--yes"])
        .output()
        .unwrap();
    let said = flat(&text(&out));
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("Codex is connected to PeerHarness already"),
        "{said}"
    );
    assert!(
        said.contains("keeps a redacted copy of each prompt you type in Codex"),
        "{said}"
    );
    assert!(said.contains("only after you trusted it"), "{said}");
    assert!(!said.contains("Tools: this adds"), "{said}");
    let now = read_json(&hooks);
    // Theirs is still the first under its event: Codex ties trust to the position.
    assert_eq!(now["hooks"]["Stop"][0], mine["hooks"]["Stop"][0]);
    assert!(now["hooks"]["Stop"][1]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .ends_with("hook stop codex"));
    // A backup of the owner's file was made.
    let backups: Vec<_> = std::fs::read_dir(m.home.join("backups"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with("hooks.json"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(backups[0].path()).unwrap()).unwrap(),
        mine
    );

    // `--no-hooks` takes them out again and leaves Codex connected.
    let out = m
        .cmd(&["watch", "codex", "--install", "--no-hooks", "--yes"])
        .output()
        .unwrap();
    let said = flat(&text(&out));
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("no copy of what you type in Codex is kept any more"),
        "{said}"
    );
    assert_eq!(read_json(&hooks), mine);
    let st = m.json(&["watch", "codex", "--status"]);
    assert_eq!(st["connected"], true);
    assert_eq!(st["tools"], "registered");
    assert_eq!(st["hooks"], "not_installed");

    m.json(&["watch", "codex", "--install", "--yes"]);
    m.json(&["watch", "codex", "--remove", "--yes"]);
    assert_eq!(read_json(&hooks), mine);
}

/// A hooks file PeerHarness cannot edit safely is left as it is and the entries are
/// shown; Droid's `hooks.json` is not created while its settings hold hooks, which
/// Droid would stop reading.
#[test]
fn a_hooks_file_that_cannot_be_edited_safely_is_left_and_the_entries_shown() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    std::fs::create_dir_all(m.agents.join(".cursor")).unwrap();
    let commented = "{\n  // mine\n  \"version\": 1,\n  \"hooks\": {}\n}\n";
    std::fs::write(m.agents.join(".cursor/hooks.json"), commented).unwrap();
    std::fs::create_dir_all(m.agents.join(".factory")).unwrap();
    let settings =
        "{\"hooks\": {\"Stop\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"mine\"}]}]}}";
    std::fs::write(m.agents.join(".factory/settings.json"), settings).unwrap();

    let out = m.setup(&[]);
    let said = flat(&text(&out));
    assert!(out.status.success(), "{said}");
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".cursor/hooks.json")).unwrap(),
        commented
    );
    assert!(said.contains("hook user-prompt-submit cursor"), "{said}");
    assert_eq!(
        m.json(&["watch", "cursor", "--status"])["hooks"],
        "file_not_editable"
    );

    assert!(!m.agents.join(".factory/hooks.json").exists());
    assert_eq!(
        std::fs::read_to_string(m.agents.join(".factory/settings.json")).unwrap(),
        settings
    );
    assert!(
        said.contains("creating that file would turn yours off"),
        "{said}"
    );
    assert!(said.contains("hook stop droid"), "{said}");
    assert_eq!(
        m.json(&["watch", "droid", "--status"])["hooks"],
        "file_not_editable"
    );
}

/// A hook that names an agent this build gives no hooks to, or no agent at all that
/// it knows, reads nothing and stores nothing. Qwen Code's prompt event also fires
/// when tool results go back to the model: only what the person submitted is kept.
#[test]
fn a_hook_stores_only_what_the_person_typed_in_an_agent_that_has_hooks() {
    let tmp = TempDir::new().unwrap();
    let m = Machine::new(tmp.path());
    assert!(m.setup(&[]).status.success());
    let hook = |agent: &str, payload: Value| {
        let line = format!(
            "PEERHARNESS_HOME='{}' '{}' hook user-prompt-submit {agent}",
            m.home.display(),
            exe()
        );
        let out = run_hook(&m, &line, &payload);
        assert!(out.status.success(), "{agent}");
        assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{agent}");
    };
    for agent in ["crush", "antigravity", "opencode", "nosuch", "Codex"] {
        hook(agent, claude_shaped("No, use pnpm, not npm"));
    }
    hook(
        "qwen",
        serde_json::json!({"session_id": "s", "cwd": "/w", "prompt": "tool output"}),
    );
    assert_eq!(m.json(&["status"])["observations"], 0);
    hook(
        "qwen",
        serde_json::json!({"session_id": "s", "cwd": "/w", "prompt": "x", "submitted_prompt": "No, use pnpm, not npm"}),
    );
    assert_eq!(m.json(&["status"])["observations"], 1);
}
