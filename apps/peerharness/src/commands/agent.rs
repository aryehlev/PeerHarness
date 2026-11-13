//! `watch <agent> --install | --remove | --status` for the coding agents besides
//! Claude Code (ADR-050, ADR-052): the agents of [`crate::agents::Agent`].
//!
//! Connecting an agent is the owner's choice, in their own terminal: it is refused
//! inside an agent's session as a whole, like `setup`, and every change is shown before
//! it is made. It does two things, both undone by `--remove`:
//!
//! * the agent is added to `[agents] connected` in the settings, and from then on the
//!   directory it reads skills from holds copies of what PeerHarness manages in Claude
//!   Code's (`crate::copies`);
//! * `peerharness mcp` is registered in its configuration file, with a backup, when
//!   PeerHarness can edit that file safely. An entry of that name that PeerHarness did
//!   not write is left alone, and a file that does not parse is not changed: the entry
//!   is shown for the owner to add.
//!
//! For an agent that runs command hooks from a file (`Agent::hook_spec`, ADR-053) it
//! also adds the hook that keeps a redacted copy of each prompt, and, where the agent
//! shows a hook's message to the person alone, the one that prints the notice at the
//! end of a turn. The preview says what is stored; `--no-hooks` leaves them out, and an
//! agent that was connected before gets them only after a preview of their own.
//!
//! What the agent may start through those tools is what the owner allowed for every
//! agent (`config::Asked`, `peerharness setup`): connecting one allows nothing more.

use anyhow::Result;
use ph_observer::agent_config::{self, AgentConfigError, Entry};
use ph_observer::agent_hooks::{self, Ours, Place};
use ph_observer::{HookCommand, HookEvent};
use serde_json::{json, Value};

use super::Ctx;
use crate::agents::{self, Agent, Paths, ToolsFile, SERVER_NAME};
use crate::cli::WatchOtherArgs;
use crate::config::Config;
use crate::consent::{confirm, human_only};
use crate::output::{Report, Text};

pub fn run(ctx: &Ctx, agent: Agent, a: &WatchOtherArgs) -> Result<Report> {
    if a.install {
        install(ctx, agent, a.yes, a.no_hooks)
    } else if a.remove {
        remove(ctx, agent, a.yes)
    } else {
        status(ctx, agent)
    }
}

/// Where the tools stand in the agent's configuration.
#[derive(Debug)]
enum Tools {
    /// No entry: one can be added.
    Absent,
    /// Exactly the entry PeerHarness writes for this binary and home.
    Same,
    /// An entry of that name that PeerHarness did not write.
    Other,
    /// The file cannot be edited safely (it does not parse, say): the reason.
    Unreadable(String),
    /// The agent's file is one PeerHarness does not edit.
    Manual,
}

impl Tools {
    const fn code(&self) -> &'static str {
        match self {
            Tools::Absent => "not_registered",
            Tools::Same => "registered",
            Tools::Other => "other_entry",
            Tools::Unreadable(_) => "file_not_editable",
            Tools::Manual => "manual",
        }
    }
}

/// Where PeerHarness's hooks stand in the agent's hooks file.
#[derive(Debug)]
enum Hooks {
    /// The agent gets none (`Agent::hook_spec`).
    None,
    /// None of ours is there.
    Absent,
    /// Exactly the ones this binary and home would write.
    Installed,
    /// Ours, but for another path of the binary or another set of events.
    Outdated,
    /// The file cannot be edited safely: the reason.
    Unreadable(String),
    /// Creating the file would make the agent stop reading the hooks in this one.
    Shadowed(std::path::PathBuf),
}

impl Hooks {
    const fn code(&self) -> &'static str {
        match self {
            Hooks::None => "none",
            Hooks::Absent => "not_installed",
            Hooks::Installed => "installed",
            Hooks::Outdated => "outdated",
            Hooks::Unreadable(_) | Hooks::Shadowed(_) => "file_not_editable",
        }
    }

    /// Whether `--install` has something to write.
    const fn wanted(&self) -> bool {
        matches!(self, Hooks::Absent | Hooks::Outdated)
    }
}

/// The hooks PeerHarness writes for one agent on this machine.
struct HookPlan {
    spec: agents::HookSpec,
    file: std::path::PathBuf,
    first: Vec<(&'static str, Value)>,
    /// Event name, entry and command, the prompt's first.
    entries: Vec<(&'static str, Value, String)>,
    home: Option<String>,
}

impl HookPlan {
    fn new(agent: Agent, paths: &Paths, cmd: &HookCommand) -> Option<Self> {
        let spec = agent.hook_spec()?;
        let file = paths.hooks.clone()?;
        let mut entries = Vec::new();
        for (name, event) in [
            (Some(spec.prompt_event), HookEvent::UserPromptSubmit),
            (spec.stop_event, HookEvent::Stop),
        ] {
            let Some(name) = name else { continue };
            let command = cmd.render_for(event, agent.id())?;
            entries.push((name, agent.hook_entry(&command)?, command));
        }
        Some(Self {
            spec,
            file,
            first: if spec.version {
                vec![("version", json!(1))]
            } else {
                Vec::new()
            },
            entries,
            home: cmd.home().map(str::to_owned),
        })
    }

    fn place(&self) -> Place<'_> {
        Place {
            path: &self.file,
            at: self.spec.at,
            first: &self.first,
            own_dirs: self.spec.own_dirs,
        }
    }

    fn ours(&self, agent: Agent) -> Ours<'_> {
        Ours {
            home: self.home.as_deref(),
            agent: agent.id(),
        }
    }

    fn want(&self) -> Vec<(&str, Value)> {
        self.entries
            .iter()
            .map(|(name, entry, _)| (*name, entry.clone()))
            .collect()
    }

    /// The entries as the owner would add them by hand.
    fn text(&self) -> String {
        let mut events = serde_json::Map::new();
        for (name, entry, _) in &self.entries {
            events.insert((*name).to_owned(), json!([entry]));
        }
        let mut v = Value::Object(events);
        for key in self.spec.at.iter().rev() {
            v = json!({ *key: v });
        }
        serde_json::to_string_pretty(&v).unwrap_or_default()
    }
}

fn hooks_state(agent: Agent, paths: &Paths, plan: Option<&HookPlan>) -> Hooks {
    let Some(plan) = plan else {
        return Hooks::None;
    };
    match agent_hooks::hooks(&plan.place(), plan.ours(agent), &plan.want()) {
        Ok(agent_hooks::Hooks::Installed) => Hooks::Installed,
        Ok(agent_hooks::Hooks::Outdated) => Hooks::Outdated,
        Ok(agent_hooks::Hooks::Absent) => match &paths.hooks_shadow {
            // The agent reads the hooks of the other file only while this one does not
            // exist. Whatever the other file holds that cannot be read counts as hooks.
            Some(other) if !plan.file.exists() && holds_hooks(other) => {
                Hooks::Shadowed(other.clone())
            }
            _ => Hooks::Absent,
        },
        Err(e) => Hooks::Unreadable(not_editable(&e)),
    }
}

/// Whether the JSON file at `path` has a `hooks` member, or cannot be read as JSON.
fn holds_hooks(path: &std::path::Path) -> bool {
    match std::fs::read(path) {
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        Ok(bytes) => {
            serde_json::from_slice::<Value>(&bytes).map_or(true, |v| v.get("hooks").is_some())
        }
    }
}

/// What `install` says about the hooks, before it asks.
fn hooks_preview(agent: Agent, plan: &HookPlan, hooks: &Hooks, days: u32) -> Option<String> {
    let file = plan.file.display();
    let name = agent.name();
    Some(match hooks {
        Hooks::None | Hooks::Installed => return None,
        Hooks::Absent | Hooks::Outdated => {
            let mut s = format!(
                "Hooks: this {} {file} (a backup of an existing file is made first; your own \
                 hooks are kept):",
                if matches!(hooks, Hooks::Outdated) {
                    "brings PeerHarness's hooks up to date in"
                } else if plan.entries.len() == 1 {
                    "adds one hook to"
                } else {
                    "adds two hooks to"
                }
            );
            for (event, _, command) in &plan.entries {
                s.push_str(&format!("\n  {event:<19} {command}"));
            }
            s.push_str(&format!(
                "\n{} keeps a redacted copy of each prompt you type in {name}, so that \
                 a correction can be noticed. The copies stay on this machine, for {days} \
                 days, in PeerHarness's database, which is not encrypted. Nothing is sent \
                 anywhere.",
                if plan.entries.len() == 1 {
                    "It"
                } else {
                    "The first"
                }
            ));
            s.push_str(&if plan.spec.stop_event.is_some() {
                format!(
                    " The second prints, at the end of a turn and at most twice a day, how \
                     many proposals and notes wait for you: a count, which {name} shows to \
                     you and not to its model."
                )
            } else {
                format!(
                    " {name} has no way to show you a line at the end of a turn without its \
                     model reading it, so there is no notice there: look with `peerharness \
                     inbox`."
                )
            });
            if let Some(note) = plan.spec.note {
                s.push(' ');
                s.push_str(note);
            }
            s.push_str(" Leave the hooks out with --no-hooks.");
            s
        }
        Hooks::Unreadable(why) => format!(
            "Hooks: {file} is not changed: {why}. To let PeerHarness notice your corrections \
             in {name}, add this yourself:\n{}",
            indented(&plan.text())
        ),
        Hooks::Shadowed(other) => format!(
            "Hooks: none are added. {name} reads the hooks in {} only while {file} does not \
             exist, so creating that file would turn yours off. To let PeerHarness notice \
             your corrections in {name}, add this to your hooks there:\n{}",
            other.display(),
            indented(&plan.text())
        ),
    })
}

fn locate(agent: Agent) -> Result<Paths> {
    agent.paths().ok_or_else(|| {
        crate::error::usage(format!(
            "cannot find {}'s files: this build looks for them only under {} \
             (debug builds never look in your own home directory)",
            agent.name(),
            agents::AGENTS_HOME_ENV
        ))
    })
}

fn not_editable(e: &AgentConfigError) -> String {
    e.to_string()
}

/// The entry PeerHarness writes, for showing, and what the file holds.
fn tools_state(agent: Agent, paths: &Paths, server: &[String]) -> Tools {
    let state = match &paths.tools {
        ToolsFile::Manual(_) => return Tools::Manual,
        ToolsFile::Toml(file) => agent_config::toml_entry(file, &Agent::toml_server(server)),
        ToolsFile::Json { file, at } => {
            agent_config::json_entry(file, at, SERVER_NAME, &agent.json_entry(server, at))
        }
    };
    match state {
        Ok(Entry::Absent) => Tools::Absent,
        Ok(Entry::Same) => Tools::Same,
        Ok(Entry::Other) => Tools::Other,
        Err(e) => Tools::Unreadable(not_editable(&e)),
    }
}

/// The entry as the owner would add it by hand.
fn entry_text(agent: Agent, paths: &Paths, server: &[String]) -> String {
    match &paths.tools {
        ToolsFile::Manual(_) => agent.manual_entry(server),
        ToolsFile::Toml(_) => Agent::toml_server(server)
            .block()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
        ToolsFile::Json { at, .. } => {
            let mut v = json!({ SERVER_NAME: agent.json_entry(server, at) });
            for key in at.iter().rev() {
                v = json!({ *key: v });
            }
            serde_json::to_string_pretty(&v).unwrap_or_default()
        }
    }
}

fn indented(text: &str) -> String {
    text.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The line about the rules.
fn rules_line(agent: Agent, paths: &Paths) -> Result<String> {
    let source = crate::governance::user_installer()?;
    let source = source.target_root().display();
    Ok(match &paths.skills {
        None => format!(
            "Rules: {} already reads Claude Code's skills ({source}), where PeerHarness installs \
             them. Nothing is copied.",
            agent.name()
        ),
        Some(dir) => format!(
            "Rules: what PeerHarness manages in {source} (the rules installed for your agent, \
             and PeerHarness's own skill) is copied to {}, where {} reads skills, and kept the \
             same after every PeerHarness command. In a project where rules are installed, \
             they are copied to its .agents/skills too. A skill there that PeerHarness did not \
             put there is never touched.",
            dir.display(),
            agent.name()
        ),
    })
}

/// The line about recognizing the agent's sessions.
fn session_line(agent: Agent) -> String {
    if agent.marks_its_commands() {
        format!(
            "{} marks the commands it runs ({}). There, as in Claude Code, PeerHarness refuses \
             every decision, or asks you in a window if you allowed that.",
            agent.name(),
            agent.session_env().join(", ")
        )
    } else {
        format!(
            "{} is not known to mark every command its agent runs. PeerHarness looks for {}; \
             where it is missing, a command its agent runs looks like one you typed. Its tools \
             are marked as an agent's in every case, and PeerHarness's skill tells it never to \
             skip a confirmation.",
            agent.name(),
            agent.session_env().join(", ")
        )
    }
}

/// What `install` adds about the tools, before it asks.
fn tools_preview(
    agent: Agent,
    paths: &Paths,
    tools: &Tools,
    server: &[String],
    line: &str,
) -> String {
    let file = paths.tools.path().display();
    match tools {
        Tools::Absent => {
            format!(
            "Tools: this adds a server named {SERVER_NAME} to {file} (a backup is made first), \
             which runs:\n   {line}\n{} then starts it in each session. The tools start steps \
             for you; they never decide.{}",
            agent.name(),
            agent.tools_note().map(|n| format!(" {n}")).unwrap_or_default()
        )
        }
        Tools::Same => format!("Tools: already registered in {file}."),
        Tools::Other => format!(
            "Tools: {file} already has a server named {SERVER_NAME} that PeerHarness did not \
             write. It is left as it is."
        ),
        Tools::Unreadable(why) => format!(
            "Tools: {file} is not changed: {why}. To give {} the tools, add this yourself:\n{}",
            agent.name(),
            indented(&entry_text(agent, paths, server))
        ),
        Tools::Manual => format!(
            "Tools: PeerHarness does not edit {}'s configuration. To give it the tools, merge \
             this into {file}:\n{}",
            agent.name(),
            indented(&entry_text(agent, paths, server))
        ),
    }
}

fn install(ctx: &Ctx, agent: Agent, yes: bool, no_hooks: bool) -> Result<Report> {
    let what = format!("connecting {}", agent.name());
    human_only(&what)?;
    if !ctx.home.is_initialized() {
        return Err(crate::error::usage(
            "this home is not initialized: run `peerharness setup` first",
        ));
    }
    let paths = locate(agent)?;
    let mut config = Config::load(&ctx.home)?;
    let server_os = super::setup::server_command(ctx)?;
    let server = agents::utf8_command(&server_os)?;
    let line = super::setup::shell_words(&server_os)
        .trim_start()
        .to_owned();
    let tools = tools_state(agent, &paths, &server);
    let connected = config.agents.has(agent);
    let plan = HookPlan::new(agent, &paths, &super::hook_command(&ctx.home)?);
    let hooks = hooks_state(agent, &paths, plan.as_ref());
    let want_hooks = !no_hooks && hooks.wanted();
    // `--no-hooks` also takes out the ones that are there.
    let drop_hooks = no_hooks && matches!(hooks, Hooks::Installed | Hooks::Outdated);

    if connected && !matches!(tools, Tools::Absent) && !want_hooks && !drop_hooks {
        return Ok(done(
            ctx,
            agent,
            &paths,
            "install",
            false,
            &tools,
            &hooks,
            None,
            "Already connected; nothing changed.",
        ));
    }

    let mut preview = Text::new();
    preview.line(if connected {
        format!(
            "{} is connected to PeerHarness already. This adds to it.",
            agent.name()
        )
    } else {
        format!("This connects {} to PeerHarness.", agent.name())
    });
    if !connected {
        preview.line(rules_line(agent, &paths)?);
    }
    if !connected || matches!(tools, Tools::Absent) {
        preview.line(tools_preview(agent, &paths, &tools, &server, &line));
    }
    // A file that cannot be edited is said once, when the agent is connected.
    let days = config.retention.observation_days.clamp(1, 3650);
    let hooks_text = match (&plan, no_hooks) {
        (Some(plan), false) if want_hooks || !connected => hooks_preview(agent, plan, &hooks, days),
        _ => None,
    };
    if let Some(text) = &hooks_text {
        preview.line(text);
    }
    if let (Some(plan), true) = (&plan, drop_hooks) {
        preview.line(format!(
            "Hooks: the ones PeerHarness wrote are removed from {} (a backup is made first), \
             so no copy of what you type in {} is kept any more. The copies it already keeps \
             go when their days are over.",
            plan.file.display(),
            agent.name()
        ));
    }
    if !connected {
        preview.line(session_line(agent));
        preview.line(
            "What your agent may start is what you allowed for every agent (`peerharness \
             setup`); connecting this one allows nothing more.",
        );
        preview.line(format!(
            "Disconnect it with `peerharness watch {} --remove`.",
            agent.id()
        ));
    }
    confirm(&ctx.out, &preview.finish(), yes, &what)?;

    // The setting first: copies follow from it.
    if config.agents.connect(agent) {
        config.save(&ctx.home)?;
    }
    let mut backup = None;
    let tools = if matches!(tools, Tools::Absent) {
        let edit = match &paths.tools {
            ToolsFile::Toml(file) => agent_config::add_toml_entry(
                file,
                &Agent::toml_server(&server),
                &ctx.home.backups_dir(),
            ),
            ToolsFile::Json { file, at } => {
                let first: Vec<(&str, Value)> = match agent {
                    Agent::Opencode => vec![("$schema", json!("https://opencode.ai/config.json"))],
                    Agent::Crush => vec![("$schema", json!("https://charm.land/crush.json"))],
                    Agent::Kilo => vec![("$schema", json!("https://app.kilo.ai/config.json"))],
                    _ => Vec::new(),
                };
                agent_config::add_json_entry(
                    file,
                    at,
                    SERVER_NAME,
                    &agent.json_entry(&server, at),
                    &first,
                    &ctx.home.backups_dir(),
                )
            }
            ToolsFile::Manual(_) => Ok(agent_config::Edit::default()),
        };
        match edit {
            Ok(e) => {
                backup = e.backup_path;
                tools_state(agent, &paths, &server)
            }
            Err(e) => Tools::Unreadable(not_editable(&e)),
        }
    } else {
        tools
    };
    let mut hooks_backup = None;
    let hooks = match (&plan, want_hooks) {
        (Some(plan), true) => {
            match agent_hooks::add_hooks(
                &plan.place(),
                plan.ours(agent),
                &plan.want(),
                &ctx.home.backups_dir(),
            ) {
                Ok(e) => {
                    hooks_backup = e.backup_path;
                    hooks_state(agent, &paths, Some(plan))
                }
                Err(e) => Hooks::Unreadable(not_editable(&e)),
            }
        }
        (Some(plan), false) if drop_hooks => {
            hooks_backup =
                agent_hooks::remove_hooks(&plan.place(), plan.ours(agent), &ctx.home.backups_dir())
                    .map_err(|e| anyhow::anyhow!("{e}"))
                    .map_err(|e| e.context(format!("cannot update {}", plan.file.display())))?
                    .backup_path;
            hooks_state(agent, &paths, Some(plan))
        }
        _ => hooks,
    };
    let node = ctx.open_node()?;
    crate::copies::sync(&config, Some(&node.store));
    let mut r = done(
        ctx,
        agent,
        &paths,
        "install",
        true,
        &tools,
        &hooks,
        backup.as_deref(),
        if connected {
            "Brought up to date."
        } else {
            "Connected."
        },
    );
    if let Some(b) = &hooks_backup {
        r.json["hooks_backup"] = json!(b);
        r.text
            .push_str(&format!("\n  hooks backup: {}", b.display()));
    }
    if let Tools::Unreadable(_) = tools {
        r.text.push_str(&format!(
            "\n{}",
            tools_preview(agent, &paths, &tools, &server, &line)
        ));
    }
    if let (Some(plan), false, Hooks::Unreadable(_) | Hooks::Shadowed(_)) =
        (&plan, no_hooks, &hooks)
    {
        if let Some(text) = hooks_preview(agent, plan, &hooks, days) {
            r.text.push_str(&format!("\n{text}"));
        }
    }
    Ok(r)
}

fn remove(ctx: &Ctx, agent: Agent, yes: bool) -> Result<Report> {
    let what = format!("disconnecting {}", agent.name());
    human_only(&what)?;
    if !ctx.home.is_initialized() {
        return Err(crate::error::usage(
            "this home is not initialized: there is nothing to disconnect",
        ));
    }
    let paths = locate(agent)?;
    let mut config = Config::load(&ctx.home)?;
    let server = agents::utf8_command(&super::setup::server_command(ctx)?)?;
    let tools = tools_state(agent, &paths, &server);
    let connected = config.agents.has(agent);
    let ours = matches!(tools, Tools::Same);
    let plan = HookPlan::new(agent, &paths, &super::hook_command(&ctx.home)?);
    let hooks = hooks_state(agent, &paths, plan.as_ref());
    let our_hooks = matches!(hooks, Hooks::Installed | Hooks::Outdated);
    if !connected && !ours && !our_hooks {
        return Ok(done(
            ctx,
            agent,
            &paths,
            "remove",
            false,
            &tools,
            &hooks,
            None,
            "Not connected; nothing changed.",
        ));
    }
    // The copies stay where another connected agent reads the same directory.
    let others: Vec<Agent> = config
        .agents
        .connected
        .iter()
        .copied()
        .filter(|a| *a != agent)
        .collect();
    let shared_with: Vec<Agent> = others
        .iter()
        .copied()
        .filter(|a| a.paths().and_then(|p| p.skills) == paths.skills && paths.skills.is_some())
        .collect();
    let mut preview = Text::new();
    preview.line(format!(
        "This disconnects {} from PeerHarness.",
        agent.name()
    ));
    if let Some(dir) = &paths.skills {
        if shared_with.is_empty() {
            preview.line(format!(
                "Rules: the copies PeerHarness made in {} are removed. A copy you edited, and \
                 every skill PeerHarness did not put there, stay.",
                dir.display()
            ));
        } else {
            preview.line(format!(
                "Rules: the copies in {} stay, because {} reads them too.",
                dir.display(),
                agents::names(&shared_with)
            ));
        }
    }
    if ours {
        preview.line(format!(
            "Tools: the server {SERVER_NAME} that PeerHarness wrote is removed from {} (a backup \
             is made first).",
            paths.tools.path().display()
        ));
    }
    if let (Some(plan), true) = (&plan, our_hooks) {
        preview.line(format!(
            "Hooks: the ones PeerHarness wrote are removed from {} (a backup is made first). \
             The copies of your prompts it already keeps go when their days are over.",
            plan.file.display()
        ));
    }
    confirm(&ctx.out, &preview.finish(), yes, &what)?;

    if config.agents.disconnect(agent) {
        config.save(&ctx.home)?;
    }
    let mut hooks_backup = None;
    if let (Some(plan), true) = (&plan, our_hooks) {
        hooks_backup =
            agent_hooks::remove_hooks(&plan.place(), plan.ours(agent), &ctx.home.backups_dir())
                .map_err(|e| anyhow::anyhow!("{e}"))
                .map_err(|e| e.context(format!("cannot update {}", plan.file.display())))?
                .backup_path;
    }
    let mut backup = None;
    if ours {
        let edit = match &paths.tools {
            ToolsFile::Toml(file) => agent_config::remove_toml_entry(
                file,
                &Agent::toml_server(&server),
                &ctx.home.backups_dir(),
            ),
            ToolsFile::Json { file, at } => agent_config::remove_json_entry(
                file,
                at,
                SERVER_NAME,
                &agent.json_entry(&server, at),
                &ctx.home.backups_dir(),
            ),
            ToolsFile::Manual(_) => Ok(agent_config::Edit::default()),
        };
        backup = edit
            .map_err(|e| anyhow::anyhow!("{e}"))
            .map_err(|e| e.context(format!("cannot update {}", paths.tools.path().display())))?
            .backup_path;
    }
    let mut left = Vec::new();
    let mut removed = 0;
    if let (Some(dir), true) = (&paths.skills, shared_with.is_empty()) {
        if let Ok(r) = ph_skills::remove_copies(&ph_skills::Installer::new(dir)) {
            removed += r.removed.len();
            left.extend(r.blocked.into_iter().map(|b| b.name));
        }
    }
    // A project's copies go once no connected agent reads that project's directory.
    let still_in_projects = others
        .iter()
        .any(|a| a.project_skills().is_some() && a.project_skills() == agent.project_skills());
    if agent.project_skills().is_some() && !still_in_projects {
        let node = ctx.open_node()?;
        let mut before = config.clone();
        before.agents.connect(agent);
        for d in crate::copies::dirs(&before, Some(&node.store)) {
            if d.project.is_none() {
                continue;
            }
            if let Ok(r) = ph_skills::remove_copies(&d.copy) {
                removed += r.removed.len();
                left.extend(r.blocked.into_iter().map(|b| b.name));
            }
        }
    }
    let tools = tools_state(agent, &paths, &server);
    let hooks = hooks_state(agent, &paths, plan.as_ref());
    let mut r = done(
        ctx,
        agent,
        &paths,
        "remove",
        true,
        &tools,
        &hooks,
        backup.as_deref(),
        "Disconnected.",
    );
    if let Some(b) = &hooks_backup {
        r.json["hooks_backup"] = json!(b);
        r.text
            .push_str(&format!("\n  hooks backup: {}", b.display()));
    }
    r.json["copies_removed"] = json!(removed);
    r.text.push_str(&format!("\n  copies removed: {removed}"));
    if !left.is_empty() {
        r.json["copies_left"] = json!(left);
        r.text.push_str(&format!(
            "\n  left in place because they were edited: {}",
            left.join(", ")
        ));
    }
    Ok(r)
}

fn status(ctx: &Ctx, agent: Agent) -> Result<Report> {
    let paths = locate(agent)?;
    let server = agents::utf8_command(&super::setup::server_command(ctx)?)?;
    let tools = tools_state(agent, &paths, &server);
    let plan = HookPlan::new(agent, &paths, &super::hook_command(&ctx.home)?);
    let hooks = hooks_state(agent, &paths, plan.as_ref());
    Ok(done(
        ctx,
        agent,
        &paths,
        "status",
        false,
        &tools,
        &hooks,
        None,
        agent.name(),
    ))
}

/// How many skills PeerHarness manages in `dir`.
fn copies_in(dir: &std::path::Path) -> usize {
    ph_skills::Installer::new(dir)
        .list()
        .map(|l| {
            l.iter()
                .filter(|(_, s)| matches!(s, ph_skills::InstallState::Managed { .. }))
                .count()
        })
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn done(
    ctx: &Ctx,
    agent: Agent,
    paths: &Paths,
    action: &str,
    changed: bool,
    tools: &Tools,
    hooks: &Hooks,
    backup: Option<&std::path::Path>,
    headline: &str,
) -> Report {
    let connected =
        ctx.home.is_initialized() && Config::load(&ctx.home).is_ok_and(|c| c.agents.has(agent));
    let copies = paths.skills.as_deref().map(copies_in);
    let json = json!({
        "agent": agent.id(),
        "action": action,
        "changed": changed,
        "connected": connected,
        "detected": agent.detected(),
        "skills_dir": paths.skills,
        "copies": copies,
        "tools": tools.code(),
        "tools_file": paths.tools.path(),
        "hooks": hooks.code(),
        "hooks_file": paths.hooks,
        "backup": backup,
        "session_env": agent.session_env(),
    });
    let mut t = Text::new();
    t.line(headline);
    t.kv("connected", if connected { "yes" } else { "no" });
    match (&paths.skills, copies) {
        (Some(dir), Some(n)) => t.kv("rules", format!("{n} copied to {}", dir.display())),
        _ => t.kv("rules", "read from Claude Code's skills"),
    };
    t.kv(
        "tools",
        match tools {
            Tools::Absent => "not registered".to_owned(),
            Tools::Same => format!("registered in {}", paths.tools.path().display()),
            Tools::Other => format!(
                "{} has a server named {SERVER_NAME} that PeerHarness did not write",
                paths.tools.path().display()
            ),
            Tools::Unreadable(why) => {
                format!("{} cannot be edited: {why}", paths.tools.path().display())
            }
            Tools::Manual => format!("added by you, in {}", paths.tools.path().display()),
        },
    );
    let hooks_file = paths
        .hooks
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    t.kv(
        "hooks",
        match hooks {
            Hooks::None => format!(
                "none: {} has no hooks PeerHarness can use, so a correction is noted when \
                 its agent notes it",
                agent.name()
            ),
            Hooks::Absent => "not installed".to_owned(),
            Hooks::Installed => format!("installed in {hooks_file}"),
            Hooks::Outdated => format!(
                "in {hooks_file}, from another version or place of PeerHarness: `peerharness \
                 watch {} --install` brings them up to date",
                agent.id()
            ),
            Hooks::Unreadable(why) => format!("{hooks_file} cannot be edited: {why}"),
            Hooks::Shadowed(other) => format!(
                "not installed: {} holds your hooks, which {hooks_file} would turn off",
                other.display()
            ),
        },
    );
    if let Some(b) = backup {
        t.kv("backup", b.display());
    }
    Report::new(json, t.finish())
}
