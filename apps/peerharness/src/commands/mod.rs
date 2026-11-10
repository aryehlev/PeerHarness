//! One module per command group.

pub mod circle;
pub mod demo;
pub mod doctor;
pub mod exchange;
pub mod export;
pub mod inbox;
pub mod init;
pub mod net;
pub mod note;
pub mod observe;
pub mod proposal;
pub mod question;
pub mod reset;
pub mod review;
pub mod rule;
pub mod skills;
pub mod status;
pub mod watch;

use std::path::PathBuf;

use anyhow::Result;

use crate::cli::Command;
use crate::home::Home;
use crate::node::Node;
use crate::output::{Output, Report};

/// What every command gets.
pub struct Ctx {
    pub home: Home,
    pub out: Output,
}

impl Ctx {
    pub fn open_node(&self) -> Result<Node> {
        Node::open(&self.home)
    }
}

pub fn dispatch(ctx: &Ctx, command: Command) -> Result<Report> {
    use crate::cli::{ObserveCommand, WatchAgent};
    match command {
        Command::Init(a) => init::run(ctx, a),
        Command::Status => status::run(ctx),
        Command::Demo => demo::run(ctx),
        Command::Doctor => doctor::run(ctx),
        Command::Daemon(a) => net::daemon(ctx, a),
        Command::Connect(a) => net::connect(ctx, a),
        Command::Observe { command } => match command {
            ObserveCommand::Demo => observe::demo(ctx),
            ObserveCommand::Import { file } => observe::import(ctx, &file),
        },
        // Normally handled before clap (see main); reached only when clap parsed it.
        Command::Hook(a) => {
            crate::hook::run_and_exit(Some(ctx.home.root().to_path_buf()), Some(&a.event))
        }
        Command::Watch { agent } => match agent {
            WatchAgent::Claude(a) => watch::claude(ctx, a),
        },
        // Serves until its client closes standard input, and prints no report: standard
        // output belongs to the protocol.
        Command::Mcp => crate::mcp::serve_and_exit(ctx),
        Command::Note(a) => note::run(ctx, a),
        Command::Inbox(a) => inbox::run(ctx, a),
        Command::Review(a) => review::run(ctx, a),
        Command::Skills { command } => skills::run(ctx, command),
        Command::Circle { command } => circle::run(ctx, command),
        Command::Question { command } => question::run(ctx, command),
        Command::Proposal { command } => proposal::run(ctx, command),
        Command::Events { command } => exchange::run(ctx, command),
        Command::Rule { command } => rule::run(ctx, command),
        Command::Sync(a) => net::sync(ctx, a),
        Command::Export(a) => export::run(ctx, a),
        Command::Reset(a) => reset::run(ctx, a),
    }
}

/// The Claude settings path: `--settings`, else `$PEERHARNESS_CLAUDE_SETTINGS`, else
/// `$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json`.
pub fn claude_settings_path(arg: Option<&std::path::Path>) -> Result<PathBuf> {
    if let Some(p) = arg {
        return crate::home::absolute(p);
    }
    if let Some(p) = std::env::var_os("PEERHARNESS_CLAUDE_SETTINGS").filter(|p| !p.is_empty()) {
        return crate::home::absolute(std::path::Path::new(&p));
    }
    let user_home = crate::home::user_home()
        .ok_or_else(|| crate::error::usage("cannot find your home directory: pass --settings"))?;
    let claude_dir = std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    Ok(ph_observer::claude_user_settings_path(
        &user_home,
        claude_dir.as_deref(),
    ))
}

/// The hook command for this binary and home.
pub fn hook_command(home: &Home) -> Result<ph_observer::HookCommand> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|_| anyhow::anyhow!("cannot determine the path of this executable"))?;
    let h = (!home.is_default()).then(|| home.root());
    ph_observer::HookCommand::new(&exe, h)
        .map_err(|e| anyhow::anyhow!("cannot build the hook command: {e}"))
}
