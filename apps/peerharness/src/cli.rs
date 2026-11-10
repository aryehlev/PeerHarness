//! clap definitions: the complete command contract (spec section 4 plus ADR-008).
//!
//! Commands that belong to later build stages are defined here with their final
//! arguments and currently return a "not yet implemented in this build" error.

use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "peerharness",
    version,
    about = "Local-first, peer-to-peer learning harness for AI coding agents",
    long_about = "Local-first, peer-to-peer learning harness for AI coding agents.\n\n\
                  Your AI learns from you. Your peers' AI learns from what you approve.\n\
                  Nothing leaves this device without an explicit, previewed confirmation."
)]
pub struct Cli {
    /// Node home directory (default ~/.peerharness).
    #[arg(long, global = true, env = "PEERHARNESS_HOME", value_name = "PATH")]
    pub home: Option<PathBuf>,

    /// Machine-readable JSON output on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Log to stderr (-v info, -vv debug, -vvv trace). Logs contain ids and counts only.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate the device key, database and config (idempotent).
    Init(InitArgs),
    /// Show mode, peer id, circles and hook status.
    Status,
    /// Run a self-contained demonstration: three members vote on a rule for their agents.
    ///
    /// Uses temporary homes and temporary skills directories. Nothing in your own
    /// home or in ~/.claude is read or changed, and nothing is sent anywhere.
    Demo,
    /// Local diagnostics (no network calls).
    Doctor,
    /// Run the networking daemon in the foreground.
    Daemon(DaemonArgs),
    /// Dial a peer through the running daemon.
    Connect(ConnectArgs),
    /// Inject synthetic observations (demo and tests).
    Observe {
        #[command(subcommand)]
        command: ObserveCommand,
    },
    /// Claude Code hook entry point (always exits 0).
    Hook(HookArgs),
    /// Install or remove agent hooks.
    Watch {
        #[command(subcommand)]
        agent: WatchAgent,
    },
    /// Bounded summary of what needs your attention.
    Inbox(InboxArgs),
    /// Review a detected candidate convention.
    Review(ReviewArgs),
    /// Local skill library and installation.
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    /// Private trust circles.
    Circle {
        #[command(subcommand)]
        command: CircleCommand,
    },
    /// Questions shared with a circle.
    Question {
        #[command(subcommand)]
        command: QuestionCommand,
    },
    /// Proposals, ballots and results.
    Proposal {
        #[command(subcommand)]
        command: ProposalCommand,
    },
    /// Reconcile missing authorized events with a peer through the daemon.
    Sync(SyncArgs),
    /// Exchange a circle's signed events with other members as a file.
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    /// The rules in force and your choices about them.
    Rule {
        #[command(subcommand)]
        command: RuleCommand,
    },
    /// Export the data this node owns.
    Export(ExportArgs),
    /// Delete this node's home directory and keystore entries.
    Reset(ResetArgs),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeystoreArg {
    Os,
    File,
    InsecureDev,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KdfProfileArg {
    Default,
    FastInsecureTest,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Where to keep private keys (default: os on macOS/Windows, file elsewhere).
    #[arg(long, value_enum)]
    pub keystore: Option<KeystoreArg>,
    /// Required with `--keystore insecure-dev`: keys are stored in PLAINTEXT.
    #[arg(long)]
    pub insecure_dev_keystore: bool,
    /// TEST-ONLY: weak Argon2id parameters for key files (tests and demos).
    #[arg(long, value_enum, hide = true)]
    pub kdf_profile: Option<KdfProfileArg>,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// QUIC listen multiaddr (repeatable; default from config).
    #[arg(long, value_name = "MULTIADDR")]
    pub listen: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Peer multiaddr, ideally ending in /p2p/<peer-id>.
    pub multiaddr: String,
}

#[derive(Debug, Subcommand)]
pub enum ObserveCommand {
    /// Inject the synthetic "No, use pnpm, not npm" correction twice into repo "demo-repo".
    Demo,
    /// Import synthetic observation events from a JSONL file.
    Import {
        /// File with one JSON object per line: {"kind","repo","text"[,"session"][,"created_at"]}.
        file: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct HookArgs {
    /// user-prompt-submit | stop | post-tool-use-failure
    pub event: String,
}

#[derive(Debug, Subcommand)]
pub enum WatchAgent {
    /// Claude Code hooks (UserPromptSubmit and Stop).
    Claude(WatchClaudeArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("action").args(["install", "remove", "status"])))]
pub struct WatchClaudeArgs {
    /// Add the PeerHarness hooks to Claude Code settings (with a backup).
    #[arg(long)]
    pub install: bool,
    /// Remove this home's PeerHarness hooks (with a backup).
    #[arg(long)]
    pub remove: bool,
    /// Show whether the hooks are installed (default).
    #[arg(long)]
    pub status: bool,
    /// Settings file (default: $PEERHARNESS_CLAUDE_SETTINGS or ~/.claude/settings.json).
    #[arg(long, value_name = "PATH")]
    pub settings: Option<PathBuf>,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct InboxArgs {
    /// Maximum items per section.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=200))]
    pub limit: u32,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("decision").args(["approve", "reject"])))]
pub struct ReviewArgs {
    /// Candidate id (cand_…, or a unique prefix of at least 8 hex characters).
    pub candidate: String,
    /// Save locally: approve and draft a local skill.
    #[arg(long)]
    pub approve: bool,
    /// Ignore this candidate.
    #[arg(long)]
    pub reject: bool,
    /// Replace the statement (combine with --approve to approve the edited text).
    #[arg(long, value_name = "STATEMENT")]
    pub edit: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AgentArg {
    Claude,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ScopeArg {
    User,
    Project,
}

// Used by `skills install`, which is not implemented in this build yet.
#[allow(dead_code)]
impl ScopeArg {
    pub fn skill_scope(self) -> ph_skills::SkillScope {
        match self {
            ScopeArg::User => ph_skills::SkillScope::User,
            ScopeArg::Project => ph_skills::SkillScope::Project,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    /// List local skills.
    List,
    /// Show a skill's SKILL.md, scan findings and installations.
    Show {
        /// Skill id (number), name, candidate id or bundle digest prefix.
        id: String,
    },
    /// Install a skill into the agent's native skills directory.
    Install(SkillsInstallArgs),
    /// Remove a PeerHarness-managed installation.
    Uninstall(SkillsUninstallArgs),
    /// Reinstall the previously installed version.
    Rollback(SkillsRollbackArgs),
}

#[derive(Debug, Args)]
pub struct SkillsInstallArgs {
    /// Skill id (number), name, candidate id or bundle digest prefix.
    pub id: String,
    #[arg(long, value_enum, default_value = "claude")]
    pub agent: AgentArg,
    #[arg(long, value_enum, default_value = "user")]
    pub scope: ScopeArg,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
    /// Required to install a skill with high-risk scanner findings.
    #[arg(long)]
    pub accept_risk: bool,
    /// Replace an existing directory that PeerHarness does not manage (moved to a backup).
    #[arg(long)]
    pub force_overwrite_unmanaged: bool,
    /// Replace a managed installation whose files were edited by hand.
    #[arg(long)]
    pub allow_modified: bool,
}

#[derive(Debug, Args)]
pub struct SkillsUninstallArgs {
    /// Skill id (number), name, candidate id or bundle digest prefix.
    pub id: String,
    #[arg(long, value_enum, default_value = "claude")]
    pub agent: AgentArg,
    /// Installation scope (default: the only active installation).
    #[arg(long, value_enum)]
    pub scope: Option<ScopeArg>,
    /// Also remove a managed installation whose files were edited by hand.
    #[arg(long)]
    pub allow_modified: bool,
}

#[derive(Debug, Args)]
pub struct SkillsRollbackArgs {
    /// Skill id (number), name, candidate id or bundle digest prefix.
    pub id: String,
    #[arg(long, value_enum, default_value = "claude")]
    pub agent: AgentArg,
    /// Installation scope (default: the only active installation).
    #[arg(long, value_enum)]
    pub scope: Option<ScopeArg>,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
    /// Required when the previous version has high-risk scanner findings.
    #[arg(long)]
    pub accept_risk: bool,
}

#[derive(Debug, Subcommand)]
pub enum CircleCommand {
    /// Found a circle: a new root key and a charter with you as the only member.
    Create {
        /// Local circle name (1-64 characters).
        name: String,
        /// Your member handle on the roll (a-z, 0-9, '.', '_', '-'; default: your user name).
        #[arg(long, value_name = "HANDLE")]
        member: Option<String>,
    },
    /// Propose admitting a new member. Admission is decided by vote of the current members.
    Invite(CircleInviteArgs),
    /// Join a circle from an events file a member gave you.
    Join(CircleJoinArgs),
    /// Show the charter: the rules of the vote and the roll of members.
    Members {
        #[arg(long, value_name = "NAME")]
        circle: Option<String>,
    },
    /// Revoke a member (founder only).
    Revoke(CircleRevokeArgs),
}

#[derive(Debug, Args)]
pub struct CircleInviteArgs {
    /// The invitee's `ed25519:` device key (they see it with `peerharness status`).
    pub invitee: String,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// The invitee's member handle on the roll (a-z, 0-9, '.', '_', '-').
    #[arg(long, value_name = "HANDLE")]
    pub member: String,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
    /// Granted scope (repeatable; default `*`).
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scopes: Vec<String>,
    #[arg(long, value_enum, default_value = "member")]
    pub role: RoleArg,
    /// Address the invitee can dial (repeatable; default: the running daemon's).
    #[arg(long = "addr", value_name = "MULTIADDR")]
    pub addrs: Vec<String>,
    /// Invite file to write (default ./peerharness-invite-<fingerprint>.json).
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Invite validity in hours (1-168, default 24).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=168))]
    pub ttl_hours: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    Member,
    Owner,
}

#[derive(Debug, Args)]
pub struct CircleJoinArgs {
    /// Events file exported by a member after your admission passed.
    pub invite_file: PathBuf,
    /// Skip the prompt; requires --expect-fingerprint.
    #[arg(long)]
    pub yes: bool,
    /// The circle root fingerprint the owner gave you out of band.
    #[arg(long, value_name = "FP")]
    pub expect_fingerprint: Option<String>,
    /// Local name for the circle (default: the name in the invite).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct CircleRevokeArgs {
    /// The member's peer id or `ed25519:` device key.
    pub member: String,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    #[arg(long, default_value = "")]
    pub reason: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AnswerArg {
    Agree,
    Disagree,
    Unsure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DecisionArg {
    Approve,
    Reject,
    Revise,
}

#[derive(Debug, Subcommand)]
pub enum QuestionCommand {
    /// Share a sanitized question about an approved candidate.
    Send {
        candidate: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        #[arg(long, value_name = "TEXT")]
        text: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// List received and sent questions.
    List,
    /// Answer a received question.
    Answer {
        question: String,
        #[arg(long, value_enum)]
        answer: AnswerArg,
        #[arg(long)]
        rationale: Option<String>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProposalCommand {
    /// Propose an approved candidate's skill to a circle.
    Create {
        candidate: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// List proposals.
    List,
    /// Show a proposal.
    Show { id: String },
    /// Evaluate a proposal locally.
    Status { id: String },
    /// Cast a ballot. An approval cannot be withdrawn; reject and revise are recorded dissent.
    Vote {
        id: String,
        #[arg(value_enum)]
        decision: DecisionArg,
        #[arg(long)]
        rationale: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Publish the result certificate of a proposal that has passed.
    Release {
        id: String,
        #[arg(long)]
        yes: bool,
    },
    /// Confirm installing a passed rule that is waiting for your confirmation.
    Adopt {
        id: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        accept_risk: bool,
    },
    /// Opt out of the rule a proposal adopts (same as `rule opt-out`).
    Refuse { id: String },
}

#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    /// Write everything this node holds for a circle to a file (or stdout).
    ///
    /// The file contains the circle's roll and proposals. Give it only to members.
    /// The recipient verifies every signature; the carrier does not need to be trusted.
    Export {
        #[arg(long, value_name = "NAME")]
        circle: String,
        /// Output file (0600; default stdout).
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Verify and import events from a file another member exported.
    Import { file: PathBuf },
}

#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// List the rules in force and whether each is installed here.
    List {
        #[arg(long, value_name = "NAME")]
        circle: Option<String>,
    },
    /// Keep one rule off this machine. Only this machine changes.
    OptOut {
        /// The rule's skill name.
        name: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
    },
    /// Follow a rule again after opting out.
    OptIn {
        /// The rule's skill name.
        name: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
    },
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    pub peer_id: String,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Export this node's local data (the only export mode).
    #[arg(long)]
    pub local: bool,
    /// Output file (0600; default stdout).
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ResetArgs {
    /// Actually delete (without it, only explain what would be deleted).
    #[arg(long)]
    pub confirm: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_contract_examples() {
        for args in [
            vec!["peerharness", "init", "--keystore", "file"],
            vec!["peerharness", "--json", "status"],
            vec!["peerharness", "observe", "demo"],
            vec!["peerharness", "observe", "import", "x.jsonl"],
            vec!["peerharness", "watch", "claude", "--install"],
            vec![
                "peerharness",
                "review",
                "cand_0123456789abcdef",
                "--approve",
            ],
            vec![
                "peerharness",
                "skills",
                "install",
                "1",
                "--agent",
                "claude",
                "--scope",
                "user",
                "--yes",
            ],
            vec![
                "peerharness",
                "circle",
                "invite",
                "ed25519:x",
                "--circle",
                "team",
                "--member",
                "bob",
                "--scope",
                "team/backend",
            ],
            vec![
                "peerharness",
                "circle",
                "create",
                "team",
                "--member",
                "alice",
            ],
            vec!["peerharness", "events", "export", "--circle", "team"],
            vec!["peerharness", "events", "import", "team.jsonl"],
            vec!["peerharness", "rule", "opt-out", "pnpm", "--circle", "team"],
            vec!["peerharness", "demo"],
            vec!["peerharness", "proposal", "vote", "abcd1234", "approve"],
            vec!["peerharness", "reset", "--confirm"],
            vec!["peerharness", "export", "--local"],
            vec!["peerharness", "hook", "user-prompt-submit"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        assert!(
            Cli::try_parse_from(["peerharness", "review", "cand_x", "--approve", "--reject"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["peerharness", "watch", "claude", "--install", "--remove"])
                .is_err()
        );
    }
}
