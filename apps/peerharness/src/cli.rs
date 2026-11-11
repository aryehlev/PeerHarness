//! clap definitions: the complete command contract (spec section 4 plus ADR-008).
//!
//! The first lines of `--help` are the project's one-line description, the same
//! sentence the README opens with. `observe` and `hook` are left out of the list of
//! commands: the first injects synthetic observations for tests, the second is what
//! Claude Code runs. Both still parse and run.

use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "peerharness",
    version,
    about = "Your team votes on how its AI coding agents behave",
    long_about = "Your team votes on how its AI coding agents behave.\n\n\
                  You correct your agent, the correction becomes a small rule, your team votes \
                  on it, and every member's agent follows what a majority approved. There is \
                  no server, and nothing leaves this device before you have seen it and \
                  confirmed it."
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
    /// Set PeerHarness up for Claude Code, once, in your own terminal.
    ///
    /// Creates your node if there is none, connects it to Claude Code after showing you
    /// what your agent may start and what it never decides, and gives Claude Code those
    /// steps as tools. Each change is shown first and asks for your confirmation.
    Setup(SetupArgs),
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
    /// Listen for the members of your circles and answer their syncs (foreground).
    Daemon(DaemonArgs),
    /// Check who answers at an address and remember it.
    Connect(ConnectArgs),
    /// Inject synthetic observations (tests). Not in the list `--help` prints.
    #[command(hide = true)]
    Observe {
        #[command(subcommand)]
        command: ObserveCommand,
    },
    /// Claude Code hook entry point (always exits 0). Not in the list `--help` prints:
    /// `watch claude --install` writes the command, and Claude Code runs it.
    #[command(hide = true)]
    Hook(HookArgs),
    /// Serve the steps an agent may start as tools of an MCP server, on standard input
    /// and output. Register it with your agent, for Claude Code:
    /// `claude mcp add --scope user peerharness -- peerharness mcp`.
    ///
    /// Every tool runs as an agent's session: a step that needs your consent is asked
    /// in a window when you allowed that (`peerharness setup`), and is refused
    /// otherwise.
    Mcp,
    /// Install or remove agent hooks.
    Watch {
        #[command(subcommand)]
        agent: WatchAgent,
    },
    /// Write down a rule for your agent, in one sentence.
    ///
    /// The rule becomes a candidate in your inbox. Nothing is installed or shared until
    /// you review it. A coding agent may run this command to report a correction you
    /// gave it; it cannot approve what it reported.
    Note(NoteArgs),
    /// Bounded summary of what needs your attention.
    Inbox(InboxArgs),
    /// Review a candidate rule: save it to your library, edit it or ignore it.
    Review(ReviewArgs),
    /// Keep a noted rule for your own agent: save it and install it, in one step.
    ///
    /// Shows the exact text and where it goes, and asks once. Nothing is shared. It is
    /// `review --approve` and `skills install` together.
    Keep(KeepArgs),
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
    /// Exchange with a peer what each of you lacks, directly over QUIC.
    ///
    /// The peer must be running `peerharness daemon`, and each of you must be on the
    /// roll of a circle the other holds. Give its address, or its peer id once an
    /// address is stored. With no argument, syncs with every peer whose address this
    /// node has stored.
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
    /// Where to keep private keys (default: os on macOS, file on Linux).
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
pub struct SetupArgs {
    /// Do not let your agent ask you in a window on your screen: every decision then
    /// needs your own terminal. Also turns the windows off if they were on.
    #[arg(long)]
    pub no_dialogs: bool,
    /// Skip the confirmation prompts (after reviewing what they show).
    #[arg(long)]
    pub yes: bool,
    /// Where a new node keeps its private key, as for `init`.
    #[command(flatten)]
    pub init: InitArgs,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// QUIC listen multiaddr (repeatable; default from config).
    #[arg(long, value_name = "MULTIADDR")]
    pub listen: Vec<String>,
    /// Also sync with the peers this node already knows, every this many seconds.
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u32).range(30..=86_400))]
    pub sync_every: Option<u32>,
    /// Announce this node on the local network (mDNS), so members can find it with
    /// `sync --lan`. Everyone on that network can then see this device's public key and
    /// the port it listens on. It needs a listen address that is not loopback.
    #[arg(long)]
    pub lan: bool,
    /// Join the public libp2p network, so members anywhere can find this node by its
    /// peer id (`sync --internet`, `circle join <peer id> --internet`). The servers of
    /// that network see this device's public key and IP address, and which device keys
    /// this node looks for. They never see a circle or anything said in one.
    #[arg(long)]
    pub internet: bool,
    /// Show a notification on this desktop when a proposal that needs your vote reaches
    /// this node: a count, never its text. macOS only.
    #[arg(long)]
    pub notify: bool,
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
    /// Add the PeerHarness hooks to Claude Code settings (with a backup), and the
    /// skill that asks your agent to report corrections.
    #[arg(long)]
    pub install: bool,
    /// Remove this home's PeerHarness hooks (with a backup) and the reporting skill.
    #[arg(long)]
    pub remove: bool,
    /// With --install: do not install the skill that asks the agent to report corrections.
    #[arg(long, requires = "install")]
    pub no_agent_notes: bool,
    /// With --install: let your agent put seven decisions in front of you in a window on
    /// your screen (keeping a rule for yourself, proposing a rule, your ballot on one,
    /// installing one that passed, inviting someone to a circle, your ballot on
    /// admitting someone, joining a circle).
    /// Only your click in that window decides. macOS only.
    /// The flag is about confirmation dialogs, not the operating system; `--windows`
    /// is its older name and still works.
    #[arg(
        long = "dialogs",
        alias = "windows",
        requires = "install",
        conflicts_with = "no_windows"
    )]
    pub windows: bool,
    /// With --install: turn those windows off again (`--no-windows` still works).
    #[arg(long = "no-dialogs", alias = "no-windows", requires = "install")]
    pub no_windows: bool,
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
pub struct NoteArgs {
    /// The rule, as one sentence (at most 500 characters). Secrets are redacted.
    pub text: String,
    /// Skill name for the rule (a-z, 0-9 and hyphens; default: from its first words).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Mark the note as reported by a coding agent (a label shown in the inbox).
    #[arg(long)]
    pub from_agent: bool,
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

#[derive(Debug, Args)]
pub struct KeepArgs {
    /// Candidate id (cand_…, or a unique prefix of at least 8 hex characters).
    pub candidate: String,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
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
    /// Join a circle you were admitted to: from a member's node, or from a file or
    /// directory a member gave you.
    Join(CircleJoinArgs),
    /// Show the charter: the rules of the vote and the roll of members.
    Members {
        #[arg(long, value_name = "NAME")]
        circle: Option<String>,
    },
    /// Propose removing a member. Removal is decided by vote of the current members.
    Remove(CircleRemoveArgs),
    /// Stop following a circle on this machine and ask to be taken off its roll.
    ///
    /// The rules the circle installed here are removed at once. Coming off the roll is
    /// an amendment like any other: the members vote on it.
    Leave(CircleLeaveArgs),
    /// Propose changing the rules of the vote: the thresholds, or binding versus advisory.
    Amend(CircleAmendArgs),
    /// Propose adding or removing one of a member's devices.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Choose how rules that pass reach this machine: installed at once, or after asking you.
    Mode(CircleModeArgs),
    /// Choose where the rules of a scope are installed on this machine: in one project
    /// directory, or for every project.
    ///
    /// A rule about one repository belongs in that repository. Members agree on a scope
    /// for it (for example `repo/web`); each member says once where their checkout is.
    Place(CirclePlaceArgs),
    /// Cut off a lost or stolen device at once (only on the node that founded the circle).
    ///
    /// A revocation stops the device from syncing and from voting on every node that
    /// learns of it. It does not take the member off the roll: that is `circle remove`.
    Revoke(CircleRevokeArgs),
}

#[derive(Debug, Args)]
pub struct CircleLeaveArgs {
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// Follow the circle again on this machine (a request to leave that is on record
    /// stays there).
    #[arg(long)]
    pub undo: bool,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("force").args(["binding", "advisory"])))]
pub struct CircleAmendArgs {
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// A rule passes with more than this share of its electorate, for example 1/2 or 2/3.
    #[arg(long, value_name = "N/D")]
    pub pass: Option<String>,
    /// Changing these rules needs more than this share of the roll (at least --pass).
    #[arg(long, value_name = "N/D")]
    pub amend: Option<String>,
    /// Passed rules are installed for every member (each can opt out of any rule).
    #[arg(long)]
    pub binding: bool,
    /// Passed rules are advisory: every member is asked before anything is installed.
    #[arg(long)]
    pub advisory: bool,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// Propose adding a device to a member (default: to yourself).
    Add(CircleDeviceArgs),
    /// Propose removing a device from a member (default: from yourself).
    Remove(CircleDeviceArgs),
}

#[derive(Debug, Args)]
pub struct CircleDeviceArgs {
    /// The device's `ed25519:` key (its owner sees it with `peerharness status`).
    pub device: String,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// The member's handle on the roll (default: yours).
    #[arg(long, value_name = "HANDLE")]
    pub member: Option<String>,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").args(["project", "user"]).required(true)))]
pub struct CirclePlaceArgs {
    /// The scope whose rules to place (it also covers the scopes below it).
    pub scope: String,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// Install them in this project only (`<DIR>/.claude/skills`).
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,
    /// Install them for every project again (the default).
    #[arg(long)]
    pub user: bool,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ModeArg {
    /// Rules that pass are installed without asking each time.
    Follow,
    /// You are asked before any rule is installed.
    Ask,
}

#[derive(Debug, Args)]
pub struct CircleModeArgs {
    #[arg(value_enum)]
    pub mode: ModeArg,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct CircleRemoveArgs {
    /// The member's handle on the roll.
    pub member: String,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// Skip the confirmation prompt (after reviewing the preview).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct CircleInviteArgs {
    /// The invitee's `ed25519:` device key (they see it with `peerharness status`).
    pub invitee: String,
    /// The circle to admit them to (`peerharness status` lists yours).
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
    /// Where to write the circle's records for the invitee, once the admission has
    /// passed (default ./peerharness-<circle>-events.jsonl, in the current directory).
    /// The file holds the roll and the proposals: give it only to the invitee. Inside a
    /// coding agent's session no file is written, and this option is refused.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CircleJoinArgs {
    /// Where to get the circle from, once your admission has passed: the address of a
    /// member's running daemon (a multiaddr), with --internet its peer id, or an events
    /// file or shared directory a member wrote.
    #[arg(value_name = "ADDRESS_OR_FILE")]
    pub invite_file: PathBuf,
    /// Find the member's node over the public libp2p network: give its peer id (its
    /// `daemon --internet` prints it) instead of an address. The servers of that network
    /// see this device's public key and IP address and the peer id it looks for.
    #[arg(long)]
    pub internet: bool,
    /// Skip the prompt; requires --expect-fingerprint.
    #[arg(long)]
    pub yes: bool,
    /// The circle root fingerprint the owner gave you out of band.
    #[arg(long, value_name = "FP")]
    pub expect_fingerprint: Option<String>,
    /// The name this node gives the circle: what you pass to `--circle` afterwards
    /// (default: `circle-` and the start of the root fingerprint; `peerharness status`
    /// shows it). The founder's name for the circle does not travel with it.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct CircleRevokeArgs {
    /// The device to cut off: its `ed25519:` key, its peer id, or the handle of a member
    /// who has exactly one device.
    pub device: String,
    #[arg(long, value_name = "NAME")]
    pub circle: String,
    /// Why, in one line of at most 200 characters. Every member can read it.
    #[arg(long, default_value = "")]
    pub reason: String,
    /// Skip the confirmation prompt (after reviewing the preview).
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
    /// Ask a circle about a candidate rule before proposing it.
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
    /// Take a received question out of your inbox. Nothing is sent.
    Dismiss {
        question: String,
        /// Also keep later questions from that device out of your inbox.
        #[arg(long)]
        mute_author: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProposalCommand {
    /// Propose an approved candidate's skill to a circle.
    Create {
        /// Candidate id (cand_…, or a unique prefix of at least 8 hex characters).
        candidate: String,
        /// The circle to propose it to (`peerharness status` lists yours).
        #[arg(long, value_name = "NAME")]
        circle: String,
        /// The scope the rule is for (default `*`: every member).
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        /// Skip the confirmation prompt (after reviewing the preview).
        #[arg(long)]
        yes: bool,
    },
    /// List proposals.
    List,
    /// Show a proposal.
    Show {
        /// Proposal id (sha256:…, or a unique prefix of at least 8 hex characters).
        id: String,
    },
    /// Evaluate a proposal locally.
    Status {
        /// Proposal id (sha256:…, or a unique prefix of at least 8 hex characters).
        id: String,
    },
    /// Cast a ballot. An approval cannot be withdrawn; reject and revise are recorded dissent.
    Vote {
        /// Proposal id (sha256:…, or a unique prefix of at least 8 hex characters;
        /// `inbox` and `proposal list` show them).
        id: String,
        /// Your decision.
        #[arg(value_enum)]
        decision: DecisionArg,
        /// A reason, published with the ballot: one line of at most 200 characters.
        #[arg(long, value_name = "TEXT")]
        rationale: Option<String>,
        /// Skip the confirmation prompt (after reviewing the preview).
        #[arg(long)]
        yes: bool,
    },
    /// Publish the result certificate of a proposal that has passed.
    Release {
        /// Proposal id (sha256:…, or a unique prefix of at least 8 hex characters).
        id: String,
        /// Accepted and has no effect: this command asks nothing. A result states a
        /// count that every node verifies for itself.
        #[arg(long)]
        yes: bool,
    },
    /// Confirm installing a passed rule that is waiting for your confirmation.
    Adopt {
        /// Proposal id (sha256:…, or a unique prefix of at least 8 hex characters;
        /// `rule list` shows it for each rule).
        id: String,
        /// Skip the confirmation prompt (after reviewing the preview).
        #[arg(long)]
        yes: bool,
        /// Accepted and has no effect today. A rule with a high-risk scanner finding is
        /// shown with its findings and confirmed like any other rule, in your terminal
        /// and never in a window, with or without this flag.
        #[arg(long)]
        accept_risk: bool,
    },
    /// Opt out of the rule a proposal adopts (same as `rule opt-out`).
    Refuse {
        /// Proposal id (sha256:…, or a unique prefix of at least 8 hex characters;
        /// `rule list` shows it for each rule).
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    /// Write everything this node holds for a circle to a file, a directory or stdout.
    ///
    /// The output contains the circle's roll and proposals. Give it only to members.
    /// The recipient verifies every signature; the carrier does not need to be trusted.
    Export {
        #[arg(long, value_name = "NAME")]
        circle: String,
        /// Output file (0600; default stdout).
        #[arg(long, value_name = "FILE", conflicts_with = "dir")]
        out: Option<PathBuf>,
        /// Output directory: one small file per record, named by its hash.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Verify and import events from a file or directory another member wrote.
    Import {
        /// A JSON lines file, or a directory written by `events export --dir` or `events sync`.
        file: PathBuf,
    },
    /// Bring this node and a shared directory in line: import what the directory has,
    /// then write what it lacks.
    ///
    /// Meant for a directory your team already shares, such as one in a git repository:
    /// sync, commit, push; the others pull and sync. Every record is its own file, so
    /// members who add different records never touch the same file. Anyone who can read
    /// the directory can read the circle's roll, proposals and ballots.
    Sync {
        /// The shared directory (created if missing).
        dir: PathBuf,
        /// The circle to write (default: the only circle on this node).
        #[arg(long, value_name = "NAME")]
        circle: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// List the rules in force and whether each is installed here.
    List {
        #[arg(long, value_name = "NAME")]
        circle: Option<String>,
    },
    /// Keep one rule off this machine. Only this machine changes, unless you choose to
    /// put it on the circle's record with --announce.
    OptOut {
        /// The rule's skill name.
        name: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
        /// Also tell the circle: a signed, permanent record that you do not follow this
        /// rule. It changes nothing about the rule.
        #[arg(long)]
        announce: bool,
        /// With --announce: why, shared with the members after redaction.
        #[arg(long, value_name = "TEXT", requires = "announce")]
        reason: Option<String>,
        /// With --announce: skip the confirmation prompt (after reviewing the preview).
        #[arg(long, requires = "announce")]
        yes: bool,
    },
    /// Follow a rule again after opting out.
    OptIn {
        /// The rule's skill name.
        name: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
        /// Also tell the circle that you follow the rule again.
        #[arg(long)]
        announce: bool,
        /// Skip the confirmation prompts (after reviewing the previews).
        #[arg(long)]
        yes: bool,
    },
    /// Propose repealing a rule in force. The members who adopted it vote on it.
    Repeal {
        /// The rule's skill name.
        name: String,
        #[arg(long, value_name = "NAME")]
        circle: String,
        /// Why, in one line (shared with the members, after redaction).
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Skip the confirmation prompt (after reviewing the preview).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// The peer's multiaddr (as its daemon prints it), or its peer id after a first sync
    /// (with --internet: the peer id of any device on a roll this node holds). Omit it
    /// to sync with every peer this node knows.
    #[arg(value_name = "ADDRESS_OR_PEER_ID", conflicts_with = "lan")]
    pub peer_id: Option<String>,
    /// Find members of your circles on the local network (mDNS) and sync with them.
    /// Only devices on a roll this node holds are contacted.
    #[arg(long, group = "find")]
    pub lan: bool,
    /// Find members of your circles over the public libp2p network, by their device
    /// keys, and sync with them. With a peer id: that member only. The servers of that
    /// network see this device's public key and IP address and the device keys it looks
    /// for, never a circle. Only devices on a roll this node holds are looked for.
    #[arg(long, group = "find")]
    pub internet: bool,
    /// With --lan or --internet: how many seconds to look for members (default 3 on
    /// the local network, 30 over the internet).
    #[arg(long, value_name = "SECONDS", requires = "find", value_parser = clap::value_parser!(u32).range(1..=120))]
    pub wait: Option<u32>,
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
            vec!["peerharness", "note", "Run the tests before you say done."],
            vec![
                "peerharness",
                "note",
                "--from-agent",
                "Use pnpm.",
                "--name",
                "pnpm",
            ],
            vec![
                "peerharness",
                "watch",
                "claude",
                "--install",
                "--no-agent-notes",
            ],
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
            vec![
                "peerharness",
                "events",
                "export",
                "--circle",
                "team",
                "--dir",
                ".peerharness/team",
            ],
            vec!["peerharness", "events", "sync", ".peerharness/team"],
            vec![
                "peerharness",
                "events",
                "sync",
                ".peerharness/team",
                "--circle",
                "team",
            ],
            vec!["peerharness", "rule", "opt-out", "pnpm", "--circle", "team"],
            vec![
                "peerharness",
                "rule",
                "opt-out",
                "pnpm",
                "--circle",
                "team",
                "--announce",
                "--reason",
                "Our CI images only ship npm.",
            ],
            vec![
                "peerharness",
                "rule",
                "opt-in",
                "pnpm",
                "--circle",
                "team",
                "--announce",
                "--yes",
            ],
            vec![
                "peerharness",
                "rule",
                "repeal",
                "pnpm",
                "--circle",
                "team",
                "--reason",
                "CI only ships npm",
            ],
            vec!["peerharness", "circle", "remove", "bob", "--circle", "team"],
            vec!["peerharness", "circle", "leave", "--circle", "team"],
            vec![
                "peerharness",
                "circle",
                "leave",
                "--circle",
                "team",
                "--undo",
            ],
            vec![
                "peerharness",
                "circle",
                "amend",
                "--circle",
                "team",
                "--pass",
                "2/3",
                "--advisory",
            ],
            vec![
                "peerharness",
                "circle",
                "device",
                "add",
                "ed25519:x",
                "--circle",
                "team",
            ],
            vec!["peerharness", "circle", "mode", "ask", "--circle", "team"],
            vec![
                "peerharness",
                "circle",
                "place",
                "repo/web",
                "--circle",
                "team",
                "--project",
                ".",
            ],
            vec![
                "peerharness",
                "circle",
                "place",
                "repo/web",
                "--circle",
                "team",
                "--user",
            ],
            vec![
                "peerharness",
                "circle",
                "revoke",
                "bob",
                "--circle",
                "team",
                "--reason",
                "laptop lost",
            ],
            vec![
                "peerharness",
                "question",
                "send",
                "cand_0123456789abcdef",
                "--circle",
                "team",
            ],
            vec!["peerharness", "question", "list"],
            vec![
                "peerharness",
                "question",
                "answer",
                "abcd1234",
                "--answer",
                "agree",
                "--rationale",
                "we already do",
            ],
            vec!["peerharness", "question", "dismiss", "abcd1234"],
            vec!["peerharness", "demo"],
            vec!["peerharness", "sync"],
            vec![
                "peerharness",
                "sync",
                "/ip4/192.0.2.7/udp/4001/quic-v1/p2p/12D3KooWx",
            ],
            vec!["peerharness", "daemon", "--sync-every", "60"],
            vec!["peerharness", "daemon", "--lan"],
            vec!["peerharness", "sync", "--lan", "--wait", "5"],
            vec![
                "peerharness",
                "circle",
                "join",
                "/ip4/192.0.2.7/udp/4001/quic-v1",
                "--expect-fingerprint",
                "abcd",
            ],
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
        assert!(
            Cli::try_parse_from(["peerharness", "watch", "claude", "--no-agent-notes"]).is_err()
        );
        assert!(Cli::try_parse_from(["peerharness", "daemon", "--sync-every", "5"]).is_err());
        assert!(Cli::try_parse_from(["peerharness", "sync", "--wait", "5"]).is_err());
        assert!(Cli::try_parse_from(["peerharness", "sync", "--lan", "--internet"]).is_err());
        assert!(Cli::try_parse_from(["peerharness", "sync", "--internet", "--wait", "0"]).is_err());
        for args in [
            vec!["peerharness", "sync", "--internet"],
            vec!["peerharness", "sync", "--internet", "--wait", "90"],
            vec![
                "peerharness",
                "sync",
                "12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
                "--internet",
            ],
            vec!["peerharness", "daemon", "--internet", "--sync-every", "300"],
            vec!["peerharness", "daemon", "--internet", "--lan"],
            vec![
                "peerharness",
                "circle",
                "join",
                "12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
                "--internet",
            ],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        assert!(Cli::try_parse_from(["peerharness", "sync", "/ip4/1.2.3.4", "--lan"]).is_err());
        assert!(
            Cli::try_parse_from(["peerharness", "circle", "place", "x", "--circle", "team"])
                .is_err()
        );
        assert!(Cli::try_parse_from([
            "peerharness",
            "rule",
            "opt-out",
            "pnpm",
            "--circle",
            "team",
            "--reason",
            "x"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "peerharness",
            "circle",
            "amend",
            "--circle",
            "team",
            "--binding",
            "--advisory"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "peerharness",
            "events",
            "export",
            "--circle",
            "team",
            "--out",
            "a",
            "--dir",
            "b"
        ])
        .is_err());
    }
}
