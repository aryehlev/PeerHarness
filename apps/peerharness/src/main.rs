//! `peerharness`: the command-line entry point.
//!
//! This file only wires things together: it routes hook invocations before argument
//! parsing (a hook must never fail or print), parses the command line, runs the command
//! and maps the outcome to the exit code contract in [`error`].

mod agent_notes;
mod carrier;
mod cli;
mod commands;
mod config;
mod consent;
mod daemon_info;
mod detect;
mod error;
mod governance;
mod home;
mod hook;
mod ids;
mod installs;
mod internet;
mod library;
mod node;
mod notify;
mod output;
mod peer;
mod runtime;
mod window;

use clap::Parser;

use crate::cli::Cli;
use crate::commands::Ctx;
use crate::home::Home;
use crate::output::{Output, Report};

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    // Before clap: even a malformed hook invocation exits 0 without printing.
    if let Some((home, event)) = hook::detect_hook_invocation(&args) {
        hook::run_and_exit(home, event.as_deref());
    }
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let out = Output { json: cli.json };
    let code = match run(cli, out) {
        Ok(report) => {
            out.print_report(&report);
            report.exit.map_or(0, error::ExitKind::code)
        }
        Err(e) => {
            let kind = error::exit_kind(&e);
            // `{:#}` joins the context chain. Library errors are privacy-safe by design.
            out.print_error(kind.as_str(), kind.code(), &format!("{e:#}"));
            kind.code()
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli, out: Output) -> anyhow::Result<Report> {
    let home = Home::resolve(cli.home.as_deref())?;
    let ctx = Ctx { home, out };
    commands::dispatch(&ctx, cli.command)
}

/// Logs go to stderr and carry ids and counts only (architecture section 13). Silent
/// unless `-v` is given.
fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => return,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
