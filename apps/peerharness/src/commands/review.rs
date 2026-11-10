//! `peerharness review`: not implemented yet in this build.

use anyhow::Result;

use crate::commands::Ctx;
use crate::error::not_implemented;
use crate::output::Report;

pub fn run(_ctx: &Ctx, _args: crate::cli::ReviewArgs) -> Result<Report> {
    Err(not_implemented("review"))
}
