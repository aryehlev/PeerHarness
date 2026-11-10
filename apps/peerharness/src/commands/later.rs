//! Commands whose arguments are final but whose implementation belongs to a later
//! build stage. Each one fails with a clear message and exit code 1.

use anyhow::Result;

use crate::cli::{ConnectArgs, DaemonArgs, QuestionCommand, SyncArgs};
use crate::commands::Ctx;
use crate::error::not_implemented;
use crate::output::Report;

pub fn daemon(_ctx: &Ctx, _args: DaemonArgs) -> Result<Report> {
    Err(not_implemented("daemon"))
}

pub fn connect(_ctx: &Ctx, _args: ConnectArgs) -> Result<Report> {
    Err(not_implemented("connect"))
}

pub fn question(_ctx: &Ctx, _command: QuestionCommand) -> Result<Report> {
    Err(not_implemented("question"))
}

pub fn sync(_ctx: &Ctx, _args: SyncArgs) -> Result<Report> {
    Err(not_implemented("sync"))
}
