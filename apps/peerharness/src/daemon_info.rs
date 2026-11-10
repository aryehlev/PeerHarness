//! `daemon.json` (0600): written by the running daemon once its listen addresses are
//! known and removed on shutdown. The token authenticates control requests and is never
//! printed.
// Written by the network daemon, which is not wired into the CLI yet.
#![allow(dead_code)]
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::home::{read_bounded_file, write_private_file, Home};

const MAX_DAEMON_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonInfo {
    pub pid: u32,
    pub control_port: u16,
    /// 256-bit random token, hex.
    pub token: String,
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub listen_addrs: Vec<String>,
}

impl std::fmt::Debug for DaemonInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonInfo")
            .field("pid", &self.pid)
            .field("control_port", &self.control_port)
            .field("peer_id", &self.peer_id)
            .field("listen_addrs", &self.listen_addrs.len())
            .finish_non_exhaustive()
    }
}

impl DaemonInfo {
    /// Reads `daemon.json` if present (it may be stale; see [`DaemonInfo::is_reachable`]).
    pub fn read(home: &Home) -> Result<Option<Self>> {
        let p = home.daemon_file();
        if !p.exists() {
            return Ok(None);
        }
        let bytes = read_bounded_file(&p, MAX_DAEMON_FILE_BYTES)?;
        match serde_json::from_slice::<DaemonInfo>(&bytes) {
            Ok(i) => Ok(Some(i)),
            Err(_) => {
                tracing::warn!("daemon.json is malformed; ignoring it");
                Ok(None)
            }
        }
    }

    pub fn write(&self, home: &Home) -> Result<()> {
        let s = serde_json::to_vec_pretty(self)?;
        write_private_file(&home.daemon_file(), &s)
    }

    /// Whether something accepts connections on the control port (a quick liveness
    /// probe that sends nothing).
    pub fn is_reachable(&self) -> bool {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.control_port));
        TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
    }

    /// The running daemon, if `daemon.json` exists and its control port answers.
    pub fn running(home: &Home) -> Option<Self> {
        Self::read(home).ok().flatten().filter(|i| i.is_reachable())
    }
}
