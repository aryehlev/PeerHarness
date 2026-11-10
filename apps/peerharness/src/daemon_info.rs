//! `daemon.json` (0600): written by the running daemon once its listen addresses are
//! known and removed when it stops. It tells the owner (and `status`) where this node
//! can be dialed. It holds no secret.
//!
//! Whether a daemon is running is not read from that file, which a crash leaves behind,
//! but from `daemon.lock`: the daemon holds an exclusive lock on it for as long as it
//! lives, and the operating system drops the lock with the process.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::home::{read_bounded_file, write_private_file, Home};

/// The lock file's name inside the home.
const LOCK_FILE: &str = "daemon.lock";

/// The exclusive lock a running daemon holds on its home. Dropping it releases the lock.
pub struct DaemonLock(#[allow(dead_code)] std::fs::File);

impl DaemonLock {
    fn open(home: &Home) -> Result<std::fs::File> {
        use anyhow::Context;
        let path = home.root().join(LOCK_FILE);
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("cannot open {}", path.display()))
    }

    /// Takes the lock, or returns `None` when another daemon already serves this home.
    pub fn acquire(home: &Home) -> Result<Option<Self>> {
        let file = Self::open(home)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => {
                Err(anyhow::anyhow!("cannot lock the daemon file: {e}"))
            }
        }
    }

    /// Whether a daemon currently holds the lock for this home.
    pub fn is_held(home: &Home) -> bool {
        if !home.root().join(LOCK_FILE).exists() {
            return false;
        }
        match Self::open(home).map(|f| f.try_lock()) {
            // We got it, so nobody had it. It is released when `f` is dropped here.
            Ok(Ok(())) => false,
            Ok(Err(std::fs::TryLockError::WouldBlock)) => true,
            _ => false,
        }
    }
}

const MAX_DAEMON_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DaemonInfo {
    /// Process id of the daemon that wrote the file.
    pub pid: u32,
    /// This node's peer id.
    pub peer_id: String,
    /// The addresses it listens on, each ending in `/p2p/<peer id>`.
    pub listen_addrs: Vec<String>,
}

impl DaemonInfo {
    /// Reads `daemon.json` if present. The file can be stale after a crash: it says
    /// where a daemon was listening, not that one still is.
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

    /// The running daemon of this home: its lock is held and it has written its file.
    pub fn running(home: &Home) -> Option<Self> {
        if !DaemonLock::is_held(home) {
            return None;
        }
        Self::read(home).ok().flatten()
    }

    /// Removes `daemon.json` if this process wrote it.
    pub fn remove(home: &Home) {
        if let Ok(Some(info)) = Self::read(home) {
            if info.pid == std::process::id() {
                let _ = std::fs::remove_file(home.daemon_file());
            }
        }
    }
}
