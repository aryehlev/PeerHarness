//! Bounded child-process execution shared by the CLI providers.
//!
//! The child gets the payload on stdin, its stdout is read into a buffer capped at a
//! byte limit, stderr is discarded (it may echo content and is never logged), and the
//! child is killed when the deadline passes or the cap is exceeded.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use super::{ProviderError, ADVISORY_CHILD_ENV, SCRUBBED_ENV};

/// A fresh, empty working directory for one provider run, removed on drop.
pub(crate) struct Sandbox {
    dir: tempfile::TempDir,
    work: PathBuf,
}

impl Sandbox {
    /// Creates `<tmp>/peerharness-advisory-XXXX/work` (empty).
    pub(crate) fn new() -> Result<Self, ProviderError> {
        let dir = tempfile::Builder::new()
            .prefix("peerharness-advisory-")
            .tempdir()
            .map_err(|e| ProviderError::Io(e.kind()))?;
        let work = dir.path().join("work");
        std::fs::create_dir(&work).map_err(|e| ProviderError::Io(e.kind()))?;
        Ok(Self { dir, work })
    }

    /// The empty directory used as the child's cwd.
    pub(crate) fn work_dir(&self) -> &Path {
        &self.work
    }

    /// A path outside the work directory for provider output files.
    pub(crate) fn output_path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

pub(crate) struct Finished {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
}

/// Applies the common environment and cwd rules to a provider command.
pub(crate) fn prepare(cmd: &mut Command, cwd: &Path) {
    cmd.current_dir(cwd);
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd.env(ADVISORY_CHILD_ENV, "1");
}

fn spawn_with_retry(cmd: &mut Command) -> Result<Child, ProviderError> {
    let mut attempts = 0u32;
    loop {
        match cmd.spawn() {
            Ok(c) => return Ok(c),
            // A freshly written executable can be briefly busy on Linux when another
            // thread forked while it was open for writing.
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(ProviderError::Spawn(e.kind())),
        }
    }
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs `cmd` with `input` on stdin, returning its exit status and stdout.
///
/// * Fails with [`ProviderError::Timeout`] (after killing the child) when `timeout`
///   elapses, including while waiting for stdout to close.
/// * Fails with [`ProviderError::OutputTooLarge`] (after killing the child) as soon as
///   stdout exceeds `max_stdout` bytes.
pub(crate) fn run_bounded(
    cmd: &mut Command,
    input: &[u8],
    timeout: Duration,
    max_stdout: usize,
) -> Result<Finished, ProviderError> {
    let secs = timeout.as_secs().max(1);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let deadline = Instant::now() + timeout;
    let mut child = spawn_with_retry(cmd)?;

    if let Some(mut stdin) = child.stdin.take() {
        let data = input.to_vec();
        let spawned = std::thread::Builder::new()
            .name("ph-provider-stdin".into())
            .spawn(move || {
                // A child that exits early closes the pipe; that is not our error.
                let _ = stdin.write_all(&data);
            });
        if spawned.is_err() {
            kill_and_reap(&mut child);
            return Err(ProviderError::Io(std::io::ErrorKind::Other));
        }
    }

    let Some(mut stdout) = child.stdout.take() else {
        kill_and_reap(&mut child);
        return Err(ProviderError::Io(std::io::ErrorKind::BrokenPipe));
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let overflow_flag = Arc::clone(&overflow);
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, ProviderError>>();
    let spawned = std::thread::Builder::new()
        .name("ph-provider-stdout".into())
        .spawn(move || {
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 8192];
            let result = loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => break Ok(buf),
                    Ok(n) => {
                        if buf.len().saturating_add(n) > max_stdout {
                            overflow_flag.store(true, Ordering::SeqCst);
                            break Err(ProviderError::OutputTooLarge { max: max_stdout });
                        }
                        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => break Err(ProviderError::Io(e.kind())),
                }
            };
            let _ = tx.send(result);
        });
    if spawned.is_err() {
        kill_and_reap(&mut child);
        return Err(ProviderError::Io(std::io::ErrorKind::Other));
    }

    let status = loop {
        if overflow.load(Ordering::SeqCst) {
            kill_and_reap(&mut child);
            return Err(ProviderError::OutputTooLarge { max: max_stdout });
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                kill_and_reap(&mut child);
                return Err(ProviderError::Io(e.kind()));
            }
        }
        if Instant::now() >= deadline {
            kill_and_reap(&mut child);
            tracing::warn!(
                timeout_secs = secs,
                "advisory provider timed out; child killed"
            );
            return Err(ProviderError::Timeout { secs });
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    // The child exited. A grandchild could still hold stdout open, so wait for the
    // reader only until the deadline (with a small grace period).
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(250));
    match rx.recv_timeout(remaining) {
        Ok(Ok(stdout)) => Ok(Finished { status, stdout }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ProviderError::Timeout { secs }),
    }
}
