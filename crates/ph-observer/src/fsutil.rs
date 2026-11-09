//! Small private filesystem helpers: private directories, capped reads, 0600 files and
//! atomic replacement.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Mode for files we create (owner read/write only).
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
/// Mode for directories we create (owner only).
pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;

/// The directory a file lives in; `.` for a bare relative file name.
pub(crate) fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// `create_dir_all`, giving any directory it creates mode 0700 on Unix.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(PRIVATE_DIR_MODE);
    }
    b.create(dir)
}

/// Why [`open_regular`] did not return a file.
#[derive(Debug)]
pub(crate) enum OpenFailure {
    /// The path does not exist.
    NotFound,
    /// The final path component is a symlink and `follow` was false.
    Symlink,
    /// The path exists but is not a regular file (FIFO, directory, device, socket).
    NotRegularFile,
    /// Any other I/O error.
    Io(io::Error),
}

/// Opens `path` with `opts`, refusing anything that is not a regular file.
///
/// On Unix the open always uses `O_NONBLOCK`, so a FIFO planted at `path` can never make
/// the caller block (a hook must never stall Claude Code), and with `follow == false` it
/// also uses `O_NOFOLLOW`, so a symlink in the final component is refused atomically
/// (no check-then-open race). `O_NONBLOCK` has no effect on regular files.
pub(crate) fn open_regular(
    opts: &mut OpenOptions,
    path: &Path,
    follow: bool,
) -> Result<File, OpenFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = libc::O_NONBLOCK;
        if !follow {
            flags |= libc::O_NOFOLLOW;
        }
        opts.custom_flags(flags);
    }
    #[cfg(not(unix))]
    {
        if !follow && is_symlink(path) {
            return Err(OpenFailure::Symlink);
        }
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(OpenFailure::NotFound),
        Err(e) if !follow && is_nofollow_error(&e) => return Err(OpenFailure::Symlink),
        Err(e) if is_not_regular_error(&e) => return Err(OpenFailure::NotRegularFile),
        Err(e) => return Err(OpenFailure::Io(e)),
    };
    match f.metadata() {
        Ok(m) if m.is_file() => Ok(f),
        Ok(_) => Err(OpenFailure::NotRegularFile),
        Err(e) => Err(OpenFailure::Io(e)),
    }
}

/// The error an `O_NOFOLLOW` open reports for a symlink: `ELOOP` (Linux, macOS) or
/// `EMLINK` (FreeBSD).
#[cfg(unix)]
fn is_nofollow_error(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(c) if c == libc::ELOOP || c == libc::EMLINK)
}

#[cfg(not(unix))]
fn is_nofollow_error(_e: &io::Error) -> bool {
    false
}

/// Errors an open reports for a non-regular file: `ENXIO` (FIFO without a reader opened
/// for non-blocking write, or a device) and `EISDIR` (directory opened for writing).
#[cfg(unix)]
fn is_not_regular_error(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(c) if c == libc::ENXIO || c == libc::EISDIR)
}

#[cfg(not(unix))]
fn is_not_regular_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::IsADirectory
}

/// Outcome of [`read_capped`].
pub(crate) enum CappedRead {
    /// The file does not exist.
    Missing,
    /// The whole file, at most `max` bytes.
    Bytes(Vec<u8>),
    /// The file is larger than `max` bytes.
    TooLarge,
    /// The path is not a regular file (directory, FIFO, device, ...).
    NotRegularFile,
}

/// Reads a whole regular file (following symlinks) if it is at most `max` bytes. Never
/// blocks on a FIFO.
pub(crate) fn read_capped(path: &Path, max: u64) -> io::Result<CappedRead> {
    let f = match open_regular(OpenOptions::new().read(true), path, true) {
        Ok(f) => f,
        Err(OpenFailure::NotFound) => return Ok(CappedRead::Missing),
        Err(OpenFailure::NotRegularFile) => return Ok(CappedRead::NotRegularFile),
        Err(OpenFailure::Symlink) => return Ok(CappedRead::NotRegularFile),
        Err(OpenFailure::Io(e)) => return Err(e),
    };
    let mut buf = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Ok(CappedRead::TooLarge);
    }
    Ok(CappedRead::Bytes(buf))
}

/// Options for a new 0600 file.
pub(crate) fn private_open_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(PRIVATE_FILE_MODE);
    }
    o
}

/// Creates `path` exclusively (fails if it exists) with mode 0600 and writes `bytes`.
pub(crate) fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = private_open_options()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// The Unix permission bits of an existing file, if it can be determined.
pub(crate) fn existing_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Atomically replaces `path` with `bytes`: write a temp file in the same directory,
/// fsync it, set `mode`, rename it over `path`, then fsync the directory (best effort).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = parent_dir(path);
    let mut tmp = tempfile::Builder::new()
        .prefix(".peerharness-tmp-")
        .tempfile_in(&dir)?;
    tmp.as_file_mut().write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    if let Ok(d) = File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// True when `path` exists and is a symbolic link (not followed).
pub(crate) fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}
