//! Small filesystem helpers shared by the store and the installer.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// What a path is, without following symlinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Missing,
    Symlink,
    Dir,
    File,
    Other,
}

pub(crate) fn kind_of(path: &Path) -> io::Result<Kind> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            let t = m.file_type();
            Ok(if t.is_symlink() {
                Kind::Symlink
            } else if t.is_dir() {
                Kind::Dir
            } else if t.is_file() {
                Kind::File
            } else {
                Kind::Other
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Kind::Missing),
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub(crate) enum ReadError {
    Missing,
    Symlink,
    NotRegular,
    TooLarge,
    Io(io::Error),
}

/// Reads a regular file without following a final symlink, refusing more than `max`
/// bytes. On Unix the file is opened with `O_NOFOLLOW | O_NONBLOCK` (a symlink swapped in
/// after the check fails to open, and a FIFO swapped in cannot block the read), and the
/// opened file must be the same inode as the one that was inspected.
pub(crate) fn read_regular_bounded(path: &Path, max: usize) -> Result<Vec<u8>, ReadError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::Missing),
        Err(e) => return Err(ReadError::Io(e)),
    };
    if meta.file_type().is_symlink() {
        return Err(ReadError::Symlink);
    }
    if !meta.file_type().is_file() {
        return Err(ReadError::NotRegular);
    }
    if meta.len() > max as u64 {
        return Err(ReadError::TooLarge);
    }
    let file = match open_read_nofollow(path) {
        Ok(f) => f,
        Err(e) if is_symlink_loop(&e) => return Err(ReadError::Symlink),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::Missing),
        Err(e) => return Err(ReadError::Io(e)),
    };
    let opened = file.metadata().map_err(ReadError::Io)?;
    if !same_file(&meta, &opened) || !opened.is_file() {
        return Err(ReadError::Symlink);
    }
    let mut buf = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0).min(max));
    file.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(ReadError::Io)?;
    if buf.len() > max {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// Opens `path` read-only without following a final symlink.
#[cfg(unix)]
fn open_read_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_read_nofollow(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Whether an open error means "the final component is a symlink" (`O_NOFOLLOW`).
#[cfg(unix)]
fn is_symlink_loop(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_loop(_e: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

/// Creates a new file (failing if it exists), writes `bytes` and fsyncs it.
pub(crate) fn write_new_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Fsyncs a directory so renames and creations inside it are durable. A no-op on
/// platforms where directories cannot be opened.
pub(crate) fn fsync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// 16 random hex characters from the OS RNG, for staging directory names.
pub(crate) fn random_suffix() -> Option<String> {
    ph_core::Nonce::random()
        .ok()
        .map(|n| hex::encode(&n.as_bytes()[..8]))
}
