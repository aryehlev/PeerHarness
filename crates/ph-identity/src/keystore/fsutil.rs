//! Small filesystem helpers: private directories, permission checks, bounded reads and
//! atomic writes.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use rand::TryRng as _;
use zeroize::Zeroizing;

use crate::error::{IdentityError, Result};

/// Creates `dir` (and parents) if missing and makes sure it is mode 0700 on unix.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(IdentityError::NotRegularFile {
                path: dir.to_path_buf(),
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            create_dir_all_private(dir)?;
        }
        Err(e) => return Err(IdentityError::io("inspect", dir, &e)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(dir).map_err(|e| IdentityError::io("inspect", dir, &e))?;
        if m.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| IdentityError::io("chmod", dir, &e))?;
        }
    }
    Ok(())
}

fn create_dir_all_private(dir: &Path) -> Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| IdentityError::io("create directory", dir, &e))
}

/// Whether something exists at `path` (without following a final symlink).
pub(crate) fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(IdentityError::io("inspect", path, &e)),
    }
}

/// Checks that `path` is a regular file (not a symlink) and, on unix, not accessible by
/// group or others. Returns `Ok(false)` if it does not exist.
pub(crate) fn check_private_file(path: &Path) -> Result<bool> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(IdentityError::io("inspect", path, &e)),
    };
    if !m.file_type().is_file() {
        return Err(IdentityError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    Ok(true)
}

/// Reads at most `max` bytes from `path`; a larger file is an error. The buffer is
/// zeroized on drop.
pub(crate) fn read_bounded(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let f = File::open(path).map_err(|e| IdentityError::io("open", path, &e))?;
    read_handle_bounded(f, path, max)
}

/// Like [`read_bounded`], but for secret files: the opened handle is re-checked to be a
/// regular file that is not accessible by group or others (unix). Together with the
/// [`check_private_file`] pre-check this closes the window in which the file could be
/// swapped for a symlink or a looser file between the check and the open.
pub(crate) fn read_private_bounded(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let f = File::open(path).map_err(|e| IdentityError::io("open", path, &e))?;
    let m = f
        .metadata()
        .map_err(|e| IdentityError::io("inspect", path, &e))?;
    if !m.is_file() {
        return Err(IdentityError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    read_handle_bounded(f, path, max)
}

fn read_handle_bounded(f: File, path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(max.min(64 * 1024)));
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    f.take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| IdentityError::io("read", path, &e))?;
    if buf.len() > max {
        return Err(IdentityError::FileTooLarge {
            path: path.to_path_buf(),
            max,
        });
    }
    Ok(buf)
}

/// A fresh temp path next to `path`: `<dir>/.<name>.tmp-<16 hex>`.
fn temp_path(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut rnd = [0u8; 8];
    rand::rngs::SysRng
        .try_fill_bytes(&mut rnd)
        .map_err(|_| IdentityError::Randomness)?;
    let tmp = dir.join(format!(".{name}.tmp-{}", hex::encode(rnd)));
    Ok((dir, tmp))
}

/// Creates `tmp` (must not exist) with mode 0600, writes `bytes` and fsyncs it.
fn write_temp(tmp: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(tmp)
        .map_err(|e| IdentityError::io("create", tmp, &e))?;
    f.write_all(bytes)
        .map_err(|e| IdentityError::io("write", tmp, &e))?;
    f.sync_all().map_err(|e| IdentityError::io("sync", tmp, &e))
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Writes `bytes` to `path` atomically: a fresh 0600 temp file in the same directory,
/// fsync, rename over `path`, then fsync the directory (best effort). An existing file
/// at `path` is replaced.
pub(crate) fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let (dir, tmp) = temp_path(path)?;
    let result = write_temp(&tmp, bytes)
        .and_then(|()| fs::rename(&tmp, path).map_err(|e| IdentityError::io("rename", path, &e)));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    sync_dir(&dir);
    Ok(())
}

/// Atomically creates `path` with `bytes` (mode 0600) **only if nothing exists there**.
/// Returns `Ok(false)`, leaving the existing file untouched, if `path` already exists.
///
/// The complete file is written to a temp file first and then hard-linked into place,
/// which fails atomically if `path` exists, so two concurrent creators can never
/// overwrite each other's key and readers never see a partial file. On filesystems
/// without hard links it falls back to an existence check followed by a rename.
pub(crate) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<bool> {
    let (dir, tmp) = temp_path(path)?;
    let result = write_temp(&tmp, bytes).and_then(|()| match fs::hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) => {
            if path_exists(path)? {
                Ok(false)
            } else {
                fs::rename(&tmp, path)
                    .map(|()| true)
                    .map_err(|e| IdentityError::io("rename", path, &e))
            }
        }
    });
    // After a hard link (or a failure) the temp name must go; after a rename it is
    // already gone and this is a harmless NotFound.
    let _ = fs::remove_file(&tmp);
    if matches!(result, Ok(true)) {
        sync_dir(&dir);
    }
    result
}

/// Removes the file at `path`. `Ok(false)` if it did not exist.
pub(crate) fn remove_file(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(IdentityError::io("remove", path, &e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn write_new_never_clobbers() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k.key");
        assert!(write_new_private(&p, b"first").unwrap());
        assert!(!write_new_private(&p, b"second").unwrap());
        assert_eq!(fs::read(&p).unwrap(), b"first");
        // No temp files are left behind in either case.
        assert_eq!(entries(d.path()), vec!["k.key".to_owned()]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn write_atomic_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        write_atomic_private(&p, b"a").unwrap();
        write_atomic_private(&p, b"b").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"b");
        assert_eq!(entries(d.path()), vec!["f".to_owned()]);
    }

    #[test]
    fn read_bounds_and_private_handle_check() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        write_atomic_private(&p, b"12345").unwrap();
        assert_eq!(&**read_private_bounded(&p, 5).unwrap(), b"12345");
        assert!(matches!(
            read_private_bounded(&p, 4),
            Err(IdentityError::FileTooLarge { .. })
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(matches!(
                read_private_bounded(&p, 5),
                Err(IdentityError::InsecurePermissions { .. })
            ));
            // Following a symlink to a loose file is caught on the handle as well.
            let link = d.path().join("link");
            std::os::unix::fs::symlink(&p, &link).unwrap();
            assert!(matches!(
                read_private_bounded(&link, 5),
                Err(IdentityError::InsecurePermissions { .. })
            ));
        }
        assert!(matches!(
            read_private_bounded(d.path(), 5),
            Err(IdentityError::NotRegularFile { .. }) | Err(IdentityError::Io { .. })
        ));
    }
}
