//! The node home directory (`$PEERHARNESS_HOME`, default `~/.peerharness`) and
//! permission-safe file helpers (directories 0700, files 0600).
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::error::usage;

pub const CONFIG_FILE: &str = "config.toml";
pub const DB_FILE: &str = "peerharness.db";
pub const DAEMON_FILE: &str = "daemon.json";
pub const BUNDLES_DIR: &str = "bundles";
pub const BACKUPS_DIR: &str = "backups";

/// A resolved home directory.
#[derive(Clone, Debug)]
pub struct Home {
    root: PathBuf,
    is_default: bool,
}

impl Home {
    /// Resolves the home from `--home`/`PEERHARNESS_HOME` (already merged by clap) or the
    /// default `~/.peerharness`. Relative paths are made absolute against the current
    /// directory. Nothing is created.
    pub fn resolve(arg: Option<&Path>) -> Result<Self> {
        let default = default_home();
        let root = match arg.filter(|p| !p.as_os_str().is_empty()) {
            Some(p) => absolute(p)?,
            None => default.clone().ok_or_else(|| {
                usage("cannot find your home directory: pass --home or set PEERHARNESS_HOME")
            })?,
        };
        let is_default = default.as_deref() == Some(root.as_path());
        Ok(Self { root, is_default })
    }

    #[cfg(test)]
    // A constructor for tests of commands that are not written yet.
    #[allow(dead_code)]
    pub fn for_tests(root: PathBuf) -> Self {
        Self {
            root,
            is_default: false,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether this is the default home (hook commands then omit `PEERHARNESS_HOME`).
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    pub fn db_path(&self) -> PathBuf {
        self.root.join(DB_FILE)
    }

    pub fn daemon_file(&self) -> PathBuf {
        self.root.join(DAEMON_FILE)
    }

    pub fn bundles_dir(&self) -> PathBuf {
        self.root.join(BUNDLES_DIR)
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.root.join(BACKUPS_DIR)
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.root.join(ph_identity::keystore::KEYS_DIR)
    }

    pub fn spool_path(&self) -> PathBuf {
        ph_observer::spool::spool_path(&self.root)
    }

    /// Both config.toml and the database exist.
    pub fn is_initialized(&self) -> bool {
        self.config_path().is_file() && self.db_path().is_file()
    }

    /// Creates the home directory (0700) if needed.
    pub fn ensure(&self) -> Result<()> {
        ensure_private_dir(&self.root)
    }
}

/// `~/.peerharness`, if a home directory is known.
pub fn default_home() -> Option<PathBuf> {
    user_home().map(|h| h.join(".peerharness"))
}

/// The user's home directory from `$HOME` (or `%USERPROFILE%`).
pub fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// `p` made absolute against the current directory (no symlink resolution).
pub fn absolute(p: &Path) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("cannot read the current directory")?
            .join(p))
    }
}

/// Creates `dir` and missing parents; a newly created final directory gets mode 0700.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .with_context(|| format!("cannot create directory {}", dir.display()))?;
    set_mode(dir, 0o700)?;
    Ok(())
}

/// Sets unix permission bits (no-op elsewhere).
pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("cannot set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// The unix permission bits of `path` (None elsewhere or if unreadable).
pub fn mode_of(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Atomically writes `contents` to `path` with mode 0600: a temp file in the same
/// directory, fsync, then rename. An existing file is replaced.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let mut suffix = [0u8; 8];
    getrandom_fill(&mut suffix)?;
    let tmp = dir.join(format!(".{name}.tmp-{}", hex::encode(suffix)));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        f.write_all(contents)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        f.sync_all().context("cannot flush file")?;
        drop(f);
        set_mode(&tmp, 0o600)?;
        fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Reads a regular file of at most `max` bytes (symlinks are followed only if the target
/// is a regular file).
pub fn read_bounded_file(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_file() {
        return Err(usage(format!("{} is not a regular file", path.display())));
    }
    if meta.len() > max {
        return Err(usage(format!(
            "{} is too large (more than {max} bytes)",
            path.display()
        )));
    }
    let f = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut buf = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if buf.len() as u64 > max {
        return Err(usage(format!(
            "{} is too large (more than {max} bytes)",
            path.display()
        )));
    }
    Ok(buf)
}

/// Fills `buf` from the OS random number generator.
pub fn getrandom_fill(buf: &mut [u8]) -> Result<()> {
    use rand::TryRng;
    rand::rngs::SysRng
        .try_fill_bytes(buf)
        .map_err(|_| anyhow::anyhow!("operating system random number generator failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_and_dirs() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("a/b");
        ensure_private_dir(&d).unwrap();
        #[cfg(unix)]
        assert_eq!(mode_of(&d), Some(0o700));
        let f = d.join("x.toml");
        write_private_file(&f, b"one").unwrap();
        write_private_file(&f, b"two").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"two");
        #[cfg(unix)]
        assert_eq!(mode_of(&f), Some(0o600));
        assert_eq!(read_bounded_file(&f, 3).unwrap(), b"two");
        assert!(read_bounded_file(&f, 2).is_err());
        assert!(read_bounded_file(&d, 2).is_err());
        // no temp files left behind
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
    }

    #[test]
    fn resolve_relative() {
        let h = Home::resolve(Some(Path::new("rel/home"))).unwrap();
        assert!(h.root().is_absolute());
        assert!(!h.is_default());
    }
}
