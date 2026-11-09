//! Immutable, content-addressed bundle store: `<home>/bundles/<hex-digest>/SKILL.md`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ph_core::Digest;

use crate::bundle::{validate_received, Bundle, SKILL_FILE_NAME};
use crate::error::{BundleError, StoreError};
use crate::fsutil::{
    fsync_dir, kind_of, random_suffix, read_regular_bounded, write_new_synced, Kind, ReadError,
};
use crate::validate::MAX_SKILL_FILE_BYTES;

const STAGING_PREFIX: &str = ".staging-";

/// Result of [`BundleStore::put`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutOutcome {
    /// `root/<hex>/SKILL.md`.
    pub path: PathBuf,
    /// `false` when an identical bundle was already stored (idempotent no-op).
    pub newly_stored: bool,
}

/// The local bundle store.
///
/// * [`put`](Self::put) writes `root/<hex>/SKILL.md` atomically (staged in
///   `root/.staging-<random>`, fsynced, then renamed) and never overwrites: if the
///   directory exists it must already verify to the same digest, otherwise the put
///   fails. The stored file is made read-only.
/// * [`get`](Self::get) re-verifies on every read: the directory and file must not be
///   symlinks, the directory must contain only `SKILL.md`, and the content must hash to
///   the requested digest and pass full bundle validation.
#[derive(Clone, Debug)]
pub struct BundleStore {
    root: PathBuf,
}

fn io_err(op: &'static str) -> impl FnOnce(io::Error) -> StoreError {
    move |source| StoreError::Io { op, source }
}

impl BundleStore {
    /// A store rooted at `root` (normally `$PEERHARNESS_HOME/bundles`). Nothing is
    /// created until the first [`put`](Self::put).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `root/<hex>`.
    pub fn dir_for(&self, digest: &Digest) -> PathBuf {
        self.root.join(digest.to_hex())
    }

    /// `root/<hex>/SKILL.md`.
    pub fn path_for(&self, digest: &Digest) -> PathBuf {
        self.dir_for(digest).join(SKILL_FILE_NAME)
    }

    /// `<hex>/SKILL.md`, the path relative to the store root (the `bundles.rel_path`
    /// column stores `bundles/` + this, relative to the home directory).
    pub fn relative_path(digest: &Digest) -> String {
        format!("{}/{}", digest.to_hex(), SKILL_FILE_NAME)
    }

    /// Whether a directory for `digest` exists (no verification; use
    /// [`get`](Self::get) to verify).
    pub fn contains(&self, digest: &Digest) -> bool {
        matches!(kind_of(&self.dir_for(digest)), Ok(Kind::Dir))
    }

    /// Stores `bundle` (idempotent).
    pub fn put(&self, bundle: &Bundle) -> Result<PutOutcome, StoreError> {
        let digest = bundle.digest();
        let dir = self.dir_for(&digest);
        let path = dir.join(SKILL_FILE_NAME);
        fs::create_dir_all(&self.root).map_err(io_err("create store root"))?;
        match kind_of(&dir).map_err(io_err("inspect bundle directory"))? {
            Kind::Missing => {}
            Kind::Symlink => return Err(StoreError::Symlink),
            Kind::Dir => {
                self.get(&digest)?;
                return Ok(PutOutcome {
                    path,
                    newly_stored: false,
                });
            }
            Kind::File | Kind::Other => return Err(StoreError::NotRegular),
        }

        let suffix = random_suffix().ok_or(StoreError::Randomness)?;
        let staging = self.root.join(format!("{STAGING_PREFIX}{suffix}"));
        fs::create_dir(&staging).map_err(io_err("create staging directory"))?;
        let result = (|| {
            let file = staging.join(SKILL_FILE_NAME);
            write_new_synced(&file, bundle.skill_md_bytes()).map_err(io_err("write bundle"))?;
            let mut perms = fs::metadata(&file)
                .map_err(io_err("read bundle permissions"))?
                .permissions();
            perms.set_readonly(true);
            fs::set_permissions(&file, perms).map_err(io_err("make bundle read-only"))?;
            fsync_dir(&staging).map_err(io_err("sync staging directory"))?;
            fs::rename(&staging, &dir).map_err(io_err("rename bundle into place"))
        })();
        match result {
            Ok(()) => {
                // Stored; a failed directory fsync must not report the put as failed.
                if fsync_dir(&self.root).is_err() {
                    tracing::warn!("could not fsync the bundle store root after a put");
                }
                tracing::debug!(digest = %digest, "bundle stored");
                Ok(PutOutcome {
                    path,
                    newly_stored: true,
                })
            }
            Err(e) => {
                let _ = fs::remove_dir_all(&staging);
                // A concurrent writer may have stored the same content first.
                if self.get(&digest).is_ok() {
                    return Ok(PutOutcome {
                        path,
                        newly_stored: false,
                    });
                }
                Err(e)
            }
        }
    }

    /// Reads and fully re-verifies the bundle with `digest`.
    pub fn get(&self, digest: &Digest) -> Result<Bundle, StoreError> {
        let dir = self.dir_for(digest);
        match kind_of(&dir).map_err(io_err("inspect bundle directory"))? {
            Kind::Missing => return Err(StoreError::NotFound),
            Kind::Symlink => return Err(StoreError::Symlink),
            Kind::Dir => {}
            Kind::File | Kind::Other => return Err(StoreError::NotRegular),
        }
        for entry in fs::read_dir(&dir).map_err(io_err("list bundle directory"))? {
            let entry = entry.map_err(io_err("list bundle directory"))?;
            if entry.file_name().to_str() != Some(SKILL_FILE_NAME) {
                return Err(StoreError::UnexpectedEntry);
            }
        }
        let bytes = match read_regular_bounded(&dir.join(SKILL_FILE_NAME), MAX_SKILL_FILE_BYTES) {
            Ok(b) => b,
            Err(ReadError::Missing) => return Err(StoreError::Corrupt(BundleError::Empty)),
            Err(ReadError::Symlink) => return Err(StoreError::Symlink),
            Err(ReadError::NotRegular) => return Err(StoreError::NotRegular),
            Err(ReadError::TooLarge) => {
                return Err(StoreError::Corrupt(BundleError::TooLarge {
                    size: MAX_SKILL_FILE_BYTES + 1,
                    max: MAX_SKILL_FILE_BYTES,
                }))
            }
            Err(ReadError::Io(e)) => {
                return Err(StoreError::Io {
                    op: "read bundle",
                    source: e,
                })
            }
        };
        validate_received(vec![(SKILL_FILE_NAME.to_owned(), bytes)], digest, None)
            .map_err(StoreError::Corrupt)
    }

    /// Digests of all directories in the store whose name is a digest (unverified),
    /// sorted. Staging directories and other entries are ignored. A missing root is an
    /// empty store.
    pub fn list(&self) -> Result<Vec<Digest>, StoreError> {
        let rd = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(StoreError::Io {
                    op: "list store",
                    source: e,
                })
            }
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(io_err("list store"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                if let Ok(d) = format!("sha256:{name}").parse::<Digest>() {
                    out.push(d);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Removes leftover `root/.staging-*` directories from interrupted puts. Returns how
    /// many were removed. Must not run concurrently with a [`put`](Self::put) into the
    /// same store (it could remove that put's staging directory).
    pub fn cleanup_staging(&self) -> Result<usize, StoreError> {
        let rd = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(StoreError::Io {
                    op: "list store",
                    source: e,
                })
            }
        };
        let mut n = 0;
        for entry in rd {
            let entry = entry.map_err(io_err("list store"))?;
            let is_staging = entry
                .file_name()
                .to_str()
                .is_some_and(|s| s.starts_with(STAGING_PREFIX));
            if is_staging && kind_of(&entry.path()).ok() == Some(Kind::Dir) {
                fs::remove_dir_all(entry.path()).map_err(io_err("remove staging directory"))?;
                n += 1;
            }
        }
        Ok(n)
    }
}
