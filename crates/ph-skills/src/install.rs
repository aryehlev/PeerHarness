//! Atomic installation of bundles into an agent's native skills directory.
//!
//! Layout: `<target_root>/<name>/SKILL.md` plus `<target_root>/<name>/.peerharness-managed.json`:
//!
//! ```json
//! {"bundle_digest":"sha256:…","installed_at":"2026-11-09T18:10:00Z","schema":"peerharness.install/0.1","skill_name":"…"}
//! ```
//!
//! # Safety rules
//!
//! * The new directory is staged in `<target_root>/.peerharness-staging-<random>`, both
//!   files are fsynced, and the directory is renamed into place. When an existing managed
//!   directory is replaced, it is first renamed aside, the new one is renamed in, and only
//!   then is the old one deleted. A failure before the final rename leaves the previous
//!   installation untouched (the aside directory is renamed back).
//! * A directory without a valid marker is *unmanaged*: it is never replaced unless
//!   [`InstallOptions::force_overwrite_unmanaged`] is set. A managed directory holding
//!   extra files the user added counts as unmanaged for replacement.
//! * A managed `SKILL.md` whose content no longer matches the recorded digest is
//!   *modified*: it is never replaced (or uninstalled) unless `allow_modified` is set.
//! * Symlinks at `<target_root>/<name>`, its `SKILL.md` or the marker are always refused.
//!   The target root itself may be a symlink (dotfile managers commonly symlink
//!   `~/.claude`), unless the installer is confined with [`Installer::confine_to`]: then
//!   every existing path component between the base and the target root must be a real
//!   directory. Use that for [`SkillScope::Project`], where `<project>/.claude` comes from
//!   an untrusted repository and could be a symlink to anywhere ([`claude_installer`]
//!   does this automatically).
//! * Uninstall removes only `SKILL.md` and the marker, and removes the directory only
//!   when it is then empty. It never deletes unknown files.
//! * When a replaced directory contained files PeerHarness did not write (forced
//!   unmanaged overwrite, user-added files or user modifications), it is moved into the
//!   backup directory if one is configured ([`Installer::with_backup_dir`]); otherwise it
//!   is deleted.
//!
//! * Leftover cleanup ([`Installer::cleanup_leftovers`]) must not run concurrently with
//!   an install into the same target root.
//!
//! Rollback is "install the previous digest again": read `previous_digest` from
//! [`InstallOutcome`] (or the `installations` table), fetch it with
//! [`crate::BundleStore::get`] and [`Installer::install`] it.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use ph_core::{is_valid_skill_name, Clock, Digest, SystemClock, Timestamp};
use ph_protocol::jcs::{self, ParseLimits};
use serde::{Deserialize, Serialize};

use crate::bundle::{digest_for_skill_md, Bundle, SKILL_FILE_NAME};
use crate::error::InstallError;
use crate::fsutil::{
    fsync_dir, kind_of, random_suffix, read_regular_bounded, write_new_synced, Kind, ReadError,
};
use crate::validate::MAX_SKILL_FILE_BYTES;

/// Marker file name, next to `SKILL.md`.
pub const MARKER_FILE_NAME: &str = ".peerharness-managed.json";
/// Marker `schema` value.
pub const INSTALL_SCHEMA: &str = "peerharness.install/0.1";
/// Environment variable that overrides the Claude skills directory for every scope.
pub const CLAUDE_SKILLS_DIR_ENV: &str = "PEERHARNESS_CLAUDE_SKILLS_DIR";
/// Prefix of staging directories inside the target root.
pub const STAGING_PREFIX: &str = ".peerharness-staging-";
/// Prefix of directories moved aside during a replacement.
pub const ASIDE_PREFIX: &str = ".peerharness-old-";
const MAX_MARKER_BYTES: usize = 4096;

/// Where a Claude Code skill is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SkillScope {
    /// `~/.claude/skills`.
    User,
    /// `<project_root>/.claude/skills`.
    Project,
}

impl SkillScope {
    /// `user` or `project` (the `installations.install_scope` value).
    pub const fn as_str(self) -> &'static str {
        match self {
            SkillScope::User => "user",
            SkillScope::Project => "project",
        }
    }
}

impl std::fmt::Display for SkillScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SkillScope {
    type Err = ph_core::ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(SkillScope::User),
            "project" => Ok(SkillScope::Project),
            _ => Err(ph_core::ParseError::new(
                "skill scope",
                "expected user or project",
            )),
        }
    }
}

/// The Claude Code skills directory for `scope`, reading [`CLAUDE_SKILLS_DIR_ENV`] and
/// `$HOME` (falling back to `%USERPROFILE%`) from the environment. See
/// [`resolve_claude_skills_dir`].
pub fn claude_skills_dir(scope: SkillScope, project_root: &Path) -> Result<PathBuf, InstallError> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    resolve_claude_skills_dir(
        scope,
        project_root,
        std::env::var_os(CLAUDE_SKILLS_DIR_ENV).as_deref(),
        home.as_deref(),
    )
}

/// The installer the CLI should use for Claude Code: rooted at
/// [`claude_skills_dir`]`(scope, project_root)` and, for [`SkillScope::Project`] without
/// the [`CLAUDE_SKILLS_DIR_ENV`] override, [confined](Installer::confine_to) to
/// `project_root` so a symlinked `<project>/.claude` or `.claude/skills` from an
/// untrusted repository is refused ([`InstallError::UnsafeRoot`]).
pub fn claude_installer(scope: SkillScope, project_root: &Path) -> Result<Installer, InstallError> {
    let overridden = std::env::var_os(CLAUDE_SKILLS_DIR_ENV).is_some_and(|o| !o.is_empty());
    let installer = Installer::new(claude_skills_dir(scope, project_root)?);
    Ok(match scope {
        SkillScope::Project if !overridden => installer.confine_to(project_root),
        _ => installer,
    })
}

/// Pure resolution of the Claude Code skills directory:
///
/// 1. a non-empty `override_dir` wins for both scopes (used verbatim);
/// 2. [`SkillScope::User`] → `<home>/.claude/skills` ([`InstallError::HomeNotSet`] when
///    `home` is `None` or empty);
/// 3. [`SkillScope::Project`] → `<project_root>/.claude/skills`.
pub fn resolve_claude_skills_dir(
    scope: SkillScope,
    project_root: &Path,
    override_dir: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, InstallError> {
    if let Some(o) = override_dir.filter(|o| !o.is_empty()) {
        return Ok(PathBuf::from(o));
    }
    match scope {
        SkillScope::User => {
            let home = home
                .filter(|h| !h.is_empty())
                .ok_or(InstallError::HomeNotSet)?;
            Ok(Path::new(home).join(".claude").join("skills"))
        }
        SkillScope::Project => Ok(project_root.join(".claude").join("skills")),
    }
}

/// Options for [`Installer::install`]. The default refuses everything risky.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallOptions {
    /// Replace an existing directory that PeerHarness does not manage (or a managed one
    /// with extra files). CLI: `--force-overwrite-unmanaged`.
    pub force_overwrite_unmanaged: bool,
    /// Replace a managed SKILL.md that the user modified after installation.
    pub allow_modified: bool,
}

/// Options for [`Installer::uninstall`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UninstallOptions {
    /// Remove a managed SKILL.md even though the user modified it.
    pub allow_modified: bool,
}

/// Result of a successful [`Installer::install`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallOutcome {
    /// The skill directory `<target_root>/<name>` (the `installations.path` value).
    pub path: PathBuf,
    /// Digest recorded in the marker of the managed installation that was replaced (or
    /// that is unchanged); `None` for a fresh install or a forced unmanaged overwrite.
    pub previous_digest: Option<Digest>,
    /// Whether an existing directory was replaced.
    pub replaced: bool,
    /// `true` when exactly this bundle was already installed and unmodified; nothing
    /// was written.
    pub unchanged: bool,
    /// Where the replaced directory was moved, when it was kept as a backup.
    pub backup_path: Option<PathBuf>,
}

/// Result of a successful [`Installer::uninstall`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallOutcome {
    /// The skill directory.
    pub path: PathBuf,
    /// The digest recorded in the removed marker.
    pub removed_digest: Digest,
    /// Whether the directory itself was removed (only when it became empty).
    pub dir_removed: bool,
    /// Whether the removed SKILL.md had been modified by the user.
    pub was_modified: bool,
}

/// Installation state of one skill name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallState {
    /// No directory with this name.
    NotInstalled,
    /// Installed by PeerHarness. `modified` is true when `SKILL.md` no longer matches
    /// `digest` (edited, missing or unreadable).
    Managed {
        /// The digest recorded in the marker.
        digest: Digest,
        /// Whether the user changed it.
        modified: bool,
    },
    /// Something PeerHarness does not manage: a directory without a valid marker, a
    /// symlink or a non-directory.
    Unmanaged,
}

/// The marker written next to an installed `SKILL.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallMarker {
    /// Always [`INSTALL_SCHEMA`].
    pub schema: String,
    /// The skill name (equals the directory name).
    pub skill_name: String,
    /// The installed bundle digest.
    pub bundle_digest: Digest,
    /// When it was installed.
    pub installed_at: Timestamp,
}

impl InstallMarker {
    /// Canonical JSON (JCS) plus a trailing newline.
    pub fn to_bytes(&self) -> Result<Vec<u8>, InstallError> {
        let mut s = jcs::to_canonical_string(self).map_err(|_| InstallError::Marker)?;
        s.push('\n');
        Ok(s.into_bytes())
    }

    /// Strictly parses a marker (no duplicate keys, no unknown fields, correct schema).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let v = jcs::parse_strict(
            bytes,
            ParseLimits {
                max_bytes: MAX_MARKER_BYTES,
                max_depth: 2,
            },
        )
        .ok()?;
        let m: InstallMarker = serde_json::from_value(v).ok()?;
        (m.schema == INSTALL_SCHEMA).then_some(m)
    }
}

/// Fault points for atomicity tests. Not for production use.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    /// After `SKILL.md` was written to staging, before the marker.
    AfterStagingSkillFile,
    /// After staging is complete, before any rename.
    BeforeSwap,
    /// After the old directory was moved aside, before the new one is renamed in.
    AfterMoveAside,
}

enum Existing {
    None,
    Managed {
        marker: InstallMarker,
        modified: bool,
        extra_entries: bool,
    },
    Unmanaged,
}

/// Installs, inspects and removes skills under one target root (for example
/// `~/.claude/skills`).
#[derive(Clone)]
pub struct Installer {
    root: PathBuf,
    confine: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    clock: Arc<dyn Clock>,
    fault: Option<FaultPoint>,
}

impl std::fmt::Debug for Installer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installer")
            .field("root", &self.root)
            .field("confine", &self.confine)
            .field("backup_dir", &self.backup_dir)
            .finish_non_exhaustive()
    }
}

fn io_err(op: &'static str) -> impl FnOnce(io::Error) -> InstallError {
    move |source| InstallError::Io { op, source }
}

impl Installer {
    /// An installer for `target_root` (created on the first install).
    pub fn new(target_root: impl Into<PathBuf>) -> Self {
        Self {
            root: target_root.into(),
            confine: None,
            backup_dir: None,
            clock: Arc::new(SystemClock),
            fault: None,
        }
    }

    /// Keep replaced directories that held non-PeerHarness content under `dir` (for
    /// example `$PEERHARNESS_HOME/backups/skills`) instead of deleting them. `dir` must be
    /// on the same filesystem as the target root; otherwise the install fails cleanly
    /// before anything is changed.
    pub fn with_backup_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.backup_dir = Some(dir.into());
        self
    }

    /// Confine the target root to `base`: `target_root` must be `base` or below it, and
    /// every existing path component after `base` must be a real directory (not a
    /// symlink, not a file). Checked by [`install`](Self::install),
    /// [`uninstall`](Self::uninstall) and [`cleanup_leftovers`](Self::cleanup_leftovers);
    /// violations give [`InstallError::UnsafeRoot`]. `base` itself may be a symlink.
    ///
    /// Use it for [`SkillScope::Project`] with `base = project_root`.
    pub fn confine_to(mut self, base: impl Into<PathBuf>) -> Self {
        self.confine = Some(base.into());
        self
    }

    /// Use `clock` for `installed_at` (tests).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Testing only: fail at `point` during the next installs.
    #[doc(hidden)]
    pub fn inject_fault(&mut self, point: Option<FaultPoint>) {
        self.fault = point;
    }

    /// The target root.
    pub fn target_root(&self) -> &Path {
        &self.root
    }

    /// `<target_root>/<name>`, after validating `name` (which also rules out traversal).
    pub fn skill_dir(&self, name: &str) -> Result<PathBuf, InstallError> {
        if !is_valid_skill_name(name) {
            return Err(InstallError::InvalidName);
        }
        Ok(self.root.join(name))
    }

    /// Enforces [`confine_to`](Self::confine_to).
    fn check_root(&self) -> Result<(), InstallError> {
        let Some(base) = &self.confine else {
            return Ok(());
        };
        let rel = self
            .root
            .strip_prefix(base)
            .map_err(|_| InstallError::UnsafeRoot)?;
        let mut cur = base.clone();
        for comp in rel.components() {
            match comp {
                Component::Normal(c) => cur.push(c),
                Component::CurDir => continue,
                _ => return Err(InstallError::UnsafeRoot),
            }
            match kind_of(&cur).map_err(io_err("inspect skills directory"))? {
                Kind::Dir => {}
                // The rest is created by `create_dir_all` as real directories.
                Kind::Missing => break,
                Kind::Symlink | Kind::File | Kind::Other => return Err(InstallError::UnsafeRoot),
            }
        }
        Ok(())
    }

    fn fault(&self, p: FaultPoint) -> Result<(), InstallError> {
        if self.fault == Some(p) {
            Err(InstallError::InjectedFault)
        } else {
            Ok(())
        }
    }

    fn inspect(&self, name: &str, dir: &Path) -> Result<Existing, InstallError> {
        match kind_of(dir).map_err(io_err("inspect skill directory"))? {
            Kind::Missing => return Ok(Existing::None),
            Kind::Symlink => return Err(InstallError::Symlink),
            Kind::File | Kind::Other => return Err(InstallError::NotRegular),
            Kind::Dir => {}
        }
        let marker = match read_regular_bounded(&dir.join(MARKER_FILE_NAME), MAX_MARKER_BYTES) {
            Ok(b) => match InstallMarker::from_bytes(&b) {
                Some(m) if m.skill_name == name => m,
                _ => return Ok(Existing::Unmanaged),
            },
            Err(ReadError::Missing) | Err(ReadError::TooLarge) => return Ok(Existing::Unmanaged),
            Err(ReadError::Symlink) => return Err(InstallError::Symlink),
            Err(ReadError::NotRegular) => return Err(InstallError::NotRegular),
            Err(ReadError::Io(e)) => {
                return Err(InstallError::Io {
                    op: "read marker",
                    source: e,
                })
            }
        };
        let modified = match read_regular_bounded(&dir.join(SKILL_FILE_NAME), MAX_SKILL_FILE_BYTES)
        {
            Ok(b) => digest_for_skill_md(&b).map_or(true, |d| d != marker.bundle_digest),
            Err(ReadError::Missing) | Err(ReadError::TooLarge) => true,
            Err(ReadError::Symlink) => return Err(InstallError::Symlink),
            Err(ReadError::NotRegular) => return Err(InstallError::NotRegular),
            Err(ReadError::Io(e)) => {
                return Err(InstallError::Io {
                    op: "read installed skill",
                    source: e,
                })
            }
        };
        let mut extra_entries = false;
        for entry in fs::read_dir(dir).map_err(io_err("list skill directory"))? {
            let entry = entry.map_err(io_err("list skill directory"))?;
            let n = entry.file_name();
            if n != OsStr::new(SKILL_FILE_NAME) && n != OsStr::new(MARKER_FILE_NAME) {
                extra_entries = true;
            }
        }
        Ok(Existing::Managed {
            marker,
            modified,
            extra_entries,
        })
    }

    /// The installation state of `name`. Symlinks and non-directories are reported as
    /// [`InstallState::Unmanaged`].
    pub fn status(&self, name: &str) -> Result<InstallState, InstallError> {
        let dir = self.skill_dir(name)?;
        match self.inspect(name, &dir) {
            Ok(Existing::None) => Ok(InstallState::NotInstalled),
            Ok(Existing::Managed {
                marker, modified, ..
            }) => Ok(InstallState::Managed {
                digest: marker.bundle_digest,
                modified,
            }),
            Ok(Existing::Unmanaged)
            | Err(InstallError::Symlink)
            | Err(InstallError::NotRegular) => Ok(InstallState::Unmanaged),
            Err(e) => Err(e),
        }
    }

    /// The state of every entry under the target root whose name is a valid skill name,
    /// sorted by name. A missing root yields an empty list.
    pub fn list(&self) -> Result<Vec<(String, InstallState)>, InstallError> {
        let rd = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(InstallError::Io {
                    op: "list skills",
                    source: e,
                })
            }
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(io_err("list skills"))?;
            if let Some(name) = entry.file_name().to_str() {
                if is_valid_skill_name(name) {
                    out.push((name.to_owned(), self.status(name)?));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Installs `bundle` as `<target_root>/<name>/SKILL.md` (see the module docs for the
    /// rules). Reinstalling the identical, unmodified bundle is a no-op
    /// (`unchanged == true`).
    pub fn install(
        &self,
        bundle: &Bundle,
        opts: InstallOptions,
    ) -> Result<InstallOutcome, InstallError> {
        let name = bundle.name();
        let dir = self.skill_dir(name)?;
        self.check_root()?;
        fs::create_dir_all(&self.root).map_err(io_err("create skills directory"))?;
        self.check_root()?;

        let (previous_digest, keep_old) = match self.inspect(name, &dir)? {
            Existing::None => (None, None),
            Existing::Managed {
                marker,
                modified,
                extra_entries,
            } => {
                if modified && !opts.allow_modified {
                    return Err(InstallError::Modified);
                }
                if extra_entries && !opts.force_overwrite_unmanaged {
                    return Err(InstallError::Unmanaged);
                }
                if !modified && !extra_entries && marker.bundle_digest == bundle.digest() {
                    return Ok(InstallOutcome {
                        path: dir,
                        previous_digest: Some(marker.bundle_digest),
                        replaced: false,
                        unchanged: true,
                        backup_path: None,
                    });
                }
                // Old content is entirely ours unless modified or extended by the user.
                (Some(marker.bundle_digest), Some(modified || extra_entries))
            }
            Existing::Unmanaged => {
                if !opts.force_overwrite_unmanaged {
                    return Err(InstallError::Unmanaged);
                }
                (None, Some(true))
            }
        };

        let marker = InstallMarker {
            schema: INSTALL_SCHEMA.to_owned(),
            skill_name: name.to_owned(),
            bundle_digest: bundle.digest(),
            installed_at: self.clock.now(),
        };
        let marker_bytes = marker.to_bytes()?;

        let suffix = random_suffix().ok_or(InstallError::Randomness)?;
        let staging = self.root.join(format!("{STAGING_PREFIX}{suffix}"));
        fs::create_dir(&staging).map_err(io_err("create staging directory"))?;
        let staged = (|| {
            write_new_synced(&staging.join(SKILL_FILE_NAME), bundle.skill_md_bytes())
                .map_err(io_err("write SKILL.md"))?;
            self.fault(FaultPoint::AfterStagingSkillFile)?;
            write_new_synced(&staging.join(MARKER_FILE_NAME), &marker_bytes)
                .map_err(io_err("write marker"))?;
            fsync_dir(&staging).map_err(io_err("sync staging directory"))?;
            self.fault(FaultPoint::BeforeSwap)
        })();
        if let Err(e) = staged {
            remove_staging(&staging);
            return Err(e);
        }

        let Some(user_content) = keep_old else {
            if let Err(e) = fs::rename(&staging, &dir) {
                remove_staging(&staging);
                return Err(InstallError::Io {
                    op: "rename skill into place",
                    source: e,
                });
            }
            sync_after_commit(&self.root);
            tracing::info!(digest = %bundle.digest(), "skill installed");
            return Ok(InstallOutcome {
                path: dir,
                previous_digest,
                replaced: false,
                unchanged: false,
                backup_path: None,
            });
        };

        // Replace: move the old directory aside (or into the backup dir), swap in the new.
        let backup = match (&self.backup_dir, user_content) {
            (Some(b), true) => {
                if let Err(e) = fs::create_dir_all(b) {
                    remove_staging(&staging);
                    return Err(InstallError::Io {
                        op: "create backup directory",
                        source: e,
                    });
                }
                Some(b.join(format!(
                    "{name}-{}-{suffix}",
                    marker.installed_at.unix_seconds()
                )))
            }
            _ => None,
        };
        let aside = backup
            .clone()
            .unwrap_or_else(|| self.root.join(format!("{ASIDE_PREFIX}{suffix}")));
        if let Err(e) = fs::rename(&dir, &aside) {
            remove_staging(&staging);
            return Err(InstallError::Io {
                op: "move existing skill aside",
                source: e,
            });
        }
        let swap = self
            .fault(FaultPoint::AfterMoveAside)
            .and_then(|()| fs::rename(&staging, &dir).map_err(io_err("rename skill into place")));
        if let Err(e) = swap {
            // Roll back: put the old directory back where it was.
            if fs::rename(&aside, &dir).is_err() {
                tracing::error!(
                    "failed to restore previous skill directory after a failed install"
                );
            }
            remove_staging(&staging);
            return Err(e);
        }
        // The new version is in place: from here on nothing may fail the install.
        sync_after_commit(&self.root);

        if backup.is_none() {
            // Never delete through a symlink, even if one was swapped in concurrently.
            let removed = match kind_of(&aside) {
                Ok(Kind::Dir) if user_content => fs::remove_dir_all(&aside),
                Ok(Kind::Dir) => remove_managed_files(&aside).and_then(|()| fs::remove_dir(&aside)),
                _ => Err(io::Error::other(
                    "replaced skill directory is not a directory",
                )),
            };
            if removed.is_err() {
                tracing::warn!("could not remove the replaced skill directory; it was left under a .peerharness-old- name");
            }
        }
        tracing::info!(digest = %bundle.digest(), "skill replaced");
        Ok(InstallOutcome {
            path: dir,
            previous_digest,
            replaced: true,
            unchanged: false,
            backup_path: backup,
        })
    }

    /// Uninstalls a managed skill: removes `SKILL.md` and the marker, then the directory
    /// if it is empty. Refuses unmanaged directories, symlinks, and (unless
    /// `opts.allow_modified`) user-modified files.
    pub fn uninstall(
        &self,
        name: &str,
        opts: UninstallOptions,
    ) -> Result<UninstallOutcome, InstallError> {
        let dir = self.skill_dir(name)?;
        self.check_root()?;
        let (marker, modified) = match self.inspect(name, &dir)? {
            Existing::None => return Err(InstallError::NotInstalled),
            Existing::Unmanaged => return Err(InstallError::Unmanaged),
            Existing::Managed {
                marker, modified, ..
            } => (marker, modified),
        };
        if modified && !opts.allow_modified {
            return Err(InstallError::Modified);
        }
        remove_managed_files(&dir).map_err(io_err("remove managed files"))?;
        sync_after_commit(&dir);
        let dir_removed = fs::remove_dir(&dir).is_ok();
        sync_after_commit(&self.root);
        tracing::info!(digest = %marker.bundle_digest, dir_removed, "skill uninstalled");
        Ok(UninstallOutcome {
            path: dir,
            removed_digest: marker.bundle_digest,
            dir_removed,
            was_modified: modified,
        })
    }

    /// Removes leftover staging and aside directories (`.peerharness-staging-*`,
    /// `.peerharness-old-*`) from interrupted installs. Returns how many were removed.
    pub fn cleanup_leftovers(&self) -> Result<usize, InstallError> {
        self.check_root()?;
        let rd = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(InstallError::Io {
                    op: "list skills",
                    source: e,
                })
            }
        };
        let mut n = 0;
        for entry in rd {
            let entry = entry.map_err(io_err("list skills"))?;
            let ours = entry
                .file_name()
                .to_str()
                .is_some_and(|s| s.starts_with(STAGING_PREFIX) || s.starts_with(ASIDE_PREFIX));
            if ours && kind_of(&entry.path()).ok() == Some(Kind::Dir) {
                fs::remove_dir_all(entry.path()).map_err(io_err("remove leftover directory"))?;
                n += 1;
            }
        }
        Ok(n)
    }
}

/// Removes `SKILL.md` then the marker (marker last, so an interrupted uninstall still
/// looks managed). Missing files are fine.
fn remove_managed_files(dir: &Path) -> io::Result<()> {
    for f in [SKILL_FILE_NAME, MARKER_FILE_NAME] {
        match fs::remove_file(dir.join(f)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Fsyncs a directory after a change that already happened; a failure is only logged,
/// because reporting an error would make the caller believe nothing changed.
fn sync_after_commit(dir: &Path) {
    if fsync_dir(dir).is_err() {
        tracing::warn!("could not fsync a skills directory after a change");
    }
}

fn remove_staging(staging: &Path) {
    if fs::remove_dir_all(staging).is_err() {
        tracing::warn!("could not remove a staging directory");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dirs() {
        let p = Path::new("/proj");
        assert_eq!(
            resolve_claude_skills_dir(SkillScope::User, p, None, Some(OsStr::new("/home/u")))
                .unwrap(),
            PathBuf::from("/home/u/.claude/skills")
        );
        assert_eq!(
            resolve_claude_skills_dir(SkillScope::Project, p, None, None).unwrap(),
            PathBuf::from("/proj/.claude/skills")
        );
        assert_eq!(
            resolve_claude_skills_dir(SkillScope::User, p, Some(OsStr::new("/o")), None).unwrap(),
            PathBuf::from("/o")
        );
        assert_eq!(
            resolve_claude_skills_dir(SkillScope::Project, p, Some(OsStr::new("/o")), None)
                .unwrap(),
            PathBuf::from("/o")
        );
        assert_eq!(
            resolve_claude_skills_dir(SkillScope::Project, p, Some(OsStr::new("")), None).unwrap(),
            PathBuf::from("/proj/.claude/skills")
        );
        assert!(matches!(
            resolve_claude_skills_dir(SkillScope::User, p, None, None),
            Err(InstallError::HomeNotSet)
        ));
        assert!(matches!(
            resolve_claude_skills_dir(SkillScope::User, p, None, Some(OsStr::new(""))),
            Err(InstallError::HomeNotSet)
        ));
        assert_eq!("user".parse::<SkillScope>().unwrap(), SkillScope::User);
        assert_eq!(SkillScope::Project.to_string(), "project");
        assert!("x".parse::<SkillScope>().is_err());
    }

    #[test]
    fn marker_roundtrip_and_strictness() {
        let m = InstallMarker {
            schema: INSTALL_SCHEMA.into(),
            skill_name: "a".into(),
            bundle_digest: Digest::sha256(b"x"),
            installed_at: "2026-11-09T18:10:00Z".parse().unwrap(),
        };
        let b = m.to_bytes().unwrap();
        let s = std::str::from_utf8(&b).unwrap();
        assert!(s.starts_with("{\"bundle_digest\":\"sha256:"), "{s}");
        assert!(s.ends_with("\"schema\":\"peerharness.install/0.1\",\"skill_name\":\"a\"}\n"));
        assert_eq!(InstallMarker::from_bytes(&b), Some(m.clone()));
        let dup = s.replace("{\"bundle", "{\"skill_name\":\"b\",\"bundle");
        assert_eq!(InstallMarker::from_bytes(dup.as_bytes()), None);
        let extra = s.replace("{\"bundle", "{\"x\":1,\"bundle");
        assert_eq!(InstallMarker::from_bytes(extra.as_bytes()), None);
        let schema = s.replace("install/0.1", "install/9");
        assert_eq!(InstallMarker::from_bytes(schema.as_bytes()), None);
        assert_eq!(InstallMarker::from_bytes(b"not json"), None);
    }
}
