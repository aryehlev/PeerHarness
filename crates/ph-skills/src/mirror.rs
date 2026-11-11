//! Copies of the skills PeerHarness manages, for another coding agent that reads its
//! skills from another directory (ADR-050).
//!
//! The directory a rule is installed in (the *source*, Claude Code's skills directory
//! or a project's) stays the only place where installing, holding and removing are
//! decided. [`mirror`] then makes a second directory (the *copy*) hold exactly the
//! PeerHarness-managed skills of the source, with the same installer and the same
//! rules:
//!
//! * A managed, unmodified skill of the source is installed in the copy when the copy
//!   has nothing under that name, or replaces a copy PeerHarness manages there and
//!   nobody edited.
//! * A skill in the copy that PeerHarness does not manage is never touched, and one
//!   whose `SKILL.md` was edited there is never replaced or removed: both are reported
//!   ([`Blocked`]).
//! * A managed, unmodified copy whose source no longer holds a managed skill of that
//!   name is removed. A source skill its owner edited keeps its copy as it is.
//!
//! Nothing here decides what is installed: it follows what the source holds, which a
//! confirmation, a vote and the owner's standing choice already decided.

use std::path::PathBuf;

use crate::bundle::{build_bundle, SKILL_FILE_NAME};
use crate::error::InstallError;
use crate::fsutil::read_regular_bounded;
use crate::install::{InstallOptions, InstallState, Installer, UninstallOptions};
use crate::validate::MAX_SKILL_FILE_BYTES;

/// Why a skill of the source could not be copied, or a copy could not be removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedWhy {
    /// A skill of that name that PeerHarness does not manage is in the copy directory.
    InTheWay,
    /// The copy was edited by hand, so it is neither replaced nor removed.
    Edited,
    /// The files could not be read or written.
    Failed,
}

impl BlockedWhy {
    /// A short stable code.
    pub const fn code(self) -> &'static str {
        match self {
            BlockedWhy::InTheWay => "in_the_way",
            BlockedWhy::Edited => "edited",
            BlockedWhy::Failed => "failed",
        }
    }
}

/// One skill that [`mirror`] left as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocked {
    /// The skill name.
    pub name: String,
    /// Why.
    pub why: BlockedWhy,
}

/// What [`mirror`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MirrorReport {
    /// The copy directory.
    pub root: PathBuf,
    /// Skills copied or brought up to date.
    pub written: Vec<String>,
    /// Copies removed because the source no longer holds them.
    pub removed: Vec<String>,
    /// Copies that match the source.
    pub same: usize,
    /// What was left as it was, and why.
    pub blocked: Vec<Blocked>,
}

impl MirrorReport {
    /// Whether anything was written or removed.
    pub fn changed(&self) -> bool {
        !self.written.is_empty() || !self.removed.is_empty()
    }
}

/// Makes `copy` hold the PeerHarness-managed skills of `source` (see the module docs).
///
/// Fails only when either directory cannot be listed; a skill that cannot be copied is
/// reported in [`MirrorReport::blocked`] and the others are still copied.
pub fn mirror(source: &Installer, copy: &Installer) -> Result<MirrorReport, InstallError> {
    let mut report = MirrorReport {
        root: copy.target_root().to_path_buf(),
        ..MirrorReport::default()
    };
    let blocked = |report: &mut MirrorReport, name: &str, why| {
        report.blocked.push(Blocked {
            name: name.to_owned(),
            why,
        });
    };
    let in_source = source.list()?;
    for (name, state) in &in_source {
        let InstallState::Managed {
            digest,
            modified: false,
        } = state
        else {
            continue;
        };
        match copy.status(name) {
            Ok(InstallState::Managed {
                digest: d,
                modified: false,
            }) if d == *digest => {
                report.same += 1;
                continue;
            }
            Ok(
                InstallState::NotInstalled
                | InstallState::Managed {
                    modified: false, ..
                },
            ) => {}
            Ok(InstallState::Managed { modified: true, .. }) => {
                blocked(&mut report, name, BlockedWhy::Edited);
                continue;
            }
            Ok(InstallState::Unmanaged) => {
                blocked(&mut report, name, BlockedWhy::InTheWay);
                continue;
            }
            Err(_) => {
                blocked(&mut report, name, BlockedWhy::Failed);
                continue;
            }
        }
        let Some(bundle) = installed_text(source, name)
            .and_then(|text| build_bundle(&text, Some(name)).ok())
            .filter(|b| b.digest() == *digest)
        else {
            blocked(&mut report, name, BlockedWhy::Failed);
            continue;
        };
        match copy.install(&bundle, InstallOptions::default()) {
            Ok(_) => report.written.push(name.clone()),
            Err(InstallError::Unmanaged) => blocked(&mut report, name, BlockedWhy::InTheWay),
            Err(InstallError::Modified) => blocked(&mut report, name, BlockedWhy::Edited),
            Err(_) => blocked(&mut report, name, BlockedWhy::Failed),
        }
    }
    let source_holds = |name: &str| {
        in_source
            .iter()
            .any(|(n, s)| n == name && matches!(s, InstallState::Managed { .. }))
    };
    for (name, state) in copy.list()? {
        let InstallState::Managed { modified, .. } = state else {
            continue;
        };
        if source_holds(&name) {
            continue;
        }
        if modified {
            blocked(&mut report, &name, BlockedWhy::Edited);
            continue;
        }
        match copy.uninstall(&name, UninstallOptions::default()) {
            Ok(_) => report.removed.push(name),
            Err(InstallError::Modified) => blocked(&mut report, &name, BlockedWhy::Edited),
            Err(_) => blocked(&mut report, &name, BlockedWhy::Failed),
        }
    }
    Ok(report)
}

/// Removes from `copy` every copy PeerHarness manages there and nobody edited, for an
/// agent that is no longer connected. Returns the names removed and what was left.
pub fn remove_copies(copy: &Installer) -> Result<MirrorReport, InstallError> {
    let mut report = MirrorReport {
        root: copy.target_root().to_path_buf(),
        ..MirrorReport::default()
    };
    for (name, state) in copy.list()? {
        match state {
            InstallState::Managed {
                modified: false, ..
            } => match copy.uninstall(&name, UninstallOptions::default()) {
                Ok(_) => report.removed.push(name),
                Err(_) => report.blocked.push(Blocked {
                    name,
                    why: BlockedWhy::Failed,
                }),
            },
            InstallState::Managed { modified: true, .. } => report.blocked.push(Blocked {
                name,
                why: BlockedWhy::Edited,
            }),
            _ => {}
        }
    }
    Ok(report)
}

/// The text of the `SKILL.md` installed under `name`, if it can be read.
fn installed_text(installer: &Installer, name: &str) -> Option<String> {
    let path = installer.skill_dir(name).ok()?.join(SKILL_FILE_NAME);
    match read_regular_bounded(&path, MAX_SKILL_FILE_BYTES) {
        Ok(bytes) => String::from_utf8(bytes).ok(),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(name: &str, body: &str) -> crate::Bundle {
        build_bundle(
            &format!("---\nname: {name}\ndescription: Use when testing copies.\n---\n\n{body}\n"),
            Some(name),
        )
        .unwrap()
    }

    #[test]
    fn a_copy_follows_its_source_and_never_touches_what_is_not_its_own() {
        let tmp = tempfile::tempdir().unwrap();
        let source = Installer::new(tmp.path().join("claude"));
        let copy = Installer::new(tmp.path().join("agents"));

        // Nothing to copy: nothing happens, and a missing directory is no error.
        let r = mirror(&source, &copy).unwrap();
        assert!(!r.changed() && r.blocked.is_empty());

        source
            .install(&skill("use-pnpm", "Use pnpm."), InstallOptions::default())
            .unwrap();
        source
            .install(
                &skill("run-tests", "Run the tests."),
                InstallOptions::default(),
            )
            .unwrap();
        // A skill of the owner's own in the source (no marker) is not copied.
        std::fs::create_dir_all(tmp.path().join("claude/mine")).unwrap();
        std::fs::write(tmp.path().join("claude/mine/SKILL.md"), "x").unwrap();
        // A skill of the owner's own in the copy directory is in the way of one name.
        std::fs::create_dir_all(tmp.path().join("agents/run-tests")).unwrap();
        std::fs::write(tmp.path().join("agents/run-tests/SKILL.md"), "theirs").unwrap();

        let r = mirror(&source, &copy).unwrap();
        assert_eq!(r.written, vec!["use-pnpm".to_owned()]);
        assert_eq!(
            r.blocked,
            vec![Blocked {
                name: "run-tests".into(),
                why: BlockedWhy::InTheWay
            }]
        );
        assert!(!tmp.path().join("agents/mine").exists());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("agents/run-tests/SKILL.md")).unwrap(),
            "theirs"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("agents/use-pnpm/SKILL.md")).unwrap(),
            std::fs::read(tmp.path().join("claude/use-pnpm/SKILL.md")).unwrap()
        );

        // Again: nothing changes.
        let r = mirror(&source, &copy).unwrap();
        assert!(!r.changed());
        assert_eq!(r.same, 1);

        // A new version in the source replaces the copy.
        source
            .install(
                &skill("use-pnpm", "Use pnpm, always."),
                InstallOptions::default(),
            )
            .unwrap();
        let r = mirror(&source, &copy).unwrap();
        assert_eq!(r.written, vec!["use-pnpm".to_owned()]);
        assert!(
            std::fs::read_to_string(tmp.path().join("agents/use-pnpm/SKILL.md"))
                .unwrap()
                .contains("always")
        );

        // An edited copy is neither replaced nor removed.
        std::fs::write(tmp.path().join("agents/use-pnpm/SKILL.md"), "edited").unwrap();
        source
            .install(
                &skill("use-pnpm", "Use pnpm, third."),
                InstallOptions::default(),
            )
            .unwrap();
        let r = mirror(&source, &copy).unwrap();
        assert!(r.written.is_empty());
        assert!(r.blocked.contains(&Blocked {
            name: "use-pnpm".into(),
            why: BlockedWhy::Edited
        }));
        source
            .uninstall("use-pnpm", UninstallOptions::default())
            .unwrap();
        let r = mirror(&source, &copy).unwrap();
        assert!(r.removed.is_empty());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("agents/use-pnpm/SKILL.md")).unwrap(),
            "edited"
        );
    }

    #[test]
    fn a_copy_goes_when_its_source_goes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = Installer::new(tmp.path().join("claude"));
        let copy = Installer::new(tmp.path().join("agents"));
        source
            .install(&skill("use-pnpm", "Use pnpm."), InstallOptions::default())
            .unwrap();
        mirror(&source, &copy).unwrap();
        // The owner edits the source: the copy stays as it was.
        std::fs::write(tmp.path().join("claude/use-pnpm/SKILL.md"), "mine now").unwrap();
        let r = mirror(&source, &copy).unwrap();
        assert!(!r.changed());
        assert!(tmp.path().join("agents/use-pnpm/SKILL.md").exists());
        // The source is removed: so is the copy.
        std::fs::remove_dir_all(tmp.path().join("claude/use-pnpm")).unwrap();
        let r = mirror(&source, &copy).unwrap();
        assert_eq!(r.removed, vec!["use-pnpm".to_owned()]);
        assert!(!tmp.path().join("agents/use-pnpm").exists());
    }

    #[test]
    fn removing_copies_leaves_what_was_edited_or_is_not_ours() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = Installer::new(tmp.path().join("agents"));
        copy.install(&skill("a-rule", "A."), InstallOptions::default())
            .unwrap();
        copy.install(&skill("b-rule", "B."), InstallOptions::default())
            .unwrap();
        std::fs::write(tmp.path().join("agents/b-rule/SKILL.md"), "edited").unwrap();
        std::fs::create_dir_all(tmp.path().join("agents/c-rule")).unwrap();
        let r = remove_copies(&copy).unwrap();
        assert_eq!(r.removed, vec!["a-rule".to_owned()]);
        assert_eq!(r.blocked[0].why, BlockedWhy::Edited);
        assert!(tmp.path().join("agents/b-rule/SKILL.md").exists());
        assert!(tmp.path().join("agents/c-rule").exists());
    }
}
