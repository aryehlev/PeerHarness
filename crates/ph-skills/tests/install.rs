//! Installer: install, reinstall, replace, uninstall, protection rules and atomicity.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use ph_core::FixedClock;
use ph_skills::install::FaultPoint;
use ph_skills::*;

const PNPM: &str = include_str!("fixtures/pnpm-repository-convention/SKILL.md");
const NAME: &str = "pnpm-repository-convention";

fn v1() -> Bundle {
    build_bundle(PNPM, Some(NAME)).unwrap()
}

fn v2() -> Bundle {
    build_bundle(
        &PNPM.replace(
            "automatically.",
            "automatically.\nUse `pnpm dlx` instead of `npx`.",
        ),
        Some(NAME),
    )
    .unwrap()
}

fn installer(root: &Path) -> Installer {
    Installer::new(root).with_clock(Arc::new(FixedClock::new(
        "2026-11-09T18:10:00Z".parse().unwrap(),
    )))
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn install_reinstall_replace_uninstall() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("skills");
    let inst = installer(&root);
    assert_eq!(inst.status(NAME).unwrap(), InstallState::NotInstalled);

    let b1 = v1();
    let o = inst.install(&b1, InstallOptions::default()).unwrap();
    assert_eq!(o.path, root.join(NAME));
    assert_eq!(o.previous_digest, None);
    assert!(!o.replaced && !o.unchanged);
    assert_eq!(
        fs::read_to_string(root.join(NAME).join("SKILL.md")).unwrap(),
        PNPM
    );
    let marker = fs::read_to_string(root.join(NAME).join(MARKER_FILE_NAME)).unwrap();
    assert_eq!(
        marker,
        format!(
            "{{\"bundle_digest\":\"{}\",\"installed_at\":\"2026-11-09T18:10:00Z\",\"schema\":\"peerharness.install/0.1\",\"skill_name\":\"{NAME}\"}}\n",
            b1.digest()
        )
    );
    assert_eq!(entries(&root), vec![NAME.to_owned()]);
    assert_eq!(
        entries(&root.join(NAME)),
        vec![MARKER_FILE_NAME.to_owned(), "SKILL.md".to_owned()]
    );
    assert_eq!(
        inst.status(NAME).unwrap(),
        InstallState::Managed {
            digest: b1.digest(),
            modified: false
        }
    );
    assert_eq!(
        inst.list().unwrap(),
        vec![(
            NAME.to_owned(),
            InstallState::Managed {
                digest: b1.digest(),
                modified: false
            }
        )]
    );

    // reinstall same: no-op
    let o = inst.install(&b1, InstallOptions::default()).unwrap();
    assert!(o.unchanged && !o.replaced);
    assert_eq!(o.previous_digest, Some(b1.digest()));

    // upgrade
    let b2 = v2();
    let o = inst.install(&b2, InstallOptions::default()).unwrap();
    assert!(o.replaced && !o.unchanged);
    assert_eq!(o.previous_digest, Some(b1.digest()));
    assert_eq!(o.backup_path, None);
    assert_eq!(
        fs::read_to_string(root.join(NAME).join("SKILL.md")).unwrap(),
        b2.skill_md()
    );
    assert_eq!(
        inst.status(NAME).unwrap(),
        InstallState::Managed {
            digest: b2.digest(),
            modified: false
        }
    );
    assert_eq!(
        entries(&root),
        vec![NAME.to_owned()],
        "aside/staging dirs must be gone"
    );

    // rollback = install previous
    let o = inst.install(&b1, InstallOptions::default()).unwrap();
    assert_eq!(o.previous_digest, Some(b2.digest()));
    assert_eq!(
        fs::read_to_string(root.join(NAME).join("SKILL.md")).unwrap(),
        PNPM
    );

    // uninstall
    let u = inst.uninstall(NAME, UninstallOptions::default()).unwrap();
    assert_eq!(u.removed_digest, b1.digest());
    assert!(u.dir_removed && !u.was_modified);
    assert_eq!(inst.status(NAME).unwrap(), InstallState::NotInstalled);
    assert!(entries(&root).is_empty());
    assert!(matches!(
        inst.uninstall(NAME, UninstallOptions::default()),
        Err(InstallError::NotInstalled)
    ));
}

#[test]
fn unmanaged_dir_is_protected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let dir = root.join(NAME);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), "my own skill").unwrap();
    fs::write(dir.join("notes.txt"), "keep me").unwrap();
    let inst = installer(&root);
    assert_eq!(inst.status(NAME).unwrap(), InstallState::Unmanaged);
    assert!(matches!(
        inst.install(&v1(), InstallOptions::default()),
        Err(InstallError::Unmanaged)
    ));
    assert!(matches!(
        inst.uninstall(NAME, UninstallOptions::default()),
        Err(InstallError::Unmanaged)
    ));
    assert_eq!(
        fs::read_to_string(dir.join("SKILL.md")).unwrap(),
        "my own skill"
    );
    assert_eq!(
        fs::read_to_string(dir.join("notes.txt")).unwrap(),
        "keep me"
    );

    // A corrupt or foreign marker does not make it managed.
    fs::write(dir.join(MARKER_FILE_NAME), "{\"schema\":\"other\"}").unwrap();
    assert_eq!(inst.status(NAME).unwrap(), InstallState::Unmanaged);
    assert!(matches!(
        inst.install(&v1(), InstallOptions::default()),
        Err(InstallError::Unmanaged)
    ));
    fs::remove_file(dir.join(MARKER_FILE_NAME)).unwrap();

    // forced overwrite with a backup dir keeps the old content
    let backups = tmp.path().join("backups");
    let inst = installer(&root).with_backup_dir(&backups);
    let o = inst
        .install(
            &v1(),
            InstallOptions {
                force_overwrite_unmanaged: true,
                allow_modified: false,
            },
        )
        .unwrap();
    assert!(o.replaced);
    assert_eq!(o.previous_digest, None);
    let bp = o.backup_path.unwrap();
    assert!(bp.starts_with(&backups));
    assert_eq!(fs::read_to_string(bp.join("notes.txt")).unwrap(), "keep me");
    assert_eq!(fs::read_to_string(dir.join("SKILL.md")).unwrap(), PNPM);
    assert_eq!(
        inst.status(NAME).unwrap(),
        InstallState::Managed {
            digest: v1().digest(),
            modified: false
        }
    );
}

#[test]
fn forced_overwrite_without_backup_deletes_old() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(NAME);
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub/x"), "x").unwrap();
    let inst = installer(tmp.path());
    let o = inst
        .install(
            &v1(),
            InstallOptions {
                force_overwrite_unmanaged: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(o.replaced && o.backup_path.is_none());
    assert_eq!(entries(tmp.path()), vec![NAME.to_owned()]);
    assert_eq!(
        entries(&dir),
        vec![MARKER_FILE_NAME.to_owned(), "SKILL.md".to_owned()]
    );
}

#[test]
fn modified_file_is_protected() {
    let tmp = tempfile::tempdir().unwrap();
    let inst = installer(tmp.path());
    let b1 = v1();
    inst.install(&b1, InstallOptions::default()).unwrap();
    let skill = tmp.path().join(NAME).join("SKILL.md");
    fs::write(&skill, format!("{PNPM}\nMy local tweak.\n")).unwrap();
    assert_eq!(
        inst.status(NAME).unwrap(),
        InstallState::Managed {
            digest: b1.digest(),
            modified: true
        }
    );
    assert!(matches!(
        inst.install(&v2(), InstallOptions::default()),
        Err(InstallError::Modified)
    ));
    // even reinstalling the same digest refuses to clobber edits
    assert!(matches!(
        inst.install(&b1, InstallOptions::default()),
        Err(InstallError::Modified)
    ));
    assert!(matches!(
        inst.uninstall(NAME, UninstallOptions::default()),
        Err(InstallError::Modified)
    ));
    assert!(fs::read_to_string(&skill)
        .unwrap()
        .contains("My local tweak."));

    let o = inst
        .install(
            &v2(),
            InstallOptions {
                allow_modified: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(o.replaced);
    assert_eq!(o.previous_digest, Some(b1.digest()));
    assert_eq!(
        inst.status(NAME).unwrap(),
        InstallState::Managed {
            digest: v2().digest(),
            modified: false
        }
    );

    // deleted SKILL.md counts as modified
    fs::remove_file(&skill).unwrap();
    assert_eq!(
        inst.status(NAME).unwrap(),
        InstallState::Managed {
            digest: v2().digest(),
            modified: true
        }
    );
    let u = inst
        .uninstall(
            NAME,
            UninstallOptions {
                allow_modified: true,
            },
        )
        .unwrap();
    assert!(u.was_modified && u.dir_removed);
}

#[test]
fn extra_user_files_survive_uninstall_and_block_replace() {
    let tmp = tempfile::tempdir().unwrap();
    let inst = installer(tmp.path());
    inst.install(&v1(), InstallOptions::default()).unwrap();
    let dir = tmp.path().join(NAME);
    fs::write(dir.join("user-notes.md"), "mine").unwrap();
    assert!(matches!(
        inst.install(&v2(), InstallOptions::default()),
        Err(InstallError::Unmanaged)
    ));
    let u = inst.uninstall(NAME, UninstallOptions::default()).unwrap();
    assert!(!u.dir_removed);
    assert_eq!(entries(&dir), vec!["user-notes.md".to_owned()]);
    assert_eq!(inst.status(NAME).unwrap(), InstallState::Unmanaged);
}

#[test]
fn invalid_names_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let inst = installer(tmp.path());
    for n in ["../etc", "a/b", "", ".hidden", "A"] {
        assert!(
            matches!(inst.status(n), Err(InstallError::InvalidName)),
            "{n}"
        );
        assert!(
            matches!(
                inst.uninstall(n, UninstallOptions::default()),
                Err(InstallError::InvalidName)
            ),
            "{n}"
        );
    }
}

#[test]
fn atomicity_on_injected_faults() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let mut inst = installer(&root);

    // Fresh install failing mid-staging leaves nothing behind.
    for fp in [FaultPoint::AfterStagingSkillFile, FaultPoint::BeforeSwap] {
        inst.inject_fault(Some(fp));
        assert!(matches!(
            inst.install(&v1(), InstallOptions::default()),
            Err(InstallError::InjectedFault)
        ));
        assert!(entries(&root).is_empty(), "{fp:?}: {:?}", entries(&root));
        assert_eq!(inst.status(NAME).unwrap(), InstallState::NotInstalled);
    }

    inst.inject_fault(None);
    inst.install(&v1(), InstallOptions::default()).unwrap();

    // Upgrade failing at any point leaves v1 fully intact and no leftovers.
    for fp in [
        FaultPoint::AfterStagingSkillFile,
        FaultPoint::BeforeSwap,
        FaultPoint::AfterMoveAside,
    ] {
        inst.inject_fault(Some(fp));
        assert!(matches!(
            inst.install(&v2(), InstallOptions::default()),
            Err(InstallError::InjectedFault)
        ));
        assert_eq!(entries(&root), vec![NAME.to_owned()], "{fp:?}");
        assert_eq!(
            fs::read_to_string(root.join(NAME).join("SKILL.md")).unwrap(),
            PNPM
        );
        assert_eq!(
            inst.status(NAME).unwrap(),
            InstallState::Managed {
                digest: v1().digest(),
                modified: false
            }
        );
    }
    inst.inject_fault(None);
    assert!(
        inst.install(&v2(), InstallOptions::default())
            .unwrap()
            .replaced
    );
}

#[test]
fn leftovers_are_cleaned() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join(".peerharness-staging-abc")).unwrap();
    fs::create_dir_all(tmp.path().join(".peerharness-old-abc/sub")).unwrap();
    fs::create_dir_all(tmp.path().join("user-skill")).unwrap();
    let inst = installer(tmp.path());
    assert_eq!(inst.cleanup_leftovers().unwrap(), 2);
    assert_eq!(entries(tmp.path()), vec!["user-skill".to_owned()]);
}

#[test]
fn target_dir_resolution_uses_pure_fn() {
    let p = Path::new("/repo");
    let d = resolve_claude_skills_dir(
        SkillScope::User,
        p,
        None,
        Some(std::ffi::OsStr::new("/home/alice")),
    )
    .unwrap();
    assert_eq!(d, Path::new("/home/alice/.claude/skills"));
    let d = resolve_claude_skills_dir(
        SkillScope::Project,
        p,
        Some(std::ffi::OsStr::new("/tmp/ci-skills")),
        None,
    )
    .unwrap();
    assert_eq!(d, Path::new("/tmp/ci-skills"));
}

#[test]
fn confined_root_must_be_below_base() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    fs::create_dir_all(&project).unwrap();
    // Real directories (or missing ones that are then created) are fine.
    let inst = installer(&project.join(".claude").join("skills")).confine_to(&project);
    inst.install(&v1(), InstallOptions::default()).unwrap();
    assert!(project
        .join(".claude/skills")
        .join(NAME)
        .join("SKILL.md")
        .exists());
    inst.uninstall(NAME, UninstallOptions::default()).unwrap();

    // A root outside the base, or one escaping with `..`, is refused.
    let outside = installer(&tmp.path().join("elsewhere")).confine_to(&project);
    assert!(matches!(
        outside.install(&v1(), InstallOptions::default()),
        Err(InstallError::UnsafeRoot)
    ));
    let escape = installer(&project.join("..").join("elsewhere")).confine_to(&project);
    assert!(matches!(
        escape.install(&v1(), InstallOptions::default()),
        Err(InstallError::UnsafeRoot)
    ));
    assert!(!tmp.path().join("elsewhere").exists());

    // A file where a directory component should be is refused.
    let p2 = tmp.path().join("p2");
    fs::create_dir_all(&p2).unwrap();
    fs::write(p2.join(".claude"), "not a dir").unwrap();
    let inst = installer(&p2.join(".claude").join("skills")).confine_to(&p2);
    assert!(matches!(
        inst.install(&v1(), InstallOptions::default()),
        Err(InstallError::UnsafeRoot)
    ));
}

#[test]
fn case_variant_skill_file_is_not_trusted() {
    // On case-insensitive filesystems (macOS default) `skill.md` and `SKILL.md` are the
    // same file; on case-sensitive ones they differ. Either way a managed directory
    // whose file is listed as `skill.md` must not be silently replaced or removed.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("skills");
    let inst = installer(&root);
    inst.install(&v1(), InstallOptions::default()).unwrap();
    let dir = root.join(NAME);
    fs::remove_file(dir.join("SKILL.md")).unwrap();
    fs::write(dir.join("skill.md"), "user's own lowercase skill file").unwrap();
    assert!(matches!(
        inst.install(&v2(), InstallOptions::default()),
        Err(InstallError::Modified) | Err(InstallError::Unmanaged)
    ));
    assert!(matches!(
        inst.uninstall(NAME, UninstallOptions::default()),
        Err(InstallError::Modified)
    ));
    assert!(entries(&dir).contains(&"skill.md".to_owned()));
    assert_eq!(
        fs::read_to_string(dir.join("skill.md")).unwrap(),
        "user's own lowercase skill file"
    );
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlinked_target_dir_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        fs::create_dir_all(&root).unwrap();
        let victim = tmp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("important"), "data").unwrap();
        symlink(&victim, root.join(NAME)).unwrap();
        let inst = installer(&root);
        let all = InstallOptions {
            force_overwrite_unmanaged: true,
            allow_modified: true,
        };
        assert!(matches!(
            inst.install(&v1(), all),
            Err(InstallError::Symlink)
        ));
        assert!(matches!(
            inst.uninstall(
                NAME,
                UninstallOptions {
                    allow_modified: true
                }
            ),
            Err(InstallError::Symlink)
        ));
        assert_eq!(inst.status(NAME).unwrap(), InstallState::Unmanaged);
        assert_eq!(entries(&victim), vec!["important".to_owned()]);
    }

    #[test]
    fn symlinked_managed_files_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let inst = installer(&root);
        inst.install(&v1(), InstallOptions::default()).unwrap();
        let dir = root.join(NAME);
        let outside = tmp.path().join("outside.md");
        fs::write(&outside, "outside").unwrap();

        // SKILL.md replaced by a symlink
        fs::remove_file(dir.join("SKILL.md")).unwrap();
        symlink(&outside, dir.join("SKILL.md")).unwrap();
        let all = InstallOptions {
            force_overwrite_unmanaged: true,
            allow_modified: true,
        };
        assert!(matches!(
            inst.install(&v2(), all),
            Err(InstallError::Symlink)
        ));
        assert!(matches!(
            inst.uninstall(
                NAME,
                UninstallOptions {
                    allow_modified: true
                }
            ),
            Err(InstallError::Symlink)
        ));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");
        fs::remove_file(dir.join("SKILL.md")).unwrap();
        fs::write(dir.join("SKILL.md"), PNPM).unwrap();

        // marker replaced by a symlink
        let marker = fs::read(dir.join(MARKER_FILE_NAME)).unwrap();
        let outside_marker = tmp.path().join("m.json");
        fs::write(&outside_marker, &marker).unwrap();
        fs::remove_file(dir.join(MARKER_FILE_NAME)).unwrap();
        symlink(&outside_marker, dir.join(MARKER_FILE_NAME)).unwrap();
        assert!(matches!(
            inst.install(&v2(), all),
            Err(InstallError::Symlink)
        ));
        assert!(matches!(
            inst.uninstall(NAME, UninstallOptions::default()),
            Err(InstallError::Symlink)
        ));
        assert!(outside_marker.exists());
    }

    #[test]
    fn symlinked_target_root_is_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-skills");
        fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("skills");
        symlink(&real, &link).unwrap();
        let inst = installer(&link);
        inst.install(&v1(), InstallOptions::default()).unwrap();
        assert!(real.join(NAME).join("SKILL.md").exists());
    }

    #[test]
    fn regular_file_at_target_refused() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(NAME), "file").unwrap();
        let inst = installer(tmp.path());
        let all = InstallOptions {
            force_overwrite_unmanaged: true,
            allow_modified: true,
        };
        assert!(matches!(
            inst.install(&v1(), all),
            Err(InstallError::NotRegular)
        ));
        assert_eq!(inst.status(NAME).unwrap(), InstallState::Unmanaged);
    }

    /// `mkfifo` via the system tool (creating a FIFO directly needs `unsafe`).
    fn mkfifo(path: &Path) -> bool {
        std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn symlinked_project_claude_dir_refused_when_confined() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("repo");
        fs::create_dir_all(&project).unwrap();
        // A malicious repository ships `.claude` as a symlink to somewhere else.
        let victim = tmp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        symlink(&victim, project.join(".claude")).unwrap();
        let root = project.join(".claude").join("skills");
        let inst = installer(&root).confine_to(&project);
        assert!(matches!(
            inst.install(&v1(), InstallOptions::default()),
            Err(InstallError::UnsafeRoot)
        ));
        assert!(matches!(
            inst.uninstall(NAME, UninstallOptions::default()),
            Err(InstallError::UnsafeRoot)
        ));
        assert!(matches!(
            inst.cleanup_leftovers(),
            Err(InstallError::UnsafeRoot)
        ));
        assert!(
            entries(&victim).is_empty(),
            "nothing written through the link"
        );

        // `.claude` real but `.claude/skills` a symlink: also refused.
        fs::remove_file(project.join(".claude")).unwrap();
        fs::create_dir_all(project.join(".claude")).unwrap();
        symlink(&victim, &root).unwrap();
        assert!(matches!(
            inst.install(&v1(), InstallOptions::default()),
            Err(InstallError::UnsafeRoot)
        ));
        assert!(entries(&victim).is_empty());

        // The same root without confinement (user scope semantics) follows the link.
        installer(&root)
            .install(&v1(), InstallOptions::default())
            .unwrap();
        assert_eq!(entries(&victim), vec![NAME.to_owned()]);
    }

    #[test]
    fn confined_base_itself_may_be_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-project");
        fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("project");
        symlink(&real, &link).unwrap();
        let inst = installer(&link.join(".claude/skills")).confine_to(&link);
        inst.install(&v1(), InstallOptions::default()).unwrap();
        assert!(real
            .join(".claude/skills")
            .join(NAME)
            .join("SKILL.md")
            .exists());
    }

    #[test]
    fn fifo_targets_never_block_or_count_as_managed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let inst = installer(&root);
        inst.install(&v1(), InstallOptions::default()).unwrap();
        let dir = root.join(NAME);
        fs::remove_file(dir.join("SKILL.md")).unwrap();
        if !mkfifo(&dir.join("SKILL.md")) {
            eprintln!("mkfifo unavailable; skipping");
            return;
        }
        let all = InstallOptions {
            force_overwrite_unmanaged: true,
            allow_modified: true,
        };
        assert!(matches!(
            inst.install(&v2(), all),
            Err(InstallError::NotRegular)
        ));
        assert!(matches!(
            inst.uninstall(
                NAME,
                UninstallOptions {
                    allow_modified: true
                }
            ),
            Err(InstallError::NotRegular)
        ));
        assert_eq!(inst.status(NAME).unwrap(), InstallState::Unmanaged);

        // A FIFO marker in an otherwise unmanaged directory.
        let other = root.join("other-skill");
        fs::create_dir_all(&other).unwrap();
        assert!(mkfifo(&other.join(MARKER_FILE_NAME)));
        assert_eq!(inst.status("other-skill").unwrap(), InstallState::Unmanaged);
    }
}
