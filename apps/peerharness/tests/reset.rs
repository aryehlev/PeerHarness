//! `reset`: explains before it deletes, deletes only on `--confirm`, only for a person,
//! and only a directory that is plainly this node's own.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

/// The binary for the node at `home`, run by the person, with no arguments yet. Its
/// skills directory and its Claude settings file are temporary paths beside the home:
/// `status` reads the settings file, and without one named it would read the
/// developer's own.
fn bare(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("peerharness").unwrap();
    cmd.env("PEERHARNESS_HOME", home)
        .env(
            "PEERHARNESS_CLAUDE_SKILLS_DIR",
            home.with_extension("skills"),
        )
        .env(
            "PEERHARNESS_CLAUDE_SETTINGS",
            home.with_extension("settings.json"),
        )
        .env("USER", "alice")
        .env_remove("CLAUDECODE")
        .env_remove("PEERHARNESS_AGENT_SESSION");
    cmd
}

fn cmd(home: &Path, args: &[&str]) -> Command {
    let mut cmd = bare(home);
    cmd.arg("--json").args(args);
    cmd
}

fn run(home: &Path, args: &[&str]) -> Value {
    let out = cmd(home, args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn code(home: &Path, args: &[&str]) -> i32 {
    cmd(home, args).output().unwrap().status.code().unwrap()
}

fn new_node(root: &Path, name: &str) -> PathBuf {
    let home = root.join(name);
    run(
        &home,
        &[
            "init",
            "--keystore",
            "insecure-dev",
            "--insecure-dev-keystore",
        ],
    );
    home
}

#[test]
fn reset_explains_first_and_deletes_only_when_a_person_confirms() {
    let tmp = TempDir::new().unwrap();
    let home = new_node(tmp.path(), "node");
    run(&home, &["circle", "create", "team"]);
    run(&home, &["note", "Use pnpm, not npm."]);

    // Without --confirm: an account of what would go, and nothing gone.
    let dry = run(&home, &["reset"]);
    assert_eq!(dry["deleted"], false);
    assert_eq!(dry["circles"], 1);
    assert_eq!(dry["founded_circles"], 1);
    assert_eq!(dry["candidates"], 1);
    assert!(home.join("peerharness.db").is_file());
    run(&home, &["status"]);

    // An agent's session cannot delete the node and its keys.
    let out = cmd(&home, &["reset", "--confirm"])
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(home.join("peerharness.db").is_file());

    // The person can. The directory and the keys are gone, and nothing beside it is.
    let sibling = tmp.path().join("keep.txt");
    std::fs::write(&sibling, "not ours").unwrap();
    let done = run(&home, &["reset", "--confirm"]);
    assert_eq!(done["deleted"], true);
    assert_eq!(
        done["keys_deleted"], 2,
        "the device key and the circle's root key"
    );
    assert!(!home.exists());
    assert!(sibling.is_file());
    // There is no node any more.
    assert_eq!(code(&home, &["status"]), 2);
    assert_eq!(code(&home, &["reset", "--confirm"]), 2);
}

/// What a command prints for the person to read, without `--json`.
fn reads(home: &Path, args: &[&str]) -> String {
    let out = bare(home).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A skill installed for the agent stays where it is. Before the reset the commands
/// that take it out are named. After it they cannot run any more (there is no node), so
/// the report names the folder instead of two commands that would only fail.
#[test]
fn after_the_reset_an_installed_skill_is_named_as_a_folder_not_as_a_dead_command() {
    let tmp = TempDir::new().unwrap();
    let home = new_node(tmp.path(), "node");
    let noted = run(&home, &["note", "Use pnpm, not npm, in this repository."]);
    let kept = run(
        &home,
        &["keep", noted["candidate_id"].as_str().unwrap(), "--yes"],
    );
    let folder = kept["path"].as_str().unwrap().to_owned();
    assert!(Path::new(&folder).join("SKILL.md").is_file());

    // Before: the commands, which still work, and when to run them.
    let before = reads(&home, &["reset"]);
    assert!(
        before.contains("1 skill(s) installed for your agent"),
        "{before}"
    );
    assert!(
        before.contains("`peerharness skills uninstall`"),
        "{before}"
    );
    assert!(before.contains("run them before the reset"), "{before}");

    // After: the folder, and neither command.
    let after = reads(&home, &["reset", "--confirm"]);
    assert!(after.contains("This node no longer exists."), "{after}");
    assert!(after.contains("Still in place:"), "{after}");
    assert!(after.contains(&folder), "{after}");
    assert!(after.contains("delete by hand"), "{after}");
    assert!(!after.contains("peerharness skills uninstall"), "{after}");
    assert!(!after.contains("peerharness rule opt-out"), "{after}");
    // The command it does still name works without a node.
    assert!(
        after.contains("`peerharness watch claude --remove`"),
        "{after}"
    );
    // The skill is where it was: the reset did not touch the agent's directory.
    assert!(Path::new(&folder).join("SKILL.md").is_file());
    // And the two commands would indeed have failed.
    assert_eq!(
        code(
            &home,
            &["skills", "uninstall", "use-pnpm-not-npm-repository"]
        ),
        2
    );
}

#[cfg(unix)]
#[test]
fn reset_refuses_a_home_that_is_a_link() {
    let tmp = TempDir::new().unwrap();
    let real = new_node(tmp.path(), "real");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(code(&link, &["reset", "--confirm"]), 3);
    assert!(real.join("peerharness.db").is_file(), "nothing was deleted");
    // The keys were not touched either: the node still signs.
    run(&real, &["circle", "create", "team"]);
}

/// A home is whatever folder its owner named: `init` takes a folder that is there,
/// with what lies in it. Version 0.4.0 removed the folder with everything in it. The
/// account names what stays, and the reset deletes its own files and nothing else
/// (ADR-050).
#[test]
fn reset_deletes_only_what_peerharness_put_into_its_home() {
    let tmp = TempDir::new().unwrap();
    // Somebody's work, in the folder that then becomes the node's home.
    let home = tmp.path().join("node");
    std::fs::create_dir_all(home.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".git")).unwrap();
    std::fs::write(home.join("src/main.rs"), "precious work").unwrap();
    std::fs::write(home.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
    std::fs::write(home.join("TODO.md"), "notes").unwrap();
    new_node(tmp.path(), "node");
    run(&home, &["circle", "create", "team"]);
    // What an interrupted write of the config leaves is PeerHarness's own.
    std::fs::write(home.join(".config.toml.tmp-00ff"), "").unwrap();

    let dry = run(&home, &["reset"]);
    assert_eq!(
        dry["not_peerharness_left"],
        serde_json::json!([".git", "TODO.md", "src"])
    );
    let said = reads(&home, &["reset"]);
    assert!(
        said.contains("3 other item(s) in that folder are not PeerHarness's"),
        "{said}"
    );
    assert!(said.contains(".git, TODO.md, src"), "{said}");

    let done = run(&home, &["reset", "--confirm"]);
    assert_eq!(done["deleted"], true);
    assert_eq!(done["home_removed"], false);
    assert_eq!(done["keys_deleted"], 2);
    assert_eq!(
        std::fs::read_to_string(home.join("src/main.rs")).unwrap(),
        "precious work"
    );
    assert!(home.join(".git/HEAD").is_file());
    assert!(home.join("TODO.md").is_file());
    // Everything of the node is gone, and nothing but the three is left.
    let mut left: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, [".git", "TODO.md", "src"]);
    assert_eq!(code(&home, &["status"]), 2);
}

/// The user's home directory is refused however it is spelled, and so is a folder
/// that holds it. Version 0.4.0 compared the two paths as text: `~/Documents/..` and
/// a path through a linked folder passed, and everything in the home directory went.
#[cfg(unix)]
#[test]
fn reset_refuses_the_users_home_directory_under_every_spelling() {
    let tmp = TempDir::new().unwrap();
    let users = tmp.path().join("users");
    let user_home = users.join("alice");
    // Two nodes: one in the folder that holds the user's home directory, and one
    // whose home is that directory itself.
    let init = |home: &Path| {
        let out = cmd(
            home,
            &[
                "init",
                "--keystore",
                "insecure-dev",
                "--insecure-dev-keystore",
            ],
        )
        .env("HOME", &user_home)
        .output()
        .unwrap();
        assert!(out.status.success());
    };
    init(&users);
    init(&user_home);
    std::fs::create_dir_all(user_home.join("Documents")).unwrap();
    std::fs::write(user_home.join("Documents/thesis.txt"), "years of work").unwrap();
    let alias = tmp.path().join("alias");
    std::os::unix::fs::symlink(&users, &alias).unwrap();

    let spellings = [
        user_home.clone(),
        user_home.join("Documents").join(".."),
        alias.join("alice"),
        user_home.join("Documents/../../alice"),
    ];
    for spelled in &spellings {
        for args in [&["reset"][..], &["reset", "--confirm"][..]] {
            let out = cmd(spelled, args).env("HOME", &user_home).output().unwrap();
            assert_eq!(
                out.status.code(),
                Some(3),
                "{} {args:?}: {}",
                spelled.display(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(user_home.join("Documents/thesis.txt").is_file());
        assert!(user_home.join("peerharness.db").is_file());
        assert!(user_home.join("keys").is_dir(), "the keys were not touched");
    }

    // A folder that holds the user's home directory is refused in the same way.
    for args in [&["reset"][..], &["reset", "--confirm"][..]] {
        let out = cmd(&users, args).env("HOME", &user_home).output().unwrap();
        assert_eq!(out.status.code(), Some(3), "{args:?}");
    }
    assert!(users.join("peerharness.db").is_file());
    assert!(user_home.join("Documents/thesis.txt").is_file());
}

/// A node whose database cannot be read can still be deleted. Version 0.4.0 opened
/// the database first and stopped there, so a damaged node could not be removed by
/// the one command that removes a node.
#[test]
fn reset_deletes_a_node_whose_database_cannot_be_read() {
    let tmp = TempDir::new().unwrap();
    let home = new_node(tmp.path(), "node");
    run(&home, &["circle", "create", "team"]);
    let db = home.join("peerharness.db");
    let mut bytes = std::fs::read(&db).unwrap();
    bytes[..64].fill(b'A');
    std::fs::write(&db, bytes).unwrap();
    let _ = std::fs::remove_file(home.join("peerharness.db-wal"));
    let _ = std::fs::remove_file(home.join("peerharness.db-shm"));
    assert_ne!(code(&home, &["status"]), 0, "the node cannot be opened");

    let dry = run(&home, &["reset"]);
    assert_eq!(dry["database_readable"], false);
    assert_eq!(dry["deleted"], false);
    assert!(dry["circles"].is_null(), "what it held is not made up");
    let said = reads(&home, &["reset"]);
    assert!(
        said.contains("the database, which cannot be read"),
        "{said}"
    );
    assert!(home.join("keys").is_dir());

    let done = run(&home, &["reset", "--confirm"]);
    assert_eq!(done["deleted"], true);
    assert_eq!(done["home_removed"], true);
    assert!(!home.exists());
}
