//! `install.sh`, the script behind `curl ... | sh`, run against a release that lives in a
//! temporary folder.
//!
//! The test builds the release the way the release workflow lays it out
//! (`<releases>/download/<tag>/peerharness-<tag>-<target>.tar.gz` and `SHA256SUMS`) from
//! the binary cargo built for this test run, and points the script at it with
//! `PEERHARNESS_RELEASE_URL`. Nothing is downloaded from the network and nothing is
//! installed outside the temporary folder.
//!
//! What it shows: a release that matches its checksum is installed and runs, and the
//! closing lines name the next step for this system; an archive
//! that was changed, a release without a checksum for the archive, and a version that
//! is not a tag install nothing. Finding the latest release is GitHub's redirect and is
//! not covered here.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TAG: &str = "v9.9.9";

/// The release target of the machine the test runs on, as `install.sh` works it out.
fn target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        other => panic!("no release target for {other:?}"),
    }
}

struct Release {
    _tmp: TempDir,
    /// `PEERHARNESS_RELEASE_URL`.
    url: String,
    /// The folder of the one release, holding the archive and `SHA256SUMS`.
    files: PathBuf,
    archive: String,
    /// Where the script is told to install.
    bin: PathBuf,
}

impl Release {
    /// A release of the binary under test, with a correct `SHA256SUMS`.
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let name = format!("peerharness-{TAG}-{}", target());
        let archive = format!("{name}.tar.gz");
        let files = tmp.path().join("releases").join("download").join(TAG);
        std::fs::create_dir_all(&files).unwrap();

        let staging = tmp.path().join("staging");
        std::fs::create_dir_all(staging.join(&name)).unwrap();
        std::fs::copy(
            assert_cmd::cargo::cargo_bin("peerharness"),
            staging.join(&name).join("peerharness"),
        )
        .unwrap();
        let packed = Command::new("tar")
            .arg("-czf")
            .arg(files.join(&archive))
            .arg("-C")
            .arg(&staging)
            .arg(&name)
            .status()
            .unwrap();
        assert!(packed.success());

        let release = Self {
            url: format!("file://{}", tmp.path().join("releases").display()),
            bin: tmp.path().join("bin"),
            files,
            archive,
            _tmp: tmp,
        };
        release.write_sums(&release.archive);
        release
    }

    /// Writes `SHA256SUMS` in the `sha256sum` format, naming the archive `listed_as`.
    fn write_sums(&self, listed_as: &str) {
        let bytes = std::fs::read(self.files.join(&self.archive)).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        std::fs::write(
            self.files.join("SHA256SUMS"),
            format!("{digest}  {listed_as}\n"),
        )
        .unwrap();
    }

    fn install(&self, version: &str) -> Output {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
        Command::new("sh")
            .arg(script)
            .env("PEERHARNESS_RELEASE_URL", &self.url)
            .env("PEERHARNESS_VERSION", version)
            .env("PEERHARNESS_INSTALL_DIR", &self.bin)
            .output()
            .unwrap()
    }

    fn installed(&self) -> PathBuf {
        self.bin.join("peerharness")
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_release_that_matches_its_checksum_is_installed_and_runs() {
    let release = Release::new();
    let out = release.install(TAG);
    assert!(out.status.success(), "{}", stderr(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("Checksum matches SHA256SUMS"), "{said}");
    assert!(said.contains("is not on your PATH"), "{said}");
    // It ends with the one line that sets PeerHarness up for an agent.
    assert!(said.contains("  peerharness setup\n"), "{said}");

    // Exactly one file, executable, and it is the binary.
    let entries: Vec<_> = std::fs::read_dir(&release.bin)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["peerharness"]);
    let version = Command::new(release.installed())
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("peerharness "));

    // Installing again replaces the file and leaves nothing else behind.
    assert!(release.install(TAG).status.success());
    assert_eq!(std::fs::read_dir(&release.bin).unwrap().count(), 1);
}

/// What the script says to do next depends on the system. On Linux no confirmation
/// window can be shown, so a coding agent's tools other than `note` are refused there:
/// the next step is the terminal guide, not "ask your agent".
#[test]
fn the_closing_lines_say_what_comes_next_on_this_system() {
    let release = Release::new();
    let out = release.install(TAG);
    assert!(out.status.success(), "{}", stderr(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    let guide = concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/terminal.md");
    if std::env::consts::OS == "linux" {
        assert!(
            said.contains("on Linux every decision is typed in your own terminal"),
            "{said}"
        );
        assert!(said.contains("starts nothing else"), "{said}");
        // The same address the binary gives where no window can be shown.
        assert!(
            said.contains(&format!(
                "  {guide}
"
            )),
            "{said}"
        );
        assert!(!said.contains("set it up for Claude Code."), "{said}");
    } else {
        assert!(
            said.contains("Next, once, in this terminal: set it up for Claude Code."),
            "{said}"
        );
        assert!(!said.contains("docs/terminal.md"), "{said}");
    }
    // On every system: the one command that sets it up, and the demo.
    assert!(said.contains("  peerharness setup\n"), "{said}");
    assert!(said.contains("  peerharness demo\n"), "{said}");
}

#[test]
fn an_archive_that_was_changed_is_not_installed() {
    let release = Release::new();
    // One byte more than what the checksum was made for.
    let path = release.files.join(&release.archive);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, bytes).unwrap();

    let out = release.install(TAG);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("does not match SHA256SUMS. Nothing was installed."),
        "{}",
        stderr(&out)
    );
    assert!(!release.bin.exists());
}

#[test]
fn a_release_without_a_checksum_for_the_archive_is_not_installed() {
    let release = Release::new();
    // A correct digest, listed for another file.
    release.write_sums("peerharness-v9.9.9-some-other-target.tar.gz");
    let out = release.install(TAG);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("has no checksum for"),
        "{}",
        stderr(&out)
    );
    assert!(!release.bin.exists());

    // No SHA256SUMS at all.
    std::fs::remove_file(release.files.join("SHA256SUMS")).unwrap();
    let out = release.install(TAG);
    assert_eq!(out.status.code(), Some(1));
    assert!(!release.bin.exists());
}

#[test]
fn a_version_that_is_not_a_tag_goes_nowhere() {
    let release = Release::new();
    for version in [
        "9.9.9",
        "../../etc",
        "v9/../../x",
        "v9.9.9 --output /tmp/x",
        "latest",
    ] {
        let out = release.install(version);
        assert_eq!(out.status.code(), Some(1), "{version:?}");
        assert!(
            stderr(&out).contains("is not a release tag"),
            "{version:?}: {}",
            stderr(&out)
        );
    }
    // A tag of the right form that was never released.
    let out = release.install("v1.2.3");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("could not download"),
        "{}",
        stderr(&out)
    );
    assert!(!release.bin.exists());
}
