//! `peerharness init`: device key, database and config. Idempotent: an existing identity
//! is never regenerated.
//!
//! A coding agent may run a plain `init` for its user: the keys go to the OS keychain
//! or an encrypted file. The plaintext keystore (`insecure-dev`) is refused inside an
//! agent's session, whether a flag or an existing config file asks for it: its warning
//! has to reach a person, and there it would reach the agent.
//!
//! An `init` that fails before the node has a device key leaves the home as it found
//! it ([`Made`]): it takes away the files and directories this run created, puts back a
//! config file it rewrote, and touches nothing else. Without that, a first run with no
//! passphrase to read left a config file and a database behind, and every later command
//! said the home had no identity.
//!
//! "What this run created" is only known to a run that is alone in the home. `init`
//! therefore holds an exclusive lock on the home directory for as long as it runs
//! ([`HomeLock`]), and a second `init` for the same home is refused while it does. What
//! was there is looked at under that lock. Without it, a run that waited at a prompt
//! and then failed took away the config file and the database that another `init` had
//! made in the meantime, with a circle in it. Where the lock cannot be had (a file
//! system without locks, or not Unix), a failed run removes nothing at all.

use anyhow::{Context, Result};
use ph_identity::{DeviceIdentity, KeyStore, KeystoreBackend, OsKeyStore};
use ph_store::{IdentityMetadata, Store};
use serde_json::json;

use super::Ctx;
use crate::cli::{InitArgs, KdfProfileArg, KeystoreArg};
use crate::config::{Config, KdfProfile};
use crate::consent::human_only;
use crate::error::usage;
use crate::home::{mode_of, set_mode, Home};
use crate::node::open_configured_keystore;
use crate::output::{Report, Text};

/// What a session is refused: named for `consent::human_only`'s message.
const PLAINTEXT_KEYS: &str = "storing this node's private keys in plaintext (insecure-dev)";
const WEAK_KEY_FILES: &str =
    "encrypting this node's key files with the weak test profile (fast-insecure-test)";

pub fn run(ctx: &Ctx, a: InitArgs) -> Result<Report> {
    let home = &ctx.home;
    let requested = match a.keystore {
        Some(KeystoreArg::Os) => Some(KeystoreBackend::Os),
        Some(KeystoreArg::File) => Some(KeystoreBackend::File),
        Some(KeystoreArg::InsecureDev) => Some(KeystoreBackend::InsecureDev),
        None => None,
    };
    if requested == Some(KeystoreBackend::InsecureDev) && !a.insecure_dev_keystore {
        return Err(usage(
            "`--keystore insecure-dev` stores private keys in PLAINTEXT; add \
             --insecure-dev-keystore to confirm (development only)",
        ));
    }
    if a.insecure_dev_keystore && requested.is_some_and(|b| b != KeystoreBackend::InsecureDev) {
        return Err(usage(
            "--insecure-dev-keystore only applies to --keystore insecure-dev",
        ));
    }
    let requested = requested.or(a
        .insecure_dev_keystore
        .then_some(KeystoreBackend::InsecureDev));
    if requested == Some(KeystoreBackend::InsecureDev) {
        // Before anything is created.
        human_only(PLAINTEXT_KEYS)?;
    }
    let kdf = a.kdf_profile.map(|k| match k {
        KdfProfileArg::Default => KdfProfile::Default,
        KdfProfileArg::FastInsecureTest => KdfProfile::FastInsecureTest,
    });
    if kdf == Some(KdfProfile::FastInsecureTest) {
        // Before anything is created, like the plaintext keystore: how well a key file
        // is encrypted is its owner's decision too (ADR-050).
        human_only(WEAK_KEY_FILES)?;
    }

    // What is not there yet is what this run makes, and takes away again if it fails.
    // The home itself is looked at before it is created, everything in it once this
    // run is the only `init` in it.
    let root_was_missing = is_missing(home.root());
    let lock = HomeLock::acquire(home)?;
    let made = Made::before(home, root_was_missing);
    if let Some(m) = mode_of(home.root()) {
        if m & 0o077 != 0 {
            set_mode(home.root(), 0o700)?;
            ctx.out.warn(format!(
                "tightened permissions of {} to 0700",
                home.root().display()
            ));
        }
    }

    // Existing identity: never regenerate.
    if home.db_path().is_file() {
        let store = Store::open(home.db_path()).context("cannot open the database")?;
        if let Some(id) = store.identity()? {
            if !home.config_path().is_file() {
                let mut cfg = Config::default();
                if let Ok(b) = id.keystore_backend.parse() {
                    cfg.node.keystore = b;
                }
                cfg.save(home)?;
            }
            if requested.is_some_and(|b| b.as_str() != id.keystore_backend) {
                ctx.out.warn(format!(
                    "already initialized with the `{}` keystore; the identity is kept",
                    id.keystore_backend
                ));
            }
            return Ok(report(ctx, &id, false));
        }
    }

    let mut cfg = if home.config_path().is_file() {
        Config::load(home)?
    } else {
        Config::default()
    };
    if let Some(b) = requested {
        cfg.node.keystore = b;
    }
    if let Some(k) = kdf {
        cfg.node.kdf_profile = k;
    }
    let backend = cfg.node.keystore;
    // Up to the device key, a failure leaves nothing of this run behind. Once a key is
    // in the keystore everything stays: the next `init` adopts it, and it needs the
    // config file to know which keystore that was.
    let key_in_keystore = std::cell::Cell::new(false);
    let keyed = (|| -> Result<(Store, Box<dyn KeyStore>, DeviceIdentity)> {
        if backend == KeystoreBackend::Os {
            // The error says what to run instead (`--keystore file`).
            OsKeyStore::check_available().map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        if backend == KeystoreBackend::InsecureDev {
            // A config file that names the plaintext keystore asks for it as the flag
            // does: a session is refused. And it does not stand in for the flag
            // (ADR-050): a file that was put into the home is not the owner saying so.
            human_only(PLAINTEXT_KEYS)?;
            if !a.insecure_dev_keystore {
                return Err(usage(
                    "this home's config.toml names the plaintext keystore (insecure-dev), \
                     which stores private keys in PLAINTEXT; add --insecure-dev-keystore to \
                     confirm (development only), or choose another with --keystore",
                ));
            }
            ctx.out.warn(
                "insecure-dev keystore: private keys are stored in PLAINTEXT (development only)",
            );
        }
        if backend == KeystoreBackend::File && cfg.node.kdf_profile == KdfProfile::FastInsecureTest
        {
            // Whether the flag asked for it or a config file that was already there:
            // the profile in force is what is warned about, and what a session is
            // refused.
            human_only(WEAK_KEY_FILES)?;
            ctx.out.warn(
                "kdf profile fast-insecure-test: this node's key files are encrypted with \
                 weak parameters; it is for automated tests and demos only",
            );
        }
        cfg.save(home)?;

        let store = Store::open(home.db_path()).context("cannot create the database")?;
        let ks = open_configured_keystore(home, &cfg, backend)?;
        let dev = if DeviceIdentity::exists(&*ks)? {
            key_in_keystore.set(true);
            // A previous init stored the key but not the metadata: adopt it.
            DeviceIdentity::load(&*ks).context("cannot unlock the existing device key")?
        } else {
            DeviceIdentity::create(&*ks)
                .inspect_err(|_| {
                    // Looked at again, and taken as there when that cannot be told.
                    key_in_keystore.set(DeviceIdentity::exists(&*ks).unwrap_or(true));
                })
                .context("cannot create the device key")?
        };
        Ok((store, ks, dev))
    })();
    let (store, ks, dev) = match keyed {
        Ok(keyed) => keyed,
        Err(e) => {
            // The closure's database handle is closed by now. Nothing is taken away
            // unless this run was alone in the home, and nothing once the database
            // holds an identity, whoever put it there.
            if !key_in_keystore.get() && lock.held() && !has_identity(home) {
                made.undo(home);
            }
            return Err(e);
        }
    };
    let keystore_ref = ks.locator(DeviceIdentity::LABEL)?;
    let id = IdentityMetadata {
        device_key: dev.public(),
        keystore_backend: backend.as_str().to_owned(),
        keystore_ref,
        created_at: ph_core::Timestamp::now(),
    };
    store.set_identity(&id)?;
    tracing::info!("node initialized");
    Ok(report(ctx, &id, true))
}

/// Whether nothing is at `path`: no file, no directory, no link. Only "not found"
/// counts. A path that cannot be looked at (no permission, an I/O error) is taken as
/// there, and so as not this run's to remove.
fn is_missing(path: &std::path::Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// Whether the database of `home` holds a device identity now. A home with a config
/// file and a database and no identity is what an interrupted `init` leaves (Ctrl-C at
/// the passphrase prompt): `init` completes it, and `setup` asks this to know that it
/// has to.
pub(crate) fn has_identity(home: &Home) -> bool {
    home.db_path().is_file()
        && Store::open(home.db_path())
            .ok()
            .and_then(|store| store.identity().ok().flatten())
            .is_some()
}

/// The exclusive lock `init` holds on the home directory while it runs. The operating
/// system drops it with the process, however that ends. It is a lock on the directory
/// itself, so there is no lock file to leave behind or to take away.
struct HomeLock(Option<std::fs::File>);

impl HomeLock {
    /// Creates the home if it is missing and locks it. Refuses when another `init`
    /// holds the lock. Where the file system has no locks the run goes on without one,
    /// and [`Self::held`] says so.
    #[cfg(unix)]
    fn acquire(home: &Home) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;

        // An `init` that fails removes a home it created. If that happens between
        // creating the directory here and locking it, the lock is on a directory that
        // is gone: look at what the path names once the lock is held, and start again
        // if it is another directory.
        for _ in 0..16 {
            home.ensure()?;
            let dir = match std::fs::File::open(home.root()) {
                Ok(dir) => dir,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("cannot open {}", home.root().display())))
                }
            };
            match dir.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(anyhow::anyhow!(
                        "another `peerharness init` is running for this home: finish or \
                         stop it first"
                    ))
                }
                Err(std::fs::TryLockError::Error(_)) => return Ok(Self(None)),
            }
            let same = match (dir.metadata(), std::fs::metadata(home.root())) {
                (Ok(locked), Ok(named)) => {
                    locked.dev() == named.dev() && locked.ino() == named.ino()
                }
                _ => false,
            };
            if same {
                return Ok(Self(Some(dir)));
            }
        }
        Err(anyhow::anyhow!(
            "the home directory keeps being removed while it is set up: is another \
             `peerharness init` running for it?"
        ))
    }

    #[cfg(not(unix))]
    fn acquire(home: &Home) -> Result<Self> {
        home.ensure()?;
        Ok(Self(None))
    }

    /// Whether this run holds the lock, and so is the only `init` in the home.
    fn held(&self) -> bool {
        self.0.is_some()
    }
}

/// What was missing from a home before `init` touched it, and so is this run's to take
/// away if it fails before the node has a device key.
#[derive(Clone, Debug)]
struct Made {
    root: bool,
    config: bool,
    database: bool,
    keys_dir: bool,
    /// The bytes of a config file that was there, which this run rewrites before the
    /// step that can fail: put back by [`Self::undo`].
    config_was: Option<Vec<u8>>,
}

impl Made {
    /// Looks at `home` under the lock, before anything in it is created. A path that
    /// is there in any form (a file, a directory, a link) is not this run's.
    /// `root_was_missing` is what was seen before the home itself was created.
    fn before(home: &Home, root_was_missing: bool) -> Self {
        let config = is_missing(&home.config_path());
        Self {
            root: root_was_missing,
            config,
            database: is_missing(&home.db_path()),
            keys_dir: is_missing(&home.keys_dir()),
            config_was: (!config)
                .then(|| {
                    crate::home::read_bounded_file(
                        &home.config_path(),
                        crate::config::MAX_CONFIG_BYTES,
                    )
                    .ok()
                })
                .flatten(),
        }
    }

    /// Takes away what this run created: the config file, the database with the two
    /// files SQLite keeps next to it, and the keys directory and the home itself when
    /// they are empty. A config file that was there gets back the bytes it had. A
    /// directory that holds anything else stays, so nothing that was there before, and
    /// no key, is ever removed. Failures are ignored: the error that brought us here is
    /// the one to report.
    fn undo(self, home: &Home) {
        if self.config {
            let _ = std::fs::remove_file(home.config_path());
        } else if let Some(was) = &self.config_was {
            let now = std::fs::read(home.config_path()).ok();
            if now.as_deref() != Some(was.as_slice()) {
                let _ = crate::home::write_private_file(&home.config_path(), was);
            }
        }
        if self.database {
            let db = home.db_path();
            for suffix in ["", "-wal", "-shm"] {
                let mut name = db.clone().into_os_string();
                name.push(suffix);
                let _ = std::fs::remove_file(name);
            }
        }
        // `remove_dir` removes an empty directory and nothing else.
        if self.keys_dir {
            let _ = std::fs::remove_dir(home.keys_dir());
        }
        if self.root {
            let _ = std::fs::remove_dir(home.root());
        }
    }
}

fn report(ctx: &Ctx, id: &IdentityMetadata, created: bool) -> Report {
    let peer_id = ph_network::peer_id_from_device_key(&id.device_key).to_string();
    let fp = id.device_key.fingerprint();
    let json = json!({
        "created": created,
        "home": ctx.home.root(),
        "device_key": id.device_key,
        "fingerprint": fp,
        "peer_id": peer_id,
        "keystore": id.keystore_backend,
    });
    let mut t = Text::new();
    t.line(if created {
        "Initialized a new PeerHarness node."
    } else {
        "Already initialized (identity kept)."
    });
    t.kv("home", ctx.home.root().display());
    t.kv("device key", id.device_key);
    t.kv("fingerprint", &fp);
    t.kv("peer id", &peer_id);
    t.kv("keystore", &id.keystore_backend);
    if created {
        t.line("");
        t.line("Next:");
        t.line(
            "  peerharness demo                three members vote on a rule, in temporary folders",
        );
        t.line("  peerharness note \"<a rule>\"     write a rule down in one sentence; it prints an id");
        t.line(
            "  peerharness keep <that id>      keep it: shows the exact text, asks once, installs \
             it for your agent",
        );
    }
    Report::new(json, t.finish())
}
