//! `peerharness init`: device key, database and config. Idempotent: an existing identity
//! is never regenerated.
//!
//! A coding agent may run a plain `init` for its user: the keys go to the OS keychain
//! or an encrypted file. The plaintext keystore (`insecure-dev`) is refused inside an
//! agent's session, whether a flag or an existing config file asks for it: its warning
//! has to reach a person, and there it would reach the agent.
//!
//! An `init` that fails before the node has a device key leaves the home as it found
//! it ([`Made`]): it takes away the files and directories this run created and nothing
//! else. Without that, a first run with no passphrase to read left a config file and a
//! database behind, and every later command said the home had no identity.

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
        ctx.out.warn(
            "--kdf-profile fast-insecure-test weakens key-file encryption; it is for automated \
             tests and demos only",
        );
    }

    // What is not there yet is what this run makes, and takes away again if it fails.
    let made = Made::before(home);
    home.ensure()?;
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
            // A config file that names the plaintext keystore asks for it as the flag does.
            human_only(PLAINTEXT_KEYS)?;
            ctx.out.warn(
                "insecure-dev keystore: private keys are stored in PLAINTEXT (development only)",
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
            // The closure's database handle is closed by now.
            if !key_in_keystore.get() {
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

/// What was missing from a home before `init` touched it, and so is this run's to take
/// away if it fails before the node has a device key.
#[derive(Clone, Copy, Debug)]
struct Made {
    root: bool,
    config: bool,
    database: bool,
    keys_dir: bool,
}

impl Made {
    /// Looks at `home` before anything is created. A path that is there in any form (a
    /// file, a directory, a link) is not this run's.
    fn before(home: &Home) -> Self {
        let missing = |p: std::path::PathBuf| std::fs::symlink_metadata(p).is_err();
        Self {
            root: missing(home.root().to_path_buf()),
            config: missing(home.config_path()),
            database: missing(home.db_path()),
            keys_dir: missing(home.keys_dir()),
        }
    }

    /// Takes away what this run created: the config file, the database with the two
    /// files SQLite keeps next to it, and the keys directory and the home itself when
    /// they are empty. A directory that holds anything else stays, so nothing that was
    /// there before, and no key, is ever removed. Failures are ignored: the error that
    /// brought us here is the one to report.
    fn undo(self, home: &Home) {
        if self.config {
            let _ = std::fs::remove_file(home.config_path());
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
