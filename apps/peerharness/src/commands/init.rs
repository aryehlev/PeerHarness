//! `peerharness init`: device key, database and config. Idempotent: an existing identity
//! is never regenerated.

use anyhow::{Context, Result};
use ph_identity::{DeviceIdentity, KeystoreBackend, OsKeyStore};
use ph_store::{IdentityMetadata, Store};
use serde_json::json;

use super::Ctx;
use crate::cli::{InitArgs, KdfProfileArg, KeystoreArg};
use crate::config::{Config, KdfProfile};
use crate::error::usage;
use crate::home::{mode_of, set_mode};
use crate::node::open_configured_keystore;
use crate::output::{Report, Text};

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
    if backend == KeystoreBackend::Os {
        OsKeyStore::check_available().map_err(|e| {
            anyhow::anyhow!("{e}").context(
                "the OS keychain is not available; re-run with `--keystore file` (encrypted \
                 key file protected by a passphrase)",
            )
        })?;
    }
    if backend == KeystoreBackend::InsecureDev {
        ctx.out
            .warn("insecure-dev keystore: private keys are stored in PLAINTEXT (development only)");
    }
    cfg.save(home)?;

    let store = Store::open(home.db_path()).context("cannot create the database")?;
    let ks = open_configured_keystore(home, &cfg, backend)?;
    let dev = if DeviceIdentity::exists(&*ks)? {
        // A previous init stored the key but not the metadata: adopt it.
        DeviceIdentity::load(&*ks).context("cannot unlock the existing device key")?
    } else {
        DeviceIdentity::create(&*ks).context("cannot create the device key")?
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
        t.line("Next: `peerharness observe demo` then `peerharness inbox`.");
    }
    Report::new(json, t.finish())
}
