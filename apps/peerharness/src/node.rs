//! The opened node: home, config, store and (lazily) the keystore and device key.
//!
//! Local-only commands never unlock anything. Only commands that sign call
//! [`Node::device`], which opens the keystore (prompting for the file passphrase or
//! reading `PEERHARNESS_PASSPHRASE`) once per process.
use std::cell::OnceCell;

use anyhow::{Context, Result};
use ph_core::{DeviceKey, Timestamp};
use ph_identity::{
    open_keystore, DeviceIdentity, InsecureAcknowledged, KeyStore, KeystoreBackend, KeystoreConfig,
    PassphraseSource,
};
use ph_store::{IdentityMetadata, Store};

use crate::config::Config;
use crate::error::usage;
use crate::home::Home;

pub struct Node {
    pub home: Home,
    pub config: Config,
    pub store: Store,
    pub identity: IdentityMetadata,
    keystore: OnceCell<Box<dyn KeyStore>>,
    device: OnceCell<DeviceIdentity>,
}

impl Node {
    /// Opens an initialized node. Never creates anything except the database's own
    /// WAL files.
    pub fn open(home: &Home) -> Result<Self> {
        if !home.is_initialized() {
            return Err(usage(format!(
                "{} is not initialized: run `peerharness init` first",
                home.root().display()
            )));
        }
        let config = Config::load(home)?;
        let store = Store::open(home.db_path()).context("cannot open the database")?;
        let identity = store
            .identity()
            .context("cannot read the identity")?
            .ok_or_else(|| usage("this home has no device identity yet: run `peerharness init`"))?;
        Ok(Self {
            home: home.clone(),
            config,
            store,
            identity,
            keystore: OnceCell::new(),
            device: OnceCell::new(),
        })
    }

    pub fn device_key(&self) -> DeviceKey {
        self.identity.device_key
    }

    pub fn peer_id(&self) -> ph_network::PeerId {
        ph_network::peer_id_from_device_key(&self.identity.device_key)
    }

    pub fn now(&self) -> Timestamp {
        Timestamp::now()
    }

    /// The configured keystore (opened once; the file backend caches its passphrase).
    pub fn keystore(&self) -> Result<&dyn KeyStore> {
        if let Some(k) = self.keystore.get() {
            return Ok(k.as_ref());
        }
        let ks = open_configured_keystore(&self.home, &self.config, self.backend()?)?;
        Ok(self.keystore.get_or_init(move || ks).as_ref())
    }

    /// The backend recorded at init (authoritative over config.toml).
    pub fn backend(&self) -> Result<KeystoreBackend> {
        self.identity
            .keystore_backend
            .parse::<KeystoreBackend>()
            .map_err(|_| anyhow::anyhow!("identity metadata names an unknown keystore backend"))
    }

    /// Unlocks the device key (needed only by commands that sign).
    pub fn device(&self) -> Result<&DeviceIdentity> {
        if let Some(d) = self.device.get() {
            return Ok(d);
        }
        let ks = self.keystore()?;
        let dev = DeviceIdentity::load(ks).context("cannot unlock the device key")?;
        if dev.public() != self.identity.device_key {
            return Err(anyhow::anyhow!(
                "the keystore holds a different device key than this home's database"
            ));
        }
        tracing::debug!("device key unlocked");
        Ok(self.device.get_or_init(move || dev))
    }
}

/// Opens the keystore for `backend` with the config's KDF profile. The file backend
/// takes the passphrase from `PEERHARNESS_PASSPHRASE` or prompts on the terminal.
pub fn open_configured_keystore(
    home: &Home,
    config: &Config,
    backend: KeystoreBackend,
) -> Result<Box<dyn KeyStore>> {
    let cfg = match backend {
        KeystoreBackend::Os => KeystoreConfig::Os,
        KeystoreBackend::File => KeystoreConfig::File {
            passphrase: PassphraseSource::env_or_prompt(),
            kdf: config.node.kdf_profile.params(),
        },
        KeystoreBackend::InsecureDev => KeystoreConfig::InsecureDev(
            // The human chose this explicitly with `init --insecure-dev-keystore`; the
            // keystore warns on every load and store.
            InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext(),
        ),
    };
    open_keystore(home.root(), cfg).context("cannot open the keystore")
}

/// A keystore opened only for passphrase-free operations (`exists`, `delete`,
/// `locator`): the file backend gets a passphrase source that is never used.
pub fn open_keystore_no_unlock(home: &Home, backend: KeystoreBackend) -> Result<Box<dyn KeyStore>> {
    let cfg = match backend {
        KeystoreBackend::Os => KeystoreConfig::Os,
        KeystoreBackend::File => KeystoreConfig::file(PassphraseSource::Env),
        KeystoreBackend::InsecureDev => KeystoreConfig::InsecureDev(
            InsecureAcknowledged::i_understand_keys_are_stored_in_plaintext(),
        ),
    };
    open_keystore(home.root(), cfg).context("cannot open the keystore")
}
