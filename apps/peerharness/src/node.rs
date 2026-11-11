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

use crate::config::{Config, KdfProfile};
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
        let backend = self.backend()?;
        let ks = open_configured_keystore(&self.home, &self.config, backend)?;
        // Said where a person reads it, once for a process (ADR-050). The keystore
        // itself only writes a line to the log, which nobody sees without `-v`.
        if let Some(warning) = keystore_warning(backend, self.config.node.kdf_profile) {
            crate::output::warn(warning);
        }
        Ok(self.keystore.get_or_init(move || ks).as_ref())
    }

    /// The backend recorded at init (authoritative over config.toml).
    pub fn backend(&self) -> Result<KeystoreBackend> {
        self.identity
            .keystore_backend
            .parse::<KeystoreBackend>()
            .map_err(|_| anyhow::anyhow!("identity metadata names an unknown keystore backend"))
    }

    /// Whether the device key can be unlocked with nobody typing at a terminal. A key
    /// file needs its passphrase, which only `PEERHARNESS_PASSPHRASE` can supply then.
    pub fn unlocks_without_terminal(&self) -> Result<bool> {
        Ok(match self.backend()? {
            KeystoreBackend::File => std::env::var_os(ph_identity::PASSPHRASE_ENV).is_some(),
            KeystoreBackend::Os | KeystoreBackend::InsecureDev => true,
        })
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

/// What a command that uses a private key says about a keystore that does not protect
/// it, on standard error.
pub const PLAINTEXT_KEYS: &str = "this node's private keys are stored in PLAINTEXT (the \
    insecure-dev keystore, for development only)";

/// The same for key files that are encrypted with the parameters of the tests.
pub const WEAK_KEY_FILES: &str = "this node writes its key files with the test profile \
    (kdf_profile = \"fast-insecure-test\" in config.toml): their encryption is weak, for \
    automated tests and demos only";

/// The warning that goes with a keystore, if it has one. A key in the operating
/// system's keychain or in a file encrypted with the default parameters has none.
pub fn keystore_warning(backend: KeystoreBackend, kdf: KdfProfile) -> Option<&'static str> {
    match backend {
        KeystoreBackend::InsecureDev => Some(PLAINTEXT_KEYS),
        KeystoreBackend::File if kdf == KdfProfile::FastInsecureTest => Some(WEAK_KEY_FILES),
        KeystoreBackend::File | KeystoreBackend::Os => None,
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
            // The human chose this explicitly with `init --insecure-dev-keystore`. The
            // keystore logs every load and store, and `Node::keystore` and `init` say
            // it on standard error.
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
