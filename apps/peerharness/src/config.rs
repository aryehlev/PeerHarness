//! `config.toml` (0600): local configuration only, never shared.

use anyhow::{Context, Result};
use ph_governance::LocalPolicy;
use ph_identity::{KdfParams, KeystoreBackend};
use ph_learning::ProviderConfig;
use ph_observer::{NotifyPolicy, QuietHours};
use serde::{Deserialize, Serialize};

use crate::error::usage;
use crate::home::{read_bounded_file, write_private_file, Home};

/// Largest accepted config file.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// The default QUIC listen address of the daemon.
pub const DEFAULT_LISTEN: &str = "/ip4/127.0.0.1/udp/0/quic-v1";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub learning: LearningConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub policy: LocalPolicy,
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// Argon2id parameters for newly written key files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KdfProfile {
    /// Production parameters (64 MiB, t=3).
    #[default]
    Default,
    /// `KdfParams::insecure_fast_for_tests()`: TESTS AND DEMOS ONLY.
    FastInsecureTest,
}

impl KdfProfile {
    pub fn params(self) -> KdfParams {
        match self {
            KdfProfile::Default => KdfParams::DEFAULT,
            KdfProfile::FastInsecureTest => KdfParams::insecure_fast_for_tests(),
        }
    }

    fn is_default(&self) -> bool {
        *self == KdfProfile::Default
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default = "KeystoreBackend::platform_default")]
    pub keystore: KeystoreBackend,
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,
    /// Test-only override written by `init --kdf-profile fast-insecure-test`.
    #[serde(default, skip_serializing_if = "KdfProfile::is_default")]
    pub kdf_profile: KdfProfile,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            keystore: KeystoreBackend::platform_default(),
            listen: default_listen(),
            kdf_profile: KdfProfile::Default,
        }
    }
}

fn default_listen() -> Vec<String> {
    vec![DEFAULT_LISTEN.to_owned()]
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningConfig {
    #[serde(default = "default_detector")]
    pub detector: String,
    #[serde(default)]
    pub provider: ProviderConfig,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            detector: default_detector(),
            provider: ProviderConfig::default(),
        }
    }
}

fn default_detector() -> String {
    "deterministic".to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsConfig {
    #[serde(default = "default_max_per_day")]
    pub max_per_day: u32,
    /// `[]` (off) or `[start_hour, end_hour]` in UTC, e.g. `[22, 7]`.
    #[serde(default)]
    pub quiet_hours_utc: Vec<u8>,
    #[serde(default = "default_cooldown")]
    pub topic_cooldown_secs: i64,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            max_per_day: default_max_per_day(),
            quiet_hours_utc: Vec::new(),
            topic_cooldown_secs: default_cooldown(),
        }
    }
}

fn default_max_per_day() -> u32 {
    2
}

fn default_cooldown() -> i64 {
    NotifyPolicy::default().topic_cooldown_secs
}

impl NotificationsConfig {
    pub fn policy(&self) -> Result<NotifyPolicy> {
        let quiet_hours =
            match self.quiet_hours_utc.as_slice() {
                [] => None,
                [s, e] => Some(QuietHours::new(*s, *e).map_err(|_| {
                    usage("config: notifications.quiet_hours_utc must be two different hours 0-23")
                })?),
                _ => return Err(usage(
                    "config: notifications.quiet_hours_utc must be [] or [start_hour, end_hour]",
                )),
            };
        Ok(NotifyPolicy {
            max_per_day: self.max_per_day,
            topic_cooldown_secs: self.topic_cooldown_secs,
            quiet_hours,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default = "default_observation_days")]
    pub observation_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            observation_days: default_observation_days(),
        }
    }
}

fn default_observation_days() -> u32 {
    ph_store::DEFAULT_OBSERVATION_RETENTION_DAYS as u32
}

impl RetentionConfig {
    pub fn observation_secs(&self) -> i64 {
        i64::from(self.observation_days.clamp(1, 3650)) * ph_core::timestamp::SECS_PER_DAY
    }
}

impl Config {
    /// Parses and validates config text.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text).map_err(|e| {
            // toml's message quotes the offending line of OUR config file, which holds no
            // secrets; keep it for actionability.
            usage(format!("config.toml is invalid: {e}"))
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.learning.detector != "deterministic" {
            return Err(usage(
                "config: learning.detector must be \"deterministic\" (the only detector in this build)",
            ));
        }
        self.learning
            .provider
            .validate()
            .map_err(|e| usage(format!("config: learning.provider is invalid: {e}")))?;
        for a in &self.node.listen {
            a.parse::<ph_network::Multiaddr>()
                .map_err(|_| usage("config: node.listen contains an invalid multiaddr"))?;
        }
        self.notifications.policy()?;
        Ok(())
    }

    pub fn to_toml(&self) -> Result<String> {
        let body = toml::to_string_pretty(self).context("cannot serialize config")?;
        let mut s = String::from(
            "# PeerHarness local configuration. Never shared with peers.\n\
             # See `peerharness doctor` after editing.\n",
        );
        if self.node.kdf_profile == KdfProfile::FastInsecureTest {
            s.push_str(
                "# WARNING: kdf_profile = \"fast-insecure-test\" weakens key-file encryption.\n\
                 # It exists for automated tests and demos only.\n",
            );
        }
        s.push('\n');
        s.push_str(&body);
        Ok(s)
    }

    pub fn load(home: &Home) -> Result<Self> {
        let p = home.config_path();
        let bytes = read_bounded_file(&p, MAX_CONFIG_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| usage("config.toml is not UTF-8"))?;
        Self::parse(text)
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        write_private_file(&home.config_path(), self.to_toml()?.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_default_and_custom() {
        let c = Config::default();
        let t = c.to_toml().unwrap();
        assert_eq!(Config::parse(&t).unwrap(), c);
        assert!(t.contains("[node]"));
        assert!(t.contains("max_per_day = 2"));

        let mut c = Config::default();
        c.node.keystore = KeystoreBackend::File;
        c.node.kdf_profile = KdfProfile::FastInsecureTest;
        c.notifications.quiet_hours_utc = vec![22, 7];
        let t = c.to_toml().unwrap();
        assert!(t.contains("fast-insecure-test"));
        assert!(t.contains("WARNING"));
        assert_eq!(Config::parse(&t).unwrap(), c);
        assert!(c.notifications.policy().unwrap().quiet_hours.is_some());
    }

    #[test]
    fn brief_example_parses() {
        let t = r#"
[node]
keystore = "file"
listen = ["/ip4/127.0.0.1/udp/0/quic-v1"]
[learning]
detector = "deterministic"
[learning.provider]
kind = "none"
[notifications]
max_per_day = 2
quiet_hours_utc = []
[policy]
required_members = []
[retention]
observation_days = 14
"#;
        let c = Config::parse(t).unwrap();
        assert_eq!(c.node.keystore, KeystoreBackend::File);
        assert_eq!(c.retention.observation_days, 14);
    }

    #[test]
    fn rejects_bad_config() {
        assert!(Config::parse("[node]\nbogus = 1\n").is_err());
        assert!(Config::parse("[learning]\ndetector = \"llm\"\n").is_err());
        assert!(Config::parse("[notifications]\nquiet_hours_utc = [1]\n").is_err());
        assert!(Config::parse("[node]\nlisten = [\"not an addr\"]\n").is_err());
        assert!(Config::parse("").is_ok());
    }
}
