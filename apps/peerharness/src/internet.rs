//! The opt-in internet mode, as the commands use it (ADR-032).
//!
//! `daemon --internet`, `sync --internet` and `circle join <peer id> --internet` start
//! the transport with [`ph_network::NetworkConfig::internet`] set: the node joins the
//! public libp2p network as a client, can look a device key up there and can be found
//! by its own. Without the flag none of this exists.
//!
//! What this module decides is only how the transport is configured. Who is looked up
//! and dialed is decided in [`crate::runtime`], from the rolls this node holds or from
//! the one peer id its owner typed.

use anyhow::Result;
use ph_network::libp2p::multiaddr::Protocol;
use ph_network::{InternetConfig, Multiaddr, NetworkConfig, PeerId};

use crate::error::usage;

/// Comma-separated multiaddrs, each ending in `/p2p/<peer id>`, that replace the
/// bootstrap peers of the public network: a network of one's own. The tests run one on
/// loopback.
pub const ENV_BOOTSTRAP: &str = "PEERHARNESS_INTERNET_BOOTSTRAP";

/// `1`: treat private and loopback addresses like public ones. Only for a closed
/// network in which every node sets it, together with [`ENV_BOOTSTRAP`]. On the
/// internet it would make the node announce and dial private addresses, so it is
/// refused without a bootstrap list of one's own.
pub const ENV_PRIVATE: &str = "PEERHARNESS_INTERNET_PRIVATE";

/// How long a lookup of one peer may take when the owner gave no `--wait`.
pub const DEFAULT_WAIT_SECS: u32 = 30;

/// The mode as the environment configures it: the public network unless told otherwise.
fn mode() -> Result<InternetConfig> {
    let mut config = InternetConfig::default();
    let own_network = match std::env::var(ENV_BOOTSTRAP) {
        Ok(list) if !list.trim().is_empty() => {
            config.bootstrap = list
                .split(',')
                .map(|a| {
                    a.trim().parse::<Multiaddr>().map_err(|_| {
                        usage(format!(
                            "{ENV_BOOTSTRAP} holds something that is not a multiaddr"
                        ))
                    })
                })
                .collect::<Result<_>>()?;
            true
        }
        _ => false,
    };
    if std::env::var(ENV_PRIVATE).is_ok_and(|v| v == "1") {
        if !own_network {
            return Err(usage(format!(
                "{ENV_PRIVATE} needs {ENV_BOOTSTRAP}: private addresses are only for a network of your own"
            )));
        }
        config.allow_private_addresses = true;
    }
    Ok(config)
}

/// Whether this process was told to run a closed network on private addresses.
fn private(config: &InternetConfig) -> bool {
    config.allow_private_addresses
}

fn is_loopback(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => ip.is_loopback(),
        Some(Protocol::Ip6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Where a node in the mode listens when its owner named no address: every IPv4
/// interface, on a port the system picks. (On a closed test network: loopback.)
fn default_listen(config: &InternetConfig) -> Vec<Multiaddr> {
    let addr = if private(config) {
        "/ip4/127.0.0.1/udp/0/quic-v1"
    } else {
        "/ip4/0.0.0.0/udp/0/quic-v1"
    };
    addr.parse().into_iter().collect()
}

/// The transport of `daemon --internet`. `listen` is what the owner passed with
/// `--listen`, if anything: the configured default (loopback) is of no use here, since
/// a socket bound to loopback reaches nobody on the internet.
pub fn daemon_config(listen: Option<Vec<Multiaddr>>, lan: bool) -> Result<NetworkConfig> {
    let mode = mode()?;
    let listen = match listen {
        Some(addrs) => {
            if !private(&mode) && addrs.iter().any(is_loopback) {
                return Err(usage(
                    "--internet cannot be combined with a loopback listen address: a socket \
                     bound to loopback reaches nobody on the internet. Leave --listen out, \
                     or listen on /ip4/0.0.0.0/udp/<port>/quic-v1.",
                ));
            }
            addrs
        }
        None => default_listen(&mode),
    };
    Ok(NetworkConfig {
        lan_discovery: lan,
        internet: Some(mode),
        ..NetworkConfig::listening_on(listen)
    })
}

/// The transport of one command (`sync --internet`, `circle join --internet`): it
/// listens, because a direct connection through two routers needs a socket on each
/// side, and it asks no relay for a reservation, because it is gone in a moment.
pub fn client_config() -> Result<NetworkConfig> {
    let mut mode = mode()?;
    mode.max_relays = 0;
    let listen = default_listen(&mode);
    Ok(NetworkConfig {
        internet: Some(mode),
        ..NetworkConfig::listening_on(listen)
    })
}

/// Reads a peer id as a person gives one: bare, or as `/p2p/<peer id>`.
pub fn peer_id_of(target: &str) -> Option<PeerId> {
    let target = target.trim();
    let bare = target.strip_prefix("/p2p/").unwrap_or(target);
    bare.parse::<PeerId>().ok()
}

/// What the owner is told when the mode starts: who learns what.
pub const DISCLOSURE: &str =
    "Internet mode: this node joins the public libp2p network. Its servers see this \
     device's public key and IP address, and the device keys this node looks for. They \
     never see a circle, a roll or anything said in one, and a relay cannot read what \
     it carries.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_id_is_read_bare_or_as_an_address_part() {
        let id = "12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8";
        let peer: PeerId = id.parse().unwrap();
        assert_eq!(peer_id_of(id), Some(peer));
        assert_eq!(peer_id_of(&format!("  /p2p/{id}\n")), Some(peer));
        assert_eq!(peer_id_of("alice"), None);
        assert_eq!(peer_id_of("/ip4/192.0.2.7/udp/4001/quic-v1"), None);
        assert_eq!(peer_id_of(""), None);
    }

    #[test]
    fn a_loopback_listener_is_refused_with_the_mode() {
        // Not through the environment: other tests of this binary run in parallel.
        let public = InternetConfig::default();
        assert!(!private(&public));
        assert_eq!(
            default_listen(&public),
            vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse::<Multiaddr>().unwrap()]
        );
        assert!(is_loopback(
            &"/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
        ));
        assert!(is_loopback(&"/ip6/::1/udp/4001/quic-v1".parse().unwrap()));
        assert!(!is_loopback(&"/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()));
    }
}
