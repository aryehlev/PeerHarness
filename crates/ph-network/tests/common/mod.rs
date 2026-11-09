//! Shared helpers for ph-network integration tests.
#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use ph_core::DeviceKey;
use ph_network::{start, NetEvent, NetworkConfig, NetworkHandle, RequestHandler};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// Generous upper bound for anything that should happen "soon" on loopback.
pub const SOON: Duration = Duration::from_secs(20);

pub fn seed(n: u8) -> Zeroizing<[u8; 32]> {
    let mut s = [0u8; 32];
    s[0] = n;
    s[31] = 0xa5;
    Zeroizing::new(s)
}

pub fn device_key(n: u8) -> DeviceKey {
    let s = seed(n);
    DeviceKey::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&s))
}

pub fn loopback_config() -> NetworkConfig {
    NetworkConfig::listening_on(["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()])
}

pub struct Node {
    pub net: NetworkHandle,
    pub join: JoinHandle<()>,
}

pub fn node(n: u8, config: NetworkConfig, handler: Arc<dyn RequestHandler>) -> Node {
    let (net, join) = start(seed(n), config, handler).expect("start network");
    Node { net, join }
}

pub async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(SOON, fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out waiting for {what}"),
    }
}

/// Waits for the first event matching `pred`.
pub async fn wait_event(
    rx: &mut broadcast::Receiver<NetEvent>,
    what: &str,
    mut pred: impl FnMut(&NetEvent) -> bool,
) -> NetEvent {
    within(what, async {
        loop {
            match rx.recv().await {
                Ok(e) if pred(&e) => return e,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => panic!("event channel closed"),
            }
        }
    })
    .await
}

/// Connects `from` to `to` and returns `to`'s peer id.
pub async fn connect(from: &NetworkHandle, to: &NetworkHandle) -> ph_network::PeerId {
    let addr = within("listen addr", to.listen_addrs()).await.unwrap()[0].clone();
    let pid = within("dial", from.dial(addr)).await.expect("dial");
    assert_eq!(pid, to.local_peer_id());
    pid
}

pub async fn stop(node: Node) {
    within("shutdown", node.net.shutdown()).await;
    within("join", node.join).await.expect("event loop task");
}
