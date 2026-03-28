//! `WireGuard` key generation and wg-quick config generation for VPN testing.
//!
//! Pure Rust implementation using x25519-dalek for Curve25519 key pairs.
//! Config generation produces wg-quick compatible INI strings with inline
//! key values (not file paths) since test keys are ephemeral and in-memory.

use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

/// A `WireGuard` Curve25519 key pair (base64-encoded).
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

/// Generate a random `WireGuard` key pair.
pub fn generate_keypair() -> KeyPair {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);

    let engine = base64::engine::general_purpose::STANDARD;
    KeyPair {
        private_key: engine.encode(secret.to_bytes()),
        public_key: engine.encode(public.to_bytes()),
    }
}

/// Generate a 256-bit pre-shared key (base64-encoded).
pub fn generate_psk() -> String {
    let mut psk = [0u8; 32];
    rand::fill(&mut psk);
    base64::engine::general_purpose::STANDARD.encode(psk)
}

/// Generate a `wg-quick` server config with inline key values.
///
/// The server listens on `listen_port` and accepts connections from one peer.
pub fn server_config(
    private_key: &str,
    address: &str,
    listen_port: u16,
    peer_pub: &str,
    peer_allowed_ips: &str,
    psk: &str,
) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {address}\n\
         ListenPort = {listen_port}\n\
         \n\
         [Peer]\n\
         PublicKey = {peer_pub}\n\
         PresharedKey = {psk}\n\
         AllowedIPs = {peer_allowed_ips}\n"
    )
}

/// Generate a `wg-quick` client config with inline key values.
///
/// The client connects to a peer at `peer_endpoint` with persistent keepalive.
pub fn client_config(
    private_key: &str,
    address: &str,
    peer_pub: &str,
    peer_endpoint: &str,
    peer_allowed_ips: &str,
    psk: &str,
    keepalive: u16,
) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {address}\n\
         \n\
         [Peer]\n\
         PublicKey = {peer_pub}\n\
         PresharedKey = {psk}\n\
         Endpoint = {peer_endpoint}\n\
         AllowedIPs = {peer_allowed_ips}\n\
         PersistentKeepalive = {keepalive}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_base64() {
        let kp = generate_keypair();
        let engine = base64::engine::general_purpose::STANDARD;
        let priv_bytes = engine.decode(&kp.private_key).unwrap();
        let pub_bytes = engine.decode(&kp.public_key).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn generate_keypair_derives_correct_public_key() {
        let kp = generate_keypair();
        let engine = base64::engine::general_purpose::STANDARD;
        let priv_bytes: [u8; 32] = engine
            .decode(&kp.private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let secret = StaticSecret::from(priv_bytes);
        let expected_pub = PublicKey::from(&secret);
        let actual_pub_bytes = engine.decode(&kp.public_key).unwrap();
        assert_eq!(actual_pub_bytes.as_slice(), expected_pub.as_bytes());
    }

    #[test]
    fn generate_psk_is_32_bytes() {
        let psk = generate_psk();
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = engine.decode(&psk).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn keypairs_are_unique() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn server_config_format() {
        let config = server_config(
            "ServerPrivKey==",
            "10.99.0.1/24",
            51899,
            "ClientPubKey==",
            "10.99.0.2/32",
            "SharedPSK==",
        );

        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey = ServerPrivKey=="));
        assert!(config.contains("Address = 10.99.0.1/24"));
        assert!(config.contains("ListenPort = 51899"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PublicKey = ClientPubKey=="));
        assert!(config.contains("PresharedKey = SharedPSK=="));
        assert!(config.contains("AllowedIPs = 10.99.0.2/32"));
    }

    #[test]
    fn client_config_format() {
        let config = client_config(
            "ClientPrivKey==",
            "10.99.0.2/24",
            "ServerPubKey==",
            "10.0.0.1:51899",
            "10.99.0.1/32",
            "SharedPSK==",
            25,
        );

        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey = ClientPrivKey=="));
        assert!(config.contains("Address = 10.99.0.2/24"));
        assert!(!config.contains("ListenPort"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PublicKey = ServerPubKey=="));
        assert!(config.contains("PresharedKey = SharedPSK=="));
        assert!(config.contains("Endpoint = 10.0.0.1:51899"));
        assert!(config.contains("AllowedIPs = 10.99.0.1/32"));
        assert!(config.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn server_config_with_real_keys() {
        let server = generate_keypair();
        let client = generate_keypair();
        let psk = generate_psk();

        let config = server_config(
            &server.private_key,
            "10.99.0.1/24",
            51899,
            &client.public_key,
            "10.99.0.2/32",
            &psk,
        );

        // Config should be valid wg-quick format
        assert!(config.starts_with("[Interface]\n"));
        assert!(config.contains("[Peer]\n"));
        // Keys should be base64 (44 chars for 32 bytes)
        assert_eq!(server.private_key.len(), 44);
        assert_eq!(client.public_key.len(), 44);
        assert_eq!(psk.len(), 44);
    }
}
